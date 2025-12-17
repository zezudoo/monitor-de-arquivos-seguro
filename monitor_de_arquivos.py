from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import queue
import sqlite3
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Any

TAMANHO_BUFFER = 1024 * 1024  # 1 MiB


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


BASE_DIR = _base_dir()
PASTA_LOGS = BASE_DIR / "logs"
PASTA_HASHES = BASE_DIR / "hashes"
ARQUIVO_LOCK = BASE_DIR / "monitor.lock"


@dataclass(frozen=True)
class PastaMonitorada:
    origem: Path
    destino: Path
    extensoes: set[str] | None = None
    recursivo: bool = False
    politica_conflito_destino: str = "skip"


@dataclass(frozen=True)
class ConfigAplicacao:
    pastas: list[PastaMonitorada]
    modo_monitoramento: str = "eventos"  # "eventos" (watchdog) ou "varredura"
    observer_polling: bool = False
    caminho_estado_sqlite: Path = PASTA_HASHES / "estado.sqlite3"
    expirar_hashes_dias: int | None = 180
    intervalo_scan_s: int = 60
    algoritmo_hash: str = "sha256"
    tentativas_estabilidade: int = 3
    intervalo_estabilidade_s: float = 2.0
    limite_tentativas_falha: int = 3
    tempo_ignorar_falha_s: int = 600
    permitir_symlinks: bool = False
    tamanho_maximo_bytes: int | None = None
    nivel_log: int = logging.INFO
    log_no_console: bool = True


class ErroInstanciaUnica(RuntimeError):
    pass


class LockInstanciaUnica:
    def __init__(self, caminho: Path) -> None:
        self.caminho = caminho
        self._arquivo = None

    def __enter__(self) -> "LockInstanciaUnica":
        self.caminho.parent.mkdir(parents=True, exist_ok=True)
        self._arquivo = self.caminho.open("a+", encoding="utf-8")
        self._arquivo.seek(0)

        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self._arquivo.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._arquivo.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise ErroInstanciaUnica("Já existe uma instância em execução.") from exc

        self._arquivo.seek(0)
        self._arquivo.truncate()
        self._arquivo.write(str(os.getpid()))
        self._arquivo.flush()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        try:
            if self._arquivo is None:
                return
            try:
                self._arquivo.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(self._arquivo.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(self._arquivo.fileno(), fcntl.LOCK_UN)
            finally:
                self._arquivo.close()
        finally:
            try:
                self.caminho.unlink(missing_ok=True)
            except OSError:
                pass


def inicializar_pastas() -> None:
    PASTA_LOGS.mkdir(parents=True, exist_ok=True)
    PASTA_HASHES.mkdir(parents=True, exist_ok=True)


class EstadoSqlite:
    def __init__(self, caminho_db: Path, *, expirar_hashes_dias: int | None) -> None:
        self.caminho_db = caminho_db
        self.expirar_apos_s = None if expirar_hashes_dias is None else int(expirar_hashes_dias) * 86400
        self._lock = threading.Lock()
        self._ultimo_prune_ts = 0.0

        self.caminho_db.parent.mkdir(parents=True, exist_ok=True)
        self._con = sqlite3.connect(
            str(self.caminho_db),
            timeout=30,
            check_same_thread=False,
        )
        self._con.execute("PRAGMA journal_mode=WAL;")
        self._con.execute("PRAGMA synchronous=NORMAL;")
        self._con.execute("PRAGMA foreign_keys=ON;")
        self._con.execute("PRAGMA busy_timeout=5000;")
        self._con.execute(
            """
            CREATE TABLE IF NOT EXISTS processed_hashes (
                folder_id TEXT NOT NULL,
                hash TEXT NOT NULL,
                first_seen_ts REAL NOT NULL,
                last_seen_ts REAL NOT NULL,
                PRIMARY KEY (folder_id, hash)
            );
            """
        )
        self._con.execute(
            "CREATE INDEX IF NOT EXISTS idx_processed_hashes_last_seen ON processed_hashes(last_seen_ts);"
        )

    def __enter__(self) -> "EstadoSqlite":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        self.close()

    def close(self) -> None:
        try:
            self._con.close()
        except Exception:
            pass

    def importar_hashes(self, folder_id: str, hashes: dict[str, float]) -> int:
        if not hashes:
            return 0
        with self._lock:
            self._con.executemany(
                """
                INSERT INTO processed_hashes(folder_id, hash, first_seen_ts, last_seen_ts)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(folder_id, hash) DO UPDATE SET last_seen_ts=excluded.last_seen_ts;
                """,
                [(folder_id, h, ts, ts) for h, ts in hashes.items()],
            )
        return len(hashes)

    def hash_ja_processado(self, folder_id: str, hash_arquivo: str, *, agora: float) -> bool:
        with self._lock:
            cur = self._con.execute(
                "SELECT 1 FROM processed_hashes WHERE folder_id=? AND hash=? LIMIT 1;",
                (folder_id, hash_arquivo),
            )
            existe = cur.fetchone() is not None
            if existe:
                self._con.execute(
                    "UPDATE processed_hashes SET last_seen_ts=? WHERE folder_id=? AND hash=?;",
                    (agora, folder_id, hash_arquivo),
                )
        return existe

    def registrar_hash(self, folder_id: str, hash_arquivo: str, *, agora: float) -> None:
        with self._lock:
            self._con.execute(
                """
                INSERT INTO processed_hashes(folder_id, hash, first_seen_ts, last_seen_ts)
                VALUES(?, ?, ?, ?)
                ON CONFLICT(folder_id, hash) DO UPDATE SET last_seen_ts=excluded.last_seen_ts;
                """,
                (folder_id, hash_arquivo, agora, agora),
            )

    def maybe_prune(self, *, agora: float, force: bool = False) -> None:
        if self.expirar_apos_s is None:
            return
        if not force and (agora - self._ultimo_prune_ts) < 3600:
            return
        cutoff = agora - self.expirar_apos_s
        with self._lock:
            self._con.execute("DELETE FROM processed_hashes WHERE last_seen_ts < ?;", (cutoff,))
        self._ultimo_prune_ts = agora


def _identificador_pasta(pasta: Path) -> str:
    texto = str(pasta)
    digest = hashlib.sha256(texto.encode("utf-8", errors="replace")).hexdigest()[:12]
    slug = "".join(ch if ch.isalnum() else "_" for ch in texto).strip("_")[-40:] or "pasta"
    return f"{slug}_{digest}"


def _caminho_hashes(pasta_origem: Path) -> Path:
    ident = _identificador_pasta(pasta_origem)
    return PASTA_HASHES / f"hashes_{ident}.json"


def _caminho_hashes_legado(pasta_origem: Path) -> Path:
    nome_base = str(pasta_origem).replace(":", "").replace("\\", "_").replace("/", "_").strip("_")
    return PASTA_HASHES / f"hashes_{nome_base}.json"


def carregar_hashes(pasta_origem: Path, logger: logging.Logger) -> dict[str, float]:
    candidatos = [_caminho_hashes(pasta_origem), _caminho_hashes_legado(pasta_origem)]
    for caminho in candidatos:
        if not caminho.exists():
            continue
        try:
            with caminho.open("r", encoding="utf-8-sig") as f:
                dados = json.load(f)
        except Exception as exc:
            logger.warning("Falha ao carregar hashes (%s): %s", caminho, exc)
            continue

        if not isinstance(dados, dict):
            logger.warning("Arquivo de hashes inválido (%s): esperado objeto JSON", caminho)
            continue

        hashes: dict[str, float] = {}
        for chave, valor in dados.items():
            if isinstance(chave, str) and isinstance(valor, (int, float)):
                hashes[chave] = float(valor)
        logger.debug("Hashes carregados: %s (%d itens)", caminho, len(hashes))
        return hashes

    return {}


def salvar_hashes(pasta_origem: Path, dados: dict[str, float], logger: logging.Logger) -> None:
    caminho_hash = _caminho_hashes(pasta_origem)
    caminho_hash.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp = tempfile.mkstemp(
        dir=str(caminho_hash.parent),
        prefix=f".{caminho_hash.name}.",
        suffix=".tmp",
        text=True,
    )
    tmp_path = Path(tmp)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(dados, f, separators=(",", ":"))
        os.replace(str(tmp_path), str(caminho_hash))
        logger.debug("Hashes salvos: %s (%d itens)", caminho_hash, len(dados))
    except Exception as exc:
        logger.warning("Falha ao salvar hashes (%s): %s", caminho_hash, exc)
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass


def migrar_hashes_json_para_sqlite(
    pasta_origem: Path,
    *,
    folder_id: str,
    logger: logging.Logger,
    estado: EstadoSqlite,
) -> None:
    hashes = carregar_hashes(pasta_origem, logger)
    if not hashes:
        return
    total = estado.importar_hashes(folder_id, hashes)
    if total:
        logger.info("Migrados %d hashes do JSON para o SQLite (%s)", total, estado.caminho_db.name)


def configurar_log(pasta_origem: Path, config: ConfigAplicacao) -> logging.Logger:
    ident = _identificador_pasta(pasta_origem)
    logger = logging.getLogger(f"monitor.{ident}")
    logger.setLevel(config.nivel_log)
    logger.propagate = False

    if logger.handlers:
        return logger

    caminho_log = PASTA_LOGS / f"monitor_{ident}.log"
    handler_arquivo = TimedRotatingFileHandler(
        filename=str(caminho_log),
        when="midnight",
        backupCount=14,
        encoding="utf-8",
    )
    fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler_arquivo.setFormatter(fmt)
    logger.addHandler(handler_arquivo)

    if config.log_no_console:
        handler_console = logging.StreamHandler(sys.stdout)
        handler_console.setFormatter(fmt)
        logger.addHandler(handler_console)

    return logger


def _nome_arquivo_seguro(nome: str) -> str:
    if ":" in nome:
        raise ValueError("nome contém ':' (possível ADS)")
    nome = nome.strip().rstrip(". ")
    if not nome:
        raise ValueError("nome vazio")
    return nome


def _normalizar_extensoes(extensoes: Any) -> set[str] | None:
    if not extensoes:
        return None
    if not isinstance(extensoes, list):
        raise ValueError("extensoes deve ser uma lista")

    resultado: set[str] = set()
    for ext in extensoes:
        if not isinstance(ext, str):
            continue
        ext = ext.strip().lower()
        if not ext:
            continue
        if ext == "*":
            return None
        if not ext.startswith("."):
            ext = f".{ext}"
        resultado.add(ext)
    return resultado or None


def _normalizar_politica_conflito(valor: Any) -> str:
    if valor is None:
        return "skip"
    if not isinstance(valor, str):
        raise ValueError("politica_conflito_destino deve ser string")
    texto = valor.strip().lower()
    mapeamento = {
        "skip": "skip",
        "ignorar": "skip",
        "ignore": "skip",
        "rename": "rename",
        "renomear": "rename",
        "version": "version",
        "versao": "version",
        "versão": "version",
        "versionar": "version",
    }
    if texto not in mapeamento:
        raise ValueError(f"politica_conflito_destino inválida: {valor!r}")
    return mapeamento[texto]


def _normalizar_modo_monitoramento(valor: Any) -> str:
    if valor is None:
        return "eventos"
    if not isinstance(valor, str):
        raise ValueError("modo_monitoramento deve ser string")
    texto = valor.strip().lower()
    mapeamento = {
        "eventos": "eventos",
        "eventos_watchdog": "eventos",
        "watchdog": "eventos",
        "events": "eventos",
        "varredura": "varredura",
        "scan": "varredura",
        "polling": "varredura",
    }
    if texto not in mapeamento:
        raise ValueError(f"modo_monitoramento inválido: {valor!r}")
    return mapeamento[texto]


def _nivel_log(valor: Any) -> int:
    if valor is None:
        return logging.INFO
    if isinstance(valor, int):
        return valor
    if not isinstance(valor, str):
        raise ValueError("nivel_log deve ser string")
    try:
        return int(valor)
    except ValueError:
        pass
    nome = valor.strip().upper()
    mapeamento = {
        "CRITICAL": logging.CRITICAL,
        "ERROR": logging.ERROR,
        "WARNING": logging.WARNING,
        "INFO": logging.INFO,
        "DEBUG": logging.DEBUG,
    }
    if nome not in mapeamento:
        raise ValueError(f"nivel_log inválido: {valor!r}")
    return mapeamento[nome]


def carregar_configuracao(caminho: Path) -> dict[str, Any]:
    with caminho.open("r", encoding="utf-8-sig") as arquivo:
        dados = json.load(arquivo)
    if not isinstance(dados, dict):
        raise ValueError("configuração inválida (esperado objeto JSON)")
    return dados


def _validar_caminho_windows(caminho: str, *, campo: str, idx: int) -> None:
    if os.name != "nt":
        return

    texto = caminho.strip()
    if not texto:
        raise ValueError(f"pastas_monitoradas[{idx}] {campo} não pode ser vazio")

    if texto.startswith("\\\\") or texto.startswith("//"):
        return  # UNC / device paths

    if len(texto) >= 3 and texto[1] == ":" and texto[2] in ("\\", "/"):
        return  # C:\...

    if texto[0] in ("\\", "/"):
        raise ValueError(
            f"pastas_monitoradas[{idx}] {campo} parece caminho UNC com barra faltando: "
            'em JSON use "\\\\\\\\servidor\\\\compartilhamento\\\\pasta" (4 barras no começo) '
            'ou "//servidor/compartilhamento/pasta"; para caminho local absoluto use "C:\\\\...".'
        )


def _caminho_esta_dentro_de(child: Path, parent: Path) -> bool:
    try:
        parent_s = os.path.normcase(os.path.abspath(str(parent)))
        child_s = os.path.normcase(os.path.abspath(str(child)))
        return os.path.commonpath([parent_s, child_s]) == parent_s
    except ValueError:
        return False


def montar_config(dados: dict[str, Any], *, base_dir: Path, debug: bool = False) -> ConfigAplicacao:
    intervalo = int(dados.get("segundos_intervalo_scan", 60))
    if intervalo <= 0:
        raise ValueError("segundos_intervalo_scan deve ser > 0")

    modo_monitoramento = _normalizar_modo_monitoramento(dados.get("modo_monitoramento"))
    observer_polling = bool(dados.get("observer_polling", False))

    expirar_hashes_dias = dados.get("expirar_hashes_dias", 180)
    if expirar_hashes_dias is None:
        expirar_hashes_dias_val: int | None = None
    else:
        expirar_hashes_dias_val = int(expirar_hashes_dias)
        if expirar_hashes_dias_val <= 0:
            raise ValueError("expirar_hashes_dias deve ser > 0 (ou null para desativar)")

    caminho_estado_raw = dados.get("caminho_estado_sqlite", "hashes/estado.sqlite3")
    caminho_estado_str = os.path.expandvars(str(caminho_estado_raw)).strip()
    caminho_estado = Path(caminho_estado_str).expanduser()
    if not caminho_estado.is_absolute():
        caminho_estado = (base_dir / caminho_estado).resolve()

    algoritmo_hash = str(dados.get("algoritmo_hash", "sha256")).strip().lower()
    try:
        hashlib.new(algoritmo_hash)
    except ValueError as exc:
        raise ValueError(f"algoritmo_hash inválido: {algoritmo_hash!r}") from exc

    tamanho_maximo_bytes = None
    if "tamanho_maximo_mb" in dados and dados["tamanho_maximo_mb"] is not None:
        tamanho_maximo_mb = int(dados["tamanho_maximo_mb"])
        if tamanho_maximo_mb <= 0:
            raise ValueError("tamanho_maximo_mb deve ser > 0")
        tamanho_maximo_bytes = tamanho_maximo_mb * 1024 * 1024

    pastas_raw = dados.get("pastas_monitoradas", [])
    if not isinstance(pastas_raw, list) or not pastas_raw:
        raise ValueError("pastas_monitoradas deve ser uma lista não vazia")

    pastas: list[PastaMonitorada] = []
    for idx, bloco in enumerate(pastas_raw, start=1):
        if not isinstance(bloco, dict):
            raise ValueError(f"pastas_monitoradas[{idx}] deve ser objeto")

        origem_raw = bloco.get("origem")
        destino_raw = bloco.get("destino")
        if not origem_raw or not destino_raw:
            raise ValueError(f"pastas_monitoradas[{idx}] precisa de 'origem' e 'destino'")

        origem_str = os.path.expandvars(str(origem_raw)).strip()
        destino_str = os.path.expandvars(str(destino_raw)).strip()
        _validar_caminho_windows(origem_str, campo="origem", idx=idx)
        _validar_caminho_windows(destino_str, campo="destino", idx=idx)
        origem = Path(origem_str).expanduser()
        destino = Path(destino_str).expanduser()
        if not origem.is_absolute():
            origem = (base_dir / origem).resolve()
        if not destino.is_absolute():
            destino = (base_dir / destino).resolve()

        if origem == destino:
            raise ValueError(f"pastas_monitoradas[{idx}] origem e destino não podem ser iguais")

        extensoes = _normalizar_extensoes(bloco.get("extensoes", []))
        recursivo = bool(bloco.get("recursivo", False))
        if recursivo and _caminho_esta_dentro_de(destino, origem):
            raise ValueError(
                f"pastas_monitoradas[{idx}] destino não pode ficar dentro da origem quando recursivo=true"
            )

        politica_conflito = _normalizar_politica_conflito(
            bloco.get("politica_conflito_destino", dados.get("politica_conflito_destino"))
        )

        pastas.append(
            PastaMonitorada(
                origem=origem,
                destino=destino,
                extensoes=extensoes,
                recursivo=recursivo,
                politica_conflito_destino=politica_conflito,
            )
        )

    permitir_symlinks = bool(dados.get("permitir_symlinks", False))
    tentativas_estabilidade = int(dados.get("tentativas_estabilidade", 3))
    intervalo_estabilidade_s = float(dados.get("intervalo_estabilidade_s", 2))
    limite_tentativas_falha = int(dados.get("limite_tentativas_falha", 3))
    tempo_ignorar_falha_s = int(dados.get("tempo_ignorar_falha_s", 600))

    if tentativas_estabilidade <= 0:
        raise ValueError("tentativas_estabilidade deve ser > 0")
    if intervalo_estabilidade_s <= 0:
        raise ValueError("intervalo_estabilidade_s deve ser > 0")
    if limite_tentativas_falha <= 0:
        raise ValueError("limite_tentativas_falha deve ser > 0")
    if tempo_ignorar_falha_s <= 0:
        raise ValueError("tempo_ignorar_falha_s deve ser > 0")

    nivel_log = logging.DEBUG if debug else _nivel_log(dados.get("nivel_log", "INFO"))

    return ConfigAplicacao(
        pastas=pastas,
        modo_monitoramento=modo_monitoramento,
        observer_polling=observer_polling,
        caminho_estado_sqlite=caminho_estado,
        expirar_hashes_dias=expirar_hashes_dias_val,
        intervalo_scan_s=intervalo,
        algoritmo_hash=algoritmo_hash,
        tentativas_estabilidade=tentativas_estabilidade,
        intervalo_estabilidade_s=intervalo_estabilidade_s,
        limite_tentativas_falha=limite_tentativas_falha,
        tempo_ignorar_falha_s=tempo_ignorar_falha_s,
        permitir_symlinks=permitir_symlinks,
        tamanho_maximo_bytes=tamanho_maximo_bytes,
        nivel_log=nivel_log,
        log_no_console=bool(dados.get("log_no_console", True)),
    )


def arquivo_esta_estavel(caminho_arquivo: Path, *, tentativas: int, intervalo_s: float) -> bool:
    anterior: tuple[int, int] | None = None
    for _ in range(tentativas):
        try:
            st = caminho_arquivo.stat()
            atual = (st.st_size, st.st_mtime_ns)
        except OSError:
            return False

        if anterior == atual:
            return True
        anterior = atual
        time.sleep(intervalo_s)
    return False


def shutil_copystat(origem: Path, destino: Path) -> None:
    import shutil

    shutil.copystat(str(origem), str(destino), follow_symlinks=False)


def _copiar_para_temp_e_calcular_hash(
    origem: Path,
    destino_dir: Path,
    *,
    algoritmo_hash: str,
) -> tuple[Path, str]:
    destino_dir.mkdir(parents=True, exist_ok=True)
    nome_final = _nome_arquivo_seguro(origem.name)
    fd, tmp = tempfile.mkstemp(dir=str(destino_dir), prefix=f".{nome_final}.", suffix=".tmp")
    tmp_path = Path(tmp)

    hasher = hashlib.new(algoritmo_hash)
    try:
        with os.fdopen(fd, "wb") as saida, origem.open("rb") as entrada:
            while True:
                bloco = entrada.read(TAMANHO_BUFFER)
                if not bloco:
                    break
                hasher.update(bloco)
                saida.write(bloco)
            saida.flush()
            os.fsync(saida.fileno())
        try:
            shutil_copystat(origem, tmp_path)
        except OSError:
            pass
        return tmp_path, hasher.hexdigest()
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _destino_incremental(destino_base: Path, contador: int) -> Path:
    return destino_base.with_name(f"{destino_base.stem} ({contador}){destino_base.suffix}")


def _destino_versionado(destino_base: Path, contador: int) -> Path:
    ts = time.strftime("%Y%m%d-%H%M%S")
    sufixo = f"_{ts}" if contador == 0 else f"_{ts}_{contador}"
    return destino_base.with_name(f"{destino_base.stem}{sufixo}{destino_base.suffix}")


def _resolver_destino_final(destino_base: Path, *, politica: str) -> Path | None:
    if not destino_base.exists():
        return destino_base
    if politica == "skip":
        return None

    max_tentativas = 1000
    if politica == "rename":
        for i in range(1, max_tentativas + 1):
            candidato = _destino_incremental(destino_base, i)
            if not candidato.exists():
                return candidato
        raise RuntimeError("não foi possível gerar nome de destino livre (rename)")

    if politica == "version":
        for i in range(0, max_tentativas + 1):
            candidato = _destino_versionado(destino_base, i)
            if not candidato.exists():
                return candidato
        raise RuntimeError("não foi possível gerar nome de destino livre (version)")

    raise ValueError(f"política de conflito desconhecida: {politica!r}")


def copiar_arquivo_seguro(
    *,
    arquivo: Path,
    pasta: PastaMonitorada,
    folder_id: str,
    logger: logging.Logger,
    config: ConfigAplicacao,
    estado: EstadoSqlite,
    tentativas_falha: dict[str, int],
    arquivos_ignorados: dict[str, float],
) -> None:
    chave = str(arquivo)
    agora = time.time()

    estado.maybe_prune(agora=agora)

    if chave in arquivos_ignorados and (agora - arquivos_ignorados[chave]) < config.tempo_ignorar_falha_s:
        return

    try:
        nome_arquivo = _nome_arquivo_seguro(arquivo.name)
    except ValueError as exc:
        logger.warning("Ignorando arquivo com nome inválido (%s): %s", arquivo, exc)
        arquivos_ignorados[chave] = agora
        return

    try:
        rel_dir = arquivo.parent.relative_to(pasta.origem)
    except ValueError:
        logger.warning("Ignorando arquivo fora da origem: %s", arquivo)
        return

    destino_dir = pasta.destino / rel_dir
    destino_base = destino_dir / nome_arquivo
    if destino_base.exists() and pasta.politica_conflito_destino == "skip":
        return

    if not arquivo_esta_estavel(
        arquivo,
        tentativas=config.tentativas_estabilidade,
        intervalo_s=config.intervalo_estabilidade_s,
    ):
        tent = tentativas_falha.get(chave, 0) + 1
        tentativas_falha[chave] = tent
        if tent >= config.limite_tentativas_falha:
            arquivos_ignorados[chave] = agora
            logger.warning("Arquivo ignorado após %d tentativas (instável/ocupado): %s", tent, arquivo)
        else:
            logger.warning(
                "Arquivo instável/ocupado (tentativa %d/%d): %s",
                tent,
                config.limite_tentativas_falha,
                arquivo,
            )
        return

    try:
        st_antes = arquivo.stat()
    except OSError as exc:
        logger.warning("Não foi possível acessar %s: %s", arquivo, exc)
        return

    if config.tamanho_maximo_bytes is not None and st_antes.st_size > config.tamanho_maximo_bytes:
        logger.warning("Arquivo excede tamanho máximo (%d bytes): %s", config.tamanho_maximo_bytes, arquivo)
        arquivos_ignorados[chave] = agora
        return

    tmp_path: Path | None = None
    try:
        tmp_path, hash_arquivo = _copiar_para_temp_e_calcular_hash(
            arquivo,
            destino_dir,
            algoritmo_hash=config.algoritmo_hash,
        )

        try:
            st_depois = arquivo.stat()
        except OSError:
            st_depois = None

        if st_depois and (st_depois.st_size != st_antes.st_size or st_depois.st_mtime_ns != st_antes.st_mtime_ns):
            raise RuntimeError("arquivo mudou durante a cópia")

        if estado.hash_ja_processado(folder_id, hash_arquivo, agora=time.time()):
            logger.info("Arquivo duplicado (hash já processado), ignorando: %s", arquivo.name)
            return

        destino_final = _resolver_destino_final(destino_base, politica=pasta.politica_conflito_destino)
        if destino_final is None:
            logger.info("Arquivo já existe no destino, ignorando: %s", destino_base.name)
            return

        for _ in range(3):
            try:
                tmp_path.rename(destino_final)
                break
            except FileExistsError:
                destino_final = _resolver_destino_final(destino_base, politica=pasta.politica_conflito_destino)
                if destino_final is None:
                    logger.info("Arquivo já existe no destino, ignorando: %s", destino_base.name)
                    return
        else:
            raise RuntimeError(f"conflito ao renomear para o destino: {destino_final}")

        estado.registrar_hash(folder_id, hash_arquivo, agora=time.time())
        logger.info("Arquivo copiado com sucesso: %s", destino_final.name)
        tentativas_falha.pop(chave, None)
        arquivos_ignorados.pop(chave, None)
        tmp_path = None

    except Exception as exc:
        tent = tentativas_falha.get(chave, 0) + 1
        tentativas_falha[chave] = tent
        if tent >= config.limite_tentativas_falha:
            arquivos_ignorados[chave] = agora
            logger.warning("Falha ao copiar (ignorando por %ds): %s (%s)", config.tempo_ignorar_falha_s, arquivo, exc)
        else:
            logger.warning(
                "Falha ao copiar (tentativa %d/%d): %s (%s)",
                tent,
                config.limite_tentativas_falha,
                arquivo,
                exc,
            )
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass


def processar_pasta(
    pasta: PastaMonitorada,
    *,
    folder_id: str,
    config: ConfigAplicacao,
    logger: logging.Logger,
    estado: EstadoSqlite,
    tentativas_falha: dict[str, int],
    arquivos_ignorados: dict[str, float],
) -> None:
    if not pasta.origem.exists():
        logger.error("Pasta de origem não encontrada: %s", pasta.origem)
        return
    if not pasta.origem.is_dir():
        logger.error("Origem não é uma pasta: %s", pasta.origem)
        return

    try:
        dirs: list[Path] = [pasta.origem]
        while dirs:
            dir_atual = dirs.pop()
            with os.scandir(dir_atual) as it:
                for entry in it:
                    if not config.permitir_symlinks and entry.is_symlink():
                        logger.warning("Ignorando link simbólico: %s", entry.path)
                        continue

                    if entry.is_dir(follow_symlinks=config.permitir_symlinks):
                        if pasta.recursivo:
                            dirs.append(Path(entry.path))
                        continue

                    if not entry.is_file(follow_symlinks=config.permitir_symlinks):
                        continue

                    if pasta.extensoes and not entry.name.lower().endswith(tuple(pasta.extensoes)):
                        continue

                    copiar_arquivo_seguro(
                        arquivo=Path(entry.path),
                        pasta=pasta,
                        folder_id=folder_id,
                        logger=logger,
                        config=config,
                        estado=estado,
                        tentativas_falha=tentativas_falha,
                        arquivos_ignorados=arquivos_ignorados,
                    )
    except Exception as exc:
        logger.warning("Erro ao listar/varrer a pasta %s: %s", pasta.origem, exc)


def monitorar_pasta(pasta: PastaMonitorada, config: ConfigAplicacao, estado: EstadoSqlite) -> None:
    logger = configurar_log(pasta.origem, config)
    folder_id = _identificador_pasta(pasta.origem)
    migrar_hashes_json_para_sqlite(pasta.origem, folder_id=folder_id, logger=logger, estado=estado)
    tentativas_falha: dict[str, int] = {}
    arquivos_ignorados: dict[str, float] = {}

    logger.info("Iniciando monitoramento: %s -> %s", pasta.origem, pasta.destino)

    while True:
        processar_pasta(
            pasta,
            folder_id=folder_id,
            config=config,
            logger=logger,
            estado=estado,
            tentativas_falha=tentativas_falha,
            arquivos_ignorados=arquivos_ignorados,
        )
        time.sleep(config.intervalo_scan_s)


def _obter_watchdog(config: ConfigAplicacao) -> tuple[Any | None, Any | None]:
    try:
        from watchdog.events import FileSystemEventHandler  # type: ignore[import-not-found]

        if config.observer_polling:
            from watchdog.observers.polling import PollingObserver as Observer  # type: ignore[import-not-found]
        else:
            from watchdog.observers import Observer  # type: ignore[import-not-found]

        return Observer, FileSystemEventHandler
    except Exception:
        return None, None


class _FilaArquivos:
    def __init__(self) -> None:
        self._fila: queue.Queue[Path] = queue.Queue()
        self._pendentes: set[Path] = set()
        self._lock = threading.Lock()

    def adicionar(self, caminho: Path) -> None:
        with self._lock:
            if caminho in self._pendentes:
                return
            self._pendentes.add(caminho)
        self._fila.put(caminho)

    def obter(self, *, timeout_s: float) -> Path | None:
        try:
            caminho = self._fila.get(timeout=timeout_s)
        except queue.Empty:
            return None
        with self._lock:
            self._pendentes.discard(caminho)
        return caminho


class _MonitorEventosPasta:
    def __init__(self, pasta: PastaMonitorada, config: ConfigAplicacao, estado: EstadoSqlite) -> None:
        self.pasta = pasta
        self.config = config
        self.estado = estado

        self.logger = configurar_log(self.pasta.origem, self.config)
        self.folder_id = _identificador_pasta(self.pasta.origem)
        migrar_hashes_json_para_sqlite(self.pasta.origem, folder_id=self.folder_id, logger=self.logger, estado=self.estado)

        self.tentativas_falha: dict[str, int] = {}
        self.arquivos_ignorados: dict[str, float] = {}

        self._stop = threading.Event()
        self._fila = _FilaArquivos()
        self._thread = threading.Thread(target=self._worker, daemon=True)

    def iniciar(self) -> None:
        self._thread.start()

    def parar(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)

    def enfileirar(self, caminho: str) -> None:
        try:
            p = Path(caminho)
        except Exception:
            return

        if self.pasta.extensoes and not p.name.lower().endswith(tuple(self.pasta.extensoes)):
            return

        self._fila.adicionar(p)

    def _worker(self) -> None:
        self.logger.info("Iniciando monitoramento por eventos: %s -> %s", self.pasta.origem, self.pasta.destino)
        while not self._stop.is_set():
            caminho = self._fila.obter(timeout_s=0.5)
            if caminho is None:
                continue

            try:
                if not caminho.exists():
                    continue
                if not self.config.permitir_symlinks and caminho.is_symlink():
                    continue
                if not caminho.is_file():
                    continue
            except OSError:
                continue

            copiar_arquivo_seguro(
                arquivo=caminho,
                pasta=self.pasta,
                folder_id=self.folder_id,
                logger=self.logger,
                config=self.config,
                estado=self.estado,
                tentativas_falha=self.tentativas_falha,
                arquivos_ignorados=self.arquivos_ignorados,
            )


def executar_monitoramento_eventos(config: ConfigAplicacao, *, estado: EstadoSqlite) -> None:
    Observer, FileSystemEventHandler = _obter_watchdog(config)
    if Observer is None or FileSystemEventHandler is None:
        raise RuntimeError("watchdog não está disponível; instale com: pip install watchdog")

    class Handler(FileSystemEventHandler):  # type: ignore[misc,valid-type]
        def __init__(self, monitor: _MonitorEventosPasta) -> None:
            super().__init__()
            self._monitor = monitor

        def on_created(self, event) -> None:  # noqa: ANN001
            if not getattr(event, "is_directory", False):
                self._monitor.enfileirar(getattr(event, "src_path", ""))

        def on_modified(self, event) -> None:  # noqa: ANN001
            if not getattr(event, "is_directory", False):
                self._monitor.enfileirar(getattr(event, "src_path", ""))

        def on_moved(self, event) -> None:  # noqa: ANN001
            if not getattr(event, "is_directory", False):
                self._monitor.enfileirar(getattr(event, "dest_path", ""))

    observer = Observer()
    monitores: list[_MonitorEventosPasta] = []

    for pasta in config.pastas:
        monitor = _MonitorEventosPasta(pasta, config, estado)

        if not pasta.origem.exists():
            monitor.logger.error("Pasta de origem não encontrada: %s", pasta.origem)
            continue
        if not pasta.origem.is_dir():
            monitor.logger.error("Origem não é uma pasta: %s", pasta.origem)
            continue

        processar_pasta(
            pasta,
            folder_id=monitor.folder_id,
            config=config,
            logger=monitor.logger,
            estado=estado,
            tentativas_falha=monitor.tentativas_falha,
            arquivos_ignorados=monitor.arquivos_ignorados,
        )

        monitor.iniciar()
        monitores.append(monitor)

        observer.schedule(Handler(monitor), str(pasta.origem), recursive=bool(pasta.recursivo))

    if not monitores:
        return

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        return
    finally:
        observer.stop()
        observer.join(timeout=5)
        for monitor in monitores:
            monitor.parar()


def executar_monitoramento(config: ConfigAplicacao, *, once: bool = False) -> None:
    inicializar_pastas()
    with EstadoSqlite(
        config.caminho_estado_sqlite,
        expirar_hashes_dias=config.expirar_hashes_dias,
    ) as estado:
        estado.maybe_prune(agora=time.time(), force=True)

        if once:
            for pasta in config.pastas:
                logger = configurar_log(pasta.origem, config)
                folder_id = _identificador_pasta(pasta.origem)
                migrar_hashes_json_para_sqlite(pasta.origem, folder_id=folder_id, logger=logger, estado=estado)
                processar_pasta(
                    pasta,
                    folder_id=folder_id,
                    config=config,
                    logger=logger,
                    estado=estado,
                    tentativas_falha={},
                    arquivos_ignorados={},
                )
            return

        if config.modo_monitoramento == "eventos":
            try:
                executar_monitoramento_eventos(config, estado=estado)
                return
            except RuntimeError as exc:
                print(f"[AVISO] {exc}. Caindo para modo varredura.", file=sys.stderr)

        threads: list[threading.Thread] = []
        for pasta in config.pastas:
            t = threading.Thread(target=monitorar_pasta, args=(pasta, config, estado), daemon=True)
            t.start()
            threads.append(t)

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            return


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Monitor de Arquivos (cópia segura por varredura)")
    parser.add_argument(
        "--config",
        default=None,
        help="Caminho do arquivo configuracao.json (padrão: ./configuracao.json)",
    )
    parser.add_argument("--once", action="store_true", help="Executa uma varredura e encerra")
    parser.add_argument("--debug", action="store_true", help="Habilita logs em nível DEBUG")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    caminho_config = Path(args.config) if args.config else (BASE_DIR / "configuracao.json")

    try:
        dados = carregar_configuracao(caminho_config)
        config = montar_config(dados, base_dir=BASE_DIR, debug=bool(args.debug))
    except Exception as exc:
        print(f"Erro na configuração ({caminho_config}): {exc}", file=sys.stderr)
        return 2

    try:
        with LockInstanciaUnica(ARQUIVO_LOCK):
            executar_monitoramento(config, once=bool(args.once))
    except ErroInstanciaUnica as exc:
        print(str(exc), file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
