from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
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


@dataclass(frozen=True)
class ConfigAplicacao:
    pastas: list[PastaMonitorada]
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


def montar_config(dados: dict[str, Any], *, base_dir: Path, debug: bool = False) -> ConfigAplicacao:
    intervalo = int(dados.get("segundos_intervalo_scan", 60))
    if intervalo <= 0:
        raise ValueError("segundos_intervalo_scan deve ser > 0")

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
        pastas.append(PastaMonitorada(origem=origem, destino=destino, extensoes=extensoes))

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


def copiar_arquivo_seguro(
    *,
    arquivo: Path,
    pasta_origem: Path,
    destino: Path,
    logger: logging.Logger,
    config: ConfigAplicacao,
    arquivos_processados: dict[str, float],
    tentativas_falha: dict[str, int],
    arquivos_ignorados: dict[str, float],
) -> None:
    chave = str(arquivo)
    agora = time.time()

    if chave in arquivos_ignorados and (agora - arquivos_ignorados[chave]) < config.tempo_ignorar_falha_s:
        return

    try:
        nome_arquivo = _nome_arquivo_seguro(arquivo.name)
    except ValueError as exc:
        logger.warning("Ignorando arquivo com nome inválido (%s): %s", arquivo, exc)
        arquivos_ignorados[chave] = agora
        return

    destino_arquivo = destino / nome_arquivo

    if destino_arquivo.exists():
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
            destino,
            algoritmo_hash=config.algoritmo_hash,
        )

        try:
            st_depois = arquivo.stat()
        except OSError:
            st_depois = None

        if st_depois and (st_depois.st_size != st_antes.st_size or st_depois.st_mtime_ns != st_antes.st_mtime_ns):
            raise RuntimeError("arquivo mudou durante a cópia")

        if hash_arquivo in arquivos_processados:
            logger.info("Arquivo duplicado (hash já processado), ignorando: %s", arquivo.name)
            return

        if destino_arquivo.exists():
            logger.info("Arquivo já existe no destino, ignorando: %s", destino_arquivo.name)
            return

        try:
            tmp_path.rename(destino_arquivo)
        except FileExistsError:
            logger.info("Arquivo já existe no destino, ignorando: %s", destino_arquivo.name)
            return

        arquivos_processados[hash_arquivo] = time.time()
        salvar_hashes(pasta_origem, arquivos_processados, logger)
        logger.info("Arquivo copiado com sucesso: %s", destino_arquivo.name)
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
    config: ConfigAplicacao,
    logger: logging.Logger,
    arquivos_processados: dict[str, float],
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
        with os.scandir(pasta.origem) as it:
            for entry in it:
                if entry.is_dir(follow_symlinks=False):
                    continue

                if not config.permitir_symlinks and entry.is_symlink():
                    logger.warning("Ignorando link simbólico: %s", entry.path)
                    continue

                if not entry.is_file(follow_symlinks=config.permitir_symlinks):
                    continue

                if pasta.extensoes and not entry.name.lower().endswith(tuple(pasta.extensoes)):
                    continue

                copiar_arquivo_seguro(
                    arquivo=Path(entry.path),
                    pasta_origem=pasta.origem,
                    destino=pasta.destino,
                    logger=logger,
                    config=config,
                    arquivos_processados=arquivos_processados,
                    tentativas_falha=tentativas_falha,
                    arquivos_ignorados=arquivos_ignorados,
                )
    except Exception as exc:
        logger.warning("Erro ao listar/varrer a pasta %s: %s", pasta.origem, exc)


def monitorar_pasta(pasta: PastaMonitorada, config: ConfigAplicacao) -> None:
    logger = configurar_log(pasta.origem, config)
    arquivos_processados = carregar_hashes(pasta.origem, logger)
    tentativas_falha: dict[str, int] = {}
    arquivos_ignorados: dict[str, float] = {}

    logger.info("Iniciando monitoramento: %s -> %s", pasta.origem, pasta.destino)

    while True:
        processar_pasta(
            pasta,
            config=config,
            logger=logger,
            arquivos_processados=arquivos_processados,
            tentativas_falha=tentativas_falha,
            arquivos_ignorados=arquivos_ignorados,
        )
        time.sleep(config.intervalo_scan_s)


def executar_monitoramento(config: ConfigAplicacao, *, once: bool = False) -> None:
    inicializar_pastas()

    if once:
        for pasta in config.pastas:
            logger = configurar_log(pasta.origem, config)
            arquivos_processados = carregar_hashes(pasta.origem, logger)
            processar_pasta(
                pasta,
                config=config,
                logger=logger,
                arquivos_processados=arquivos_processados,
                tentativas_falha={},
                arquivos_ignorados={},
            )
        return

    threads: list[threading.Thread] = []
    for pasta in config.pastas:
        t = threading.Thread(target=monitorar_pasta, args=(pasta, config), daemon=True)
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
