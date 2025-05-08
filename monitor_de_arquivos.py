import os
import sys
import json
import time
import shutil
import hashlib
import logging
import threading
import datetime
from logging.handlers import RotatingFileHandler
from typing import Dict, Any, Optional, List

PASTA_LOGS = "logs"
PASTA_HASHES = "hashes"
ARQUIVO_LOCK = "monitor.lock"
ARQUIVOS_TENTATIVAS_FALHA: Dict[str, int] = {}
ARQUIVOS_IGNORADOS: Dict[str, float] = {}
TEMPO_IGNORAR_FALHA = 600
LIMITE_TENTATIVAS = 3

os.makedirs(PASTA_LOGS, exist_ok=True)
os.makedirs(PASTA_HASHES, exist_ok=True)

def carregar_hashes(origem: str) -> Dict[str, float]:
    nome_base = origem.replace(":", "").replace("\\", "_").replace("/", "_").strip("_")
    caminho_hash = os.path.join(PASTA_HASHES, f"hashes_{nome_base}.json")
    if os.path.exists(caminho_hash):
        try:
            with open(caminho_hash, "r", encoding="utf-8") as f:
                dados = json.load(f)
                print(f"[DEBUG] {len(dados)} hashes carregados de {caminho_hash}")
                print(f"[DEBUG] Hashes de exemplo: {list(dados.keys())[:5]}")
                return dados
        except Exception as e:
            print(f"[ERRO] Falha ao carregar {caminho_hash}: {e}")
            return {}
    return {}

def salvar_hashes(origem: str, dados: Dict[str, float]) -> None:
    nome_base = origem.replace(":", "").replace("\\", "_").replace("/", "_").strip("_")
    caminho_hash = os.path.join(PASTA_HASHES, f"hashes_{nome_base}.json")
    try:
        with open(caminho_hash, "w", encoding="utf-8") as f:
            print(f"[DEBUG] Salvando {len(dados)} hashes em {caminho_hash}")
            json.dump(dados, f)
    except Exception as e:
        print(f"[ERRO] Falha ao salvar {caminho_hash}: {e}")

def configurar_log(origem: str) -> logging.Logger:
    nome_base = origem.replace(":", "").replace("\\", "_").replace("/", "_").strip("_")
    data = datetime.datetime.now().strftime("%Y-%m-%d")
    nome_arquivo_log = os.path.join(PASTA_LOGS, f"monitor_{nome_base}_{data}.log")
    logger = logging.getLogger(nome_base)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        manipulador = RotatingFileHandler(nome_arquivo_log, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8")
        formatador = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        manipulador.setFormatter(formatador)
        logger.addHandler(manipulador)
        logger.addHandler(logging.StreamHandler(sys.stdout))

    return logger

def log_evento(logger: logging.Logger, mensagem: str, nivel: str = "info") -> None:
    getattr(logger, nivel, logger.info)(mensagem)

def calcular_hash_arquivo(caminho_arquivo: str) -> Optional[str]:
    hash_md5 = hashlib.md5()
    try:
        with open(caminho_arquivo, "rb") as f:
            for bloco in iter(lambda: f.read(4096), b""):
                hash_md5.update(bloco)
        hash_final = hash_md5.hexdigest()
        print(f"[DEBUG] Hash calculado: {hash_final}")
        return hash_final
    except Exception as e:
        print(f"[ERRO] Falha ao calcular hash de {caminho_arquivo}: {e}")
        return None

def arquivo_esta_estavel(caminho_arquivo: str, tentativas: int = 3, intervalo: int = 2) -> bool:
    tamanho_anterior = -1
    for _ in range(tentativas):
        try:
            tamanho_atual = os.path.getsize(caminho_arquivo)
            if tamanho_atual == tamanho_anterior:
                return True
            tamanho_anterior = tamanho_atual
        except Exception:
            return False
        time.sleep(intervalo)
    return False

def copiar_arquivo_seguro(origem: str, destino: str, logger: logging.Logger, arquivos_processados: Dict[str, float]) -> None:
    try:
        nome_arquivo = os.path.basename(origem)
        destino_arquivo = os.path.join(destino, nome_arquivo)

        if os.path.exists(destino_arquivo):
            return  # Arquivo já existe, ignora silenciosamente

        if nome_arquivo in ARQUIVOS_IGNORADOS and time.time() - ARQUIVOS_IGNORADOS[nome_arquivo] < TEMPO_IGNORAR_FALHA:
            return

        if not os.path.exists(destino):
            os.makedirs(destino)

        log_evento(logger, f"Arquivo detectado: {nome_arquivo}")
        log_evento(logger, f"Verificando arquivo: {nome_arquivo}...")

        if not arquivo_esta_estavel(origem):
            tentativas = ARQUIVOS_TENTATIVAS_FALHA.get(nome_arquivo, 0) + 1
            ARQUIVOS_TENTATIVAS_FALHA[nome_arquivo] = tentativas
            if tentativas >= LIMITE_TENTATIVAS:
                ARQUIVOS_IGNORADOS[nome_arquivo] = time.time()
                log_evento(logger, f"Arquivo ignorado após {tentativas} tentativas: {nome_arquivo}", "warning")
            else:
                log_evento(logger, f"Arquivo instável: {origem} (tentativa {tentativas})", "warning")
            return

        hash_arquivo = calcular_hash_arquivo(origem)
        if not hash_arquivo:
            log_evento(logger, f"Hash inválido para o arquivo: {nome_arquivo}", "warning")
            return

        log_evento(logger, f"Iniciando transferência: {nome_arquivo}...")
        shutil.copy2(origem, destino_arquivo)
        arquivos_processados[hash_arquivo] = time.time()
        salvar_hashes(origem, arquivos_processados)
        log_evento(logger, f"Arquivo copiado com sucesso: {nome_arquivo}")

        ARQUIVOS_TENTATIVAS_FALHA.pop(nome_arquivo, None)
        ARQUIVOS_IGNORADOS.pop(nome_arquivo, None)

    except Exception as e:
        log_evento(logger, f"Erro ao copiar o arquivo {origem}: {str(e)}", "error")

def monitorar_pasta(origem: str, destino: str, intervalo: int, extensoes: Optional[List[str]]) -> None:
    logger = configurar_log(origem)
    arquivos_processados = carregar_hashes(origem)
    log_evento(logger, f"Iniciando monitoramento: {origem} -> {destino}")

    while True:
        try:
            for nome_arquivo in os.listdir(origem):
                if extensoes and not any(nome_arquivo.lower().endswith(ext) for ext in extensoes):
                    continue
                caminho_arquivo = os.path.join(origem, nome_arquivo)
                if os.path.isfile(caminho_arquivo):
                    copiar_arquivo_seguro(caminho_arquivo, destino, logger, arquivos_processados)
        except Exception as e:
            log_evento(logger, f"Erro ao monitorar a pasta {origem}: {str(e)}", "error")
        time.sleep(intervalo)

def verificar_instancia_unica() -> None:
    if os.path.exists(ARQUIVO_LOCK):
        print("Já existe uma instância em execução.")
        sys.exit(0)
    with open(ARQUIVO_LOCK, "w") as lock:
        lock.write(str(os.getpid()))

def remover_arquivo_lock() -> None:
    if os.path.exists(ARQUIVO_LOCK):
        os.remove(ARQUIVO_LOCK)

def carregar_configuracao(caminho: str) -> Dict[str, Any]:
    with open(caminho, 'r', encoding='utf-8') as arquivo:
        return json.load(arquivo)

def executar_monitoramento() -> None:
    verificar_instancia_unica()
    try:
        config = carregar_configuracao("configuracao.json")
        intervalo = config.get("segundos_intervalo_scan", 60)
        pastas = config.get("pastas_monitoradas", [])

        threads = []
        for bloco in pastas:
            origem = bloco.get("origem")
            destino = bloco.get("destino")
            extensoes = [e.lower() for e in bloco.get("extensoes", [])] if "extensoes" in bloco else []
            if origem and destino:
                t = threading.Thread(target=monitorar_pasta, args=(origem, destino, intervalo, extensoes), daemon=True)
                t.start()
                threads.append(t)

        while True:
            time.sleep(1)
    finally:
        remover_arquivo_lock()

if __name__ == "__main__":
    executar_monitoramento()