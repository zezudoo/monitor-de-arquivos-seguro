from typing import Dict, Any, List, Optional
import os
import json
import shutil
import time
import hashlib
import logging
from logging.handlers import RotatingFileHandler
import threading
import datetime
import sys

ARQUIVOS_TENTATIVAS_FALHA: Dict[str, int] = {}
ARQUIVOS_IGNORADOS: Dict[str, float] = {}
TEMPO_IGNORAR_FALHA = 600  # segundos
LIMITE_TENTATIVAS = 3
ARQUIVO_LOCK = "monitor.lock"

def carregar_hashes(origem: str) -> Dict[str, float]:
    nome_base = origem.replace(":", "").replace("\\", "_").replace("/", "_").strip("_")
    nome_arquivo_hash = os.path.join("hashes", f"hashes_{nome_base}.json")
    if os.path.exists(nome_arquivo_hash):
        try:
            with open(nome_arquivo_hash, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def salvar_hashes(origem: str, dados: Dict[str, float]) -> None:
    nome_base = origem.replace(":", "").replace("\\", "_").replace("/", "_").strip("_")
    nome_arquivo_hash = os.path.join("hashes", f"hashes_{nome_base}.json")
    try:
        with open(nome_arquivo_hash, "w", encoding="utf-8") as f:
            json.dump(dados, f)
    except Exception:
        pass

def validar_configuracao(dados: Dict[str, Any]) -> None:
    if "pastas_monitoradas" not in dados or not isinstance(dados["pastas_monitoradas"], list):
        raise ValueError("Configuração inválida: chave 'pastas_monitoradas' ausente ou mal formatada.")
    if "segundos_intervalo_scan" not in dados:
        raise ValueError("Configuração inválida: chave 'segundos_intervalo_scan' ausente.")

def carregar_configuracao(caminho: str) -> Dict[str, Any]:
    with open(caminho, 'r', encoding='utf-8') as arquivo:
        dados = json.load(arquivo)
        validar_configuracao(dados)
        return dados

def configurar_log(origem: str) -> logging.Logger:
    nome_base = origem.replace(":", "").replace("\\", "_").replace("/", "_").strip("_")
    data = datetime.datetime.now().strftime("%Y-%m-%d")
    nome_arquivo_log = f"monitor_{nome_base}_{data}.log"
    logger = logging.getLogger(nome_base)
    logger.setLevel(logging.INFO)

    manipulador = RotatingFileHandler(nome_arquivo_log, maxBytes=5*1024*1024, backupCount=3)
    formatador = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    manipulador.setFormatter(formatador)
    if not logger.hasHandlers():
        logger.addHandler(manipulador)

    return logger

def log_evento(logger: logging.Logger, mensagem: str, nivel: str = "info") -> None:
    if nivel == "info":
        logger.info(mensagem)
    elif nivel == "warning":
        logger.warning(mensagem)
    elif nivel == "error":
        logger.error(mensagem)
    else:
        logger.debug(mensagem)

def calcular_hash_arquivo(caminho_arquivo: str) -> Optional[str]:
    hash_md5 = hashlib.md5()
    try:
        with open(caminho_arquivo, "rb") as f:
            for bloco in iter(lambda: f.read(4096), b""):
                hash_md5.update(bloco)
        return hash_md5.hexdigest()
    except Exception:
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

        if nome_arquivo in ARQUIVOS_IGNORADOS:
            if time.time() - ARQUIVOS_IGNORADOS[nome_arquivo] < TEMPO_IGNORAR_FALHA:
                return
            else:
                del ARQUIVOS_IGNORADOS[nome_arquivo]

        if not os.path.exists(destino):
            os.makedirs(destino)

        destino_arquivo = os.path.join(destino, nome_arquivo)
        log_evento(logger, f"Arquivo detectado: {nome_arquivo}")

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

        if hash_arquivo in arquivos_processados:
            return

        if os.path.exists(destino_arquivo):
            return

        shutil.copy2(origem, destino_arquivo)
        arquivos_processados[hash_arquivo] = time.time()
        salvar_hashes(origem, arquivos_processados)
        log_evento(logger, f"Arquivo copiado com sucesso: {nome_arquivo}")

        ARQUIVOS_TENTATIVAS_FALHA.pop(nome_arquivo, None)
        ARQUIVOS_IGNORADOS.pop(nome_arquivo, None)

    except Exception as e:
        log_evento(logger, f"Erro ao copiar o arquivo {origem}: {str(e)}", "error")

def monitorar_pasta(origem: str, destino: str, intervalo: int, extensoes: Optional[List[str]] = None) -> None:
    logger = configurar_log(origem)
    arquivos_processados = carregar_hashes(origem)
    log_evento(logger, f"Iniciando monitoramento: {origem} -> {destino}")

    while True:
        try:
            for nome_arquivo in os.listdir(origem):
                if extensoes and not any(nome_arquivo.lower().endswith(ext) for ext in extensoes):
                    continue
                caminho_arquivo = os.path.join(origem, str(nome_arquivo))
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

def executar_monitoramento() -> None:
    verificar_instancia_unica()
    try:
        configuracao = carregar_configuracao("configuracao.json")
        intervalo = configuracao.get("segundos_intervalo_scan", 60)
        pastas = configuracao.get("pastas_monitoradas", [])

        threads = []
        for par in pastas:
            origem = par.get("origem")
            destino = par.get("destino")
            extensoes = [e.lower() for e in par.get("extensoes", [])] if "extensoes" in par else []
            if origem and destino:
                t = threading.Thread(target=monitorar_pasta, args=(origem, destino, intervalo, extensoes), daemon=True)
                t.start()
                threads.append(t)

        while True:
            time.sleep(1)
    finally:
        remover_arquivo_lock()

executar_monitoramento()