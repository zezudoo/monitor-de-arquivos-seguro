# Monitor de Arquivos

Aplicação em Python para monitoramento de pastas no Windows e cópia segura de arquivos para uma pasta de destino.

Modos de execução:

- `eventos`: usa `watchdog` (baixa latência/CPU)
- `varredura`: scan periódico (sem dependências externas)

## Requisitos

- Python 3.10+
- Dependências (CLI + GUI): `python -m pip install -r requirements.txt`

## Funcionalidades

- Detecta arquivos novos/estáveis e copia de forma atômica (`.tmp` -> rename)
- Verifica estabilidade do arquivo antes de copiar (tamanho + mtime)
- Deduplicação por hash persistente em SQLite (`sha256` por padrão; configurável)
- Expiração de hashes (configurável via `expirar_hashes_dias`)
- Logs rotativos diários em `logs/`
- Evita múltiplas instâncias simultâneas via `monitor.lock` (file-lock)
- Opções por pasta: `recursivo` e `politica_conflito_destino`
- Migra automaticamente hashes antigos em JSON (`hashes_*.json`) para o SQLite

## Como executar

- Padrão: `python monitor_de_arquivos.py`
- Outro arquivo de config: `python monitor_de_arquivos.py --config .\\configuracao.json`
- Uma única execução (útil para testes): `python monitor_de_arquivos.py --once`
- Debug: `python monitor_de_arquivos.py --debug`

## Interface gráfica (janela + bandeja)

- Instale dependências: `python -m pip install -r requirements.txt`
- Execute: `python monitor_gui.py`
- A interface inicia/para o `monitor_de_arquivos.py` em segundo plano e exibe logs em tempo real.
- Fechar a janela (X) minimiza para a bandeja; para encerrar totalmente use **Sair** no menu da bandeja.

## Gerar executável (PyInstaller)

- Gere a GUI: `pyinstaller monitor_gui.spec`
- Gere o monitor (na mesma pasta da GUI): `pyinstaller --noconfirm --clean --onefile --distpath dist\\monitor_gui monitor_de_arquivos.py`
- Rode sempre pelo `dist/monitor_gui/monitor_gui.exe` (não pelo `_internal`).
- Ícones: `--icon monitor_icone.ico` define o ícone do arquivo `.exe`; a janela/bandeja preferem `monitor_icone.ico` ao lado do `.exe` (o `.spec` copia) e, se não achar, usam o ícone embutido no executável.

## Exemplo de configuracao.json

```json
{
  "modo_monitoramento": "eventos",
  "observer_polling": false,
  "caminho_estado_sqlite": "hashes/estado.sqlite3",
  "expirar_hashes_dias": 180,

  "pastas_monitoradas": [
    {
      "origem": "%USERPROFILE%\\Desktop\\origem",
      "destino": "%USERPROFILE%\\Desktop\\destino",
      "extensoes": [".txt", ".csv"],
      "recursivo": true,
      "politica_conflito_destino": "rename"
    }
  ],

  "segundos_intervalo_scan": 60,
  "algoritmo_hash": "sha256",
  "permitir_symlinks": false,
  "tamanho_maximo_mb": 500,
  "tentativas_estabilidade": 3,
  "intervalo_estabilidade_s": 2,
  "limite_tentativas_falha": 3,
  "tempo_ignorar_falha_s": 600,
  "nivel_log": "INFO",
  "log_no_console": true
}
```

## Rede (caminho UNC)

- Em JSON, para `\\SERVIDOR\COMPARTILHAMENTO\pasta` use `"\\\\SERVIDOR\\COMPARTILHAMENTO\\pasta"` (4 barras no começo).
- Alternativa: `"//SERVIDOR/COMPARTILHAMENTO/pasta"`.
- O usuário que executa o monitor precisa ter permissão no compartilhamento SMB; para serviços/Agendador, prefira UNC (evite drive mapeado).
- Se o compartilhamento for instável para eventos, ative `observer_polling: true` ou use `modo_monitoramento: "varredura"`.

## Observações de segurança

- Mantenha a pasta de destino com permissões restritas.
- Se habilitar `permitir_symlinks`, um link dentro da pasta monitorada pode apontar para fora dela (risco de exfiltração).
