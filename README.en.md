# File Monitor

Language: English | [Português (Brasil)](README.md)

Python application for monitoring folders on Windows and safely copying files to
a destination folder.

Execution modes:

- `eventos`: uses `watchdog` for low-latency, low-CPU monitoring.
- `varredura`: runs periodic scans without external watcher dependencies.

## Requirements

- Python 3.10 or later.
- Dependencies for CLI and GUI: `python -m pip install -r requirements.txt`.

## Features

- Detects new and stable files and copies them atomically (`.tmp` -> rename).
- Checks file stability before copying by comparing size and modification time.
- Deduplicates files with persistent SQLite hashes, using `sha256` by default.
- Expires stored hashes after a configurable number of days.
- Writes daily rotating logs in `logs/`.
- Prevents multiple simultaneous instances with `monitor.lock`.
- Supports per-folder options such as `recursivo` and
  `politica_conflito_destino`.
- Automatically migrates old JSON hash files (`hashes_*.json`) to SQLite.

## Running

- Default: `python monitor_de_arquivos.py`
- Custom config file: `python monitor_de_arquivos.py --config .\configuracao.json`
- Single run for tests: `python monitor_de_arquivos.py --once`
- Debug mode: `python monitor_de_arquivos.py --debug`

## GUI and Tray

- Install dependencies: `python -m pip install -r requirements.txt`
- Run: `python monitor_gui.py`
- The GUI starts and stops `monitor_de_arquivos.py` in the background and shows
  logs in real time.
- Closing the window minimizes it to the tray. To exit completely, use **Sair**
  from the tray menu.

## Building an Executable

- Build the GUI: `pyinstaller monitor_gui.spec`
- Build the monitor in the same GUI folder:
  `pyinstaller --noconfirm --clean --onefile --distpath dist\monitor_gui monitor_de_arquivos.py`
- Always run it through `dist/monitor_gui/monitor_gui.exe`, not from `_internal`.
- Icons: `--icon monitor_icone.ico` sets the `.exe` icon. The window and tray
  prefer `monitor_icone.ico` next to the `.exe` and fall back to the embedded
  executable icon when needed.

## `configuracao.json` Example

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

## Network Paths

- In JSON, use `"\\\\SERVER\\SHARE\\folder"` for `\\SERVER\SHARE\folder`.
- Alternative format: `"//SERVER/SHARE/folder"`.
- The user running the monitor must have permission on the SMB share. For
  services or Task Scheduler, prefer UNC paths instead of mapped drives.
- If the share is unstable for event monitoring, enable `observer_polling: true`
  or use `modo_monitoramento: "varredura"`.

## Security Notes

- Keep the destination folder restricted to the required users or service
  accounts.
- If `permitir_symlinks` is enabled, a link inside the monitored folder can
  point outside of it, which creates an exfiltration risk.
