from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


BASE_DIR = _base_dir()
DEFAULT_CONFIG = BASE_DIR / "configuracao.json"
DEFAULT_ICON = BASE_DIR / "monitor_icone.ico"
LOGS_DIR = BASE_DIR / "logs"


try:
    from PySide6.QtCore import QFileInfo, QProcess, QTimer, Qt, Slot
    from PySide6.QtGui import QAction, QCloseEvent, QIcon, QTextCursor
    from PySide6.QtWidgets import (
        QApplication,
        QCheckBox,
        QFileIconProvider,
        QFileDialog,
        QGroupBox,
        QHBoxLayout,
        QLabel,
        QLineEdit,
        QMainWindow,
        QMenu,
        QMessageBox,
        QPushButton,
        QPlainTextEdit,
        QStyle,
        QSystemTrayIcon,
        QTabWidget,
        QTableWidget,
        QTableWidgetItem,
        QVBoxLayout,
        QWidget,
    )
except Exception as exc:  # pragma: no cover
    print(
        "PySide6 não está instalado. Instale com:\n"
        "  python -m pip install -r requirements.txt\n"
        f"Detalhes: {exc}",
        file=sys.stderr,
    )
    raise SystemExit(1)


@dataclass(frozen=True)
class PastaUI:
    origem: str
    destino: str
    extensoes: str
    recursivo: bool
    conflito: str


def _ler_json(path: Path) -> dict[str, Any]:
    conteudo = path.read_text(encoding="utf-8-sig")
    dados = json.loads(conteudo)
    if not isinstance(dados, dict):
        raise ValueError("configuração inválida (esperado objeto JSON)")
    return dados


def _formatar_json(dados: Any) -> str:
    return json.dumps(dados, ensure_ascii=False, indent=2, sort_keys=False) + "\n"


def _extrair_pastas(dados: dict[str, Any]) -> list[PastaUI]:
    pastas_raw = dados.get("pastas_monitoradas", [])
    if not isinstance(pastas_raw, list):
        return []

    resultado: list[PastaUI] = []
    for bloco in pastas_raw:
        if not isinstance(bloco, dict):
            continue
        origem = str(bloco.get("origem", ""))
        destino = str(bloco.get("destino", ""))
        extensoes_val = bloco.get("extensoes", [])
        if isinstance(extensoes_val, list):
            extensoes = ", ".join(str(e) for e in extensoes_val)
        else:
            extensoes = str(extensoes_val)
        recursivo = bool(bloco.get("recursivo", False))
        conflito = str(bloco.get("politica_conflito_destino", "skip"))
        resultado.append(
            PastaUI(
                origem=origem,
                destino=destino,
                extensoes=extensoes,
                recursivo=recursivo,
                conflito=conflito,
            )
        )
    return resultado


def _carregar_icone_app(app: QApplication) -> QIcon:
    if DEFAULT_ICON.exists():
        icon = QIcon(str(DEFAULT_ICON))
        if not icon.isNull():
            return icon

    if getattr(sys, "frozen", False):
        try:
            provider = QFileIconProvider()
            icon = provider.icon(QFileInfo(sys.executable))
            if not icon.isNull():
                return icon
        except Exception:
            pass

    return app.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Monitor de Arquivos")
        self.setWindowIcon(QApplication.windowIcon())
        self.setMinimumSize(900, 600)

        self._closing = False
        self._output_buffer = ""
        self._counters = {"INFO": 0, "WARNING": 0, "ERROR": 0, "COPIADOS": 0, "DUPLICADOS": 0}

        self._process = QProcess(self)
        self._process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self._process.started.connect(self._on_started)
        self._process.finished.connect(self._on_finished)
        self._process.errorOccurred.connect(self._on_error)
        self._process.readyReadStandardOutput.connect(self._on_ready_read)

        self._tray = None
        self._tray_menu = None
        self._action_show_hide = None
        self._action_start = None
        self._action_stop = None

        self._build_ui()
        self._setup_tray()
        self._refresh_from_disk()
        self._update_buttons()

    def _build_ui(self) -> None:
        tabs = QTabWidget()
        tabs.addTab(self._build_status_tab(), "Status")
        tabs.addTab(self._build_config_tab(), "Configuração")
        tabs.addTab(self._build_logs_tab(), "Logs")
        self.setCentralWidget(tabs)

    def _build_status_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        grp = QGroupBox("Controle")
        form = QHBoxLayout(grp)

        self.config_path = QLineEdit(str(DEFAULT_CONFIG))
        self.config_path.setPlaceholderText("Caminho do configuracao.json")
        btn_browse = QPushButton("Escolher…")
        btn_browse.clicked.connect(self._choose_config)

        self.chk_debug = QCheckBox("Debug")
        self.chk_debug.setToolTip("Inicia o monitor com --debug")

        self.btn_start = QPushButton("Iniciar")
        self.btn_start.clicked.connect(self.start_monitor)
        self.btn_stop = QPushButton("Parar")
        self.btn_stop.clicked.connect(self.stop_monitor)
        self.btn_refresh = QPushButton("Atualizar")
        self.btn_refresh.clicked.connect(self._refresh_from_disk)
        self.btn_open_logs = QPushButton("Abrir logs")
        self.btn_open_logs.clicked.connect(self._open_logs_folder)

        form.addWidget(QLabel("Config:"))
        form.addWidget(self.config_path, 1)
        form.addWidget(btn_browse)
        form.addWidget(self.chk_debug)
        form.addWidget(self.btn_start)
        form.addWidget(self.btn_stop)
        form.addWidget(self.btn_refresh)
        form.addWidget(self.btn_open_logs)
        layout.addWidget(grp)

        status_row = QHBoxLayout()
        self.lbl_status = QLabel("Status: parado")
        self.lbl_status.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.lbl_modo = QLabel("Modo: -")
        self.lbl_modo.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        status_row.addWidget(self.lbl_status)
        status_row.addStretch(1)
        status_row.addWidget(self.lbl_modo)
        layout.addLayout(status_row)

        counters_row = QHBoxLayout()
        self.lbl_copiados = QLabel("Copiados: 0")
        self.lbl_duplicados = QLabel("Duplicados: 0")
        self.lbl_info = QLabel("INFO: 0")
        self.lbl_warning = QLabel("WARNING: 0")
        self.lbl_error = QLabel("ERROR: 0")
        for lbl in (self.lbl_copiados, self.lbl_duplicados, self.lbl_info, self.lbl_warning, self.lbl_error):
            lbl.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            counters_row.addWidget(lbl)
        counters_row.addStretch(1)
        layout.addLayout(counters_row)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Origem", "Destino", "Extensões", "Recursivo", "Conflito"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.table, 1)

        return w

    def _build_config_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        btns = QHBoxLayout()
        self.btn_load_cfg = QPushButton("Carregar do arquivo")
        self.btn_load_cfg.clicked.connect(self._load_config_into_editor)
        self.btn_save_cfg = QPushButton("Salvar no arquivo")
        self.btn_save_cfg.clicked.connect(self._save_editor_to_config)
        self.btn_format_cfg = QPushButton("Formatar JSON")
        self.btn_format_cfg.clicked.connect(self._format_editor_json)
        btns.addWidget(self.btn_load_cfg)
        btns.addWidget(self.btn_save_cfg)
        btns.addWidget(self.btn_format_cfg)
        btns.addStretch(1)
        layout.addLayout(btns)

        self.editor = QPlainTextEdit()
        self.editor.setPlaceholderText("Conteúdo do configuracao.json")
        layout.addWidget(self.editor, 1)
        return w

    def _build_logs_tab(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)

        btns = QHBoxLayout()
        btn_clear = QPushButton("Limpar")
        btn_clear.clicked.connect(self._clear_logs)
        btn_copy = QPushButton("Copiar tudo")
        btn_copy.clicked.connect(self._copy_logs_to_clipboard)
        btns.addWidget(btn_clear)
        btns.addWidget(btn_copy)
        btns.addStretch(1)
        layout.addLayout(btns)

        self.logs = QPlainTextEdit()
        self.logs.setReadOnly(True)
        layout.addWidget(self.logs, 1)
        return w

    def _setup_tray(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return

        icon = QApplication.windowIcon()
        if icon.isNull():
            icon = self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon)
        tray = QSystemTrayIcon(icon, self)
        tray.setToolTip("Monitor de Arquivos")
        tray.activated.connect(self._tray_activated)

        menu = QMenu()
        self._action_show_hide = QAction("Mostrar/Ocultar", self)
        self._action_show_hide.triggered.connect(self._toggle_visible)
        self._action_start = QAction("Iniciar", self)
        self._action_start.triggered.connect(self.start_monitor)
        self._action_stop = QAction("Parar", self)
        self._action_stop.triggered.connect(self.stop_monitor)
        action_open_logs = QAction("Abrir logs", self)
        action_open_logs.triggered.connect(self._open_logs_folder)
        action_quit = QAction("Sair", self)
        action_quit.triggered.connect(self._quit_app)

        menu.addAction(self._action_show_hide)
        menu.addSeparator()
        menu.addAction(self._action_start)
        menu.addAction(self._action_stop)
        menu.addSeparator()
        menu.addAction(action_open_logs)
        menu.addSeparator()
        menu.addAction(action_quit)

        tray.setContextMenu(menu)
        tray.show()
        self._tray = tray
        self._tray_menu = menu

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        if self._closing or self._tray is None:
            event.accept()
            return
        self.hide()
        self._tray.showMessage("Monitor de Arquivos", "Continuando em segundo plano na bandeja.")
        event.ignore()

    def _tray_activated(self, reason) -> None:  # noqa: ANN001
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self._toggle_visible()

    @Slot()
    def _toggle_visible(self) -> None:
        if self.isVisible():
            self.hide()
        else:
            self.showNormal()
            self.raise_()
            self.activateWindow()

    @Slot()
    def _choose_config(self) -> None:
        caminho, _ = QFileDialog.getOpenFileName(
            self,
            "Escolher configuracao.json",
            str(BASE_DIR),
            "JSON (*.json);;Todos (*.*)",
        )
        if caminho:
            self.config_path.setText(caminho)
            self._refresh_from_disk()

    def _refresh_from_disk(self) -> None:
        path = Path(self.config_path.text().strip() or str(DEFAULT_CONFIG))
        if not path.exists():
            self.lbl_modo.setText("Modo: -")
            self._set_table([])
            return
        try:
            dados = _ler_json(path)
        except Exception as exc:
            self._append_log(f"[ERRO] Falha ao ler config: {exc}")
            self.lbl_modo.setText("Modo: -")
            self._set_table([])
            return

        modo = str(dados.get("modo_monitoramento", "eventos"))
        self.lbl_modo.setText(f"Modo: {modo}")
        self._set_table(_extrair_pastas(dados))

    def _load_config_into_editor(self) -> None:
        path = Path(self.config_path.text().strip() or str(DEFAULT_CONFIG))
        try:
            dados = _ler_json(path)
        except Exception as exc:
            QMessageBox.critical(self, "Erro", f"Falha ao carregar {path}:\n{exc}")
            return
        self.editor.setPlainText(_formatar_json(dados))

    def _format_editor_json(self) -> None:
        texto = self.editor.toPlainText()
        try:
            dados = json.loads(texto or "{}")
        except Exception as exc:
            QMessageBox.warning(self, "JSON inválido", f"Não foi possível interpretar o JSON:\n{exc}")
            return
        self.editor.setPlainText(_formatar_json(dados))

    def _save_editor_to_config(self) -> None:
        path = Path(self.config_path.text().strip() or str(DEFAULT_CONFIG))
        texto = self.editor.toPlainText()
        try:
            dados = json.loads(texto)
        except Exception as exc:
            QMessageBox.warning(self, "JSON inválido", f"Não foi possível interpretar o JSON:\n{exc}")
            return
        try:
            path.write_text(_formatar_json(dados), encoding="utf-8")
        except Exception as exc:
            QMessageBox.critical(self, "Erro", f"Falha ao salvar {path}:\n{exc}")
            return
        self._refresh_from_disk()
        QMessageBox.information(self, "OK", f"Configuração salva em:\n{path}")

    @Slot()
    def start_monitor(self) -> None:
        if self._process.state() != QProcess.ProcessState.NotRunning:
            return
        config_path = self.config_path.text().strip() or str(DEFAULT_CONFIG)
        args = ["--config", config_path, "--force-console", "--parent-pid", str(os.getpid())]
        if self.chk_debug.isChecked():
            args.append("--debug")

        self._process.setWorkingDirectory(str(BASE_DIR))
        if getattr(sys, "frozen", False):
            exe = BASE_DIR / "monitor_de_arquivos.exe"
            if not exe.exists():
                QMessageBox.critical(
                    self,
                    "Erro",
                    "Não foi possível localizar o executável do monitor.\n\n"
                    "Esperado em:\n"
                    f"{exe}\n\n"
                    "Dica: ao empacotar, coloque monitor_gui.exe e monitor_de_arquivos.exe na mesma pasta.",
                )
                return
            program = str(exe)
            self._process.setProgram(program)
            self._process.setArguments(args)
            self._append_log(f"[GUI] Iniciando: {program} {' '.join(args)}")
        else:
            script = BASE_DIR / "monitor_de_arquivos.py"
            if not script.exists():
                QMessageBox.critical(self, "Erro", f"Não foi possível localizar:\n{script}")
                return
            program = sys.executable
            self._process.setProgram(program)
            self._process.setArguments([str(script), *args])
            self._append_log(f"[GUI] Iniciando: {program} {script} {' '.join(args)}")
        self._process.start()
        self._update_buttons()

    @Slot()
    def stop_monitor(self) -> None:
        if self._process.state() == QProcess.ProcessState.NotRunning:
            return
        pid = int(self._process.processId())
        self._append_log("[GUI] Parando monitor…")
        self._process.terminate()

        def _kill_if_needed() -> None:
            if self._process.state() != QProcess.ProcessState.NotRunning:
                self._append_log("[GUI] Forçando encerramento…")
                self._force_kill_tree(pid)

        QTimer.singleShot(3000, _kill_if_needed)
        self._update_buttons()

    def _force_kill_tree(self, pid: int) -> None:
        if pid <= 0:
            self._process.kill()
            return

        if not sys.platform.startswith("win"):
            self._process.kill()
            return

        try:
            creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
            result = subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                capture_output=True,
                text=True,
                creationflags=creationflags,
            )
            if result.returncode != 0:
                msg = (result.stderr or result.stdout or "").strip()
                if msg:
                    self._append_log(f"[GUI] taskkill falhou: {msg}")
                self._process.kill()
        except Exception as exc:
            self._append_log(f"[GUI] Falha ao forçar encerramento: {exc}")
            self._process.kill()

    def _on_started(self) -> None:
        self.lbl_status.setText("Status: executando")
        self._update_buttons()

    def _on_finished(self, exit_code: int, exit_status) -> None:  # noqa: ANN001
        self.lbl_status.setText(f"Status: parado (exit={exit_code})")
        self._append_log(f"[GUI] Processo finalizado (exit={exit_code})")
        self._update_buttons()
        if self._closing:
            app = QApplication.instance()
            if app is not None:
                app.quit()

    def _on_error(self, err) -> None:  # noqa: ANN001
        self._append_log(f"[GUI] Erro do processo: {err}")
        self._update_buttons()

    def _on_ready_read(self) -> None:
        raw = self._process.readAllStandardOutput().data()
        data: bytes = bytes(raw)
        if not data:
            return
        texto = data.decode("utf-8", errors="replace")
        self._consume_output(texto)

    def _consume_output(self, texto: str) -> None:
        self._output_buffer += texto
        while True:
            idx = self._output_buffer.find("\n")
            if idx < 0:
                break
            line = self._output_buffer[:idx].rstrip("\r")
            self._output_buffer = self._output_buffer[idx + 1 :]
            if line:
                self._append_log(line)
                self._update_counters_from_line(line)

    def _update_counters_from_line(self, line: str) -> None:
        if " - INFO - " in line:
            self._counters["INFO"] += 1
        elif " - WARNING - " in line:
            self._counters["WARNING"] += 1
        elif " - ERROR - " in line:
            self._counters["ERROR"] += 1

        if "Arquivo copiado com sucesso" in line:
            self._counters["COPIADOS"] += 1
        if "Arquivo duplicado" in line:
            self._counters["DUPLICADOS"] += 1

        self.lbl_copiados.setText(f"Copiados: {self._counters['COPIADOS']}")
        self.lbl_duplicados.setText(f"Duplicados: {self._counters['DUPLICADOS']}")
        self.lbl_info.setText(f"INFO: {self._counters['INFO']}")
        self.lbl_warning.setText(f"WARNING: {self._counters['WARNING']}")
        self.lbl_error.setText(f"ERROR: {self._counters['ERROR']}")

    def _append_log(self, line: str) -> None:
        self.logs.appendPlainText(line)
        cursor = self.logs.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        self.logs.setTextCursor(cursor)

        max_lines = 5000
        if self.logs.blockCount() > max_lines:
            doc = self.logs.document()
            cursor = QTextCursor(doc)
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            cursor.select(QTextCursor.SelectionType.LineUnderCursor)
            for _ in range(self.logs.blockCount() - max_lines):
                cursor.removeSelectedText()
                cursor.deleteChar()
                cursor.movePosition(QTextCursor.MoveOperation.Start)
                cursor.select(QTextCursor.SelectionType.LineUnderCursor)

    def _clear_logs(self) -> None:
        self._output_buffer = ""
        self._counters = {"INFO": 0, "WARNING": 0, "ERROR": 0, "COPIADOS": 0, "DUPLICADOS": 0}
        self.logs.clear()
        self._update_counters_from_line("")

    def _copy_logs_to_clipboard(self) -> None:
        QApplication.clipboard().setText(self.logs.toPlainText())

    def _open_logs_folder(self) -> None:
        LOGS_DIR.mkdir(exist_ok=True)
        try:
            os.startfile(str(LOGS_DIR))  # type: ignore[attr-defined]
        except Exception as exc:
            QMessageBox.warning(self, "Erro", f"Não foi possível abrir:\n{LOGS_DIR}\n\n{exc}")

    def _set_table(self, pastas: list[PastaUI]) -> None:
        self.table.setRowCount(len(pastas))
        for row, pasta in enumerate(pastas):
            self.table.setItem(row, 0, QTableWidgetItem(pasta.origem))
            self.table.setItem(row, 1, QTableWidgetItem(pasta.destino))
            self.table.setItem(row, 2, QTableWidgetItem(pasta.extensoes))
            self.table.setItem(row, 3, QTableWidgetItem("sim" if pasta.recursivo else "não"))
            self.table.setItem(row, 4, QTableWidgetItem(pasta.conflito))

    def _update_buttons(self) -> None:
        running = self._process.state() != QProcess.ProcessState.NotRunning
        self.btn_start.setEnabled(not running)
        self.btn_stop.setEnabled(running)
        if self._action_start:
            self._action_start.setEnabled(not running)
        if self._action_stop:
            self._action_stop.setEnabled(running)

    def _quit_app(self) -> None:
        app = QApplication.instance()
        if app is None:
            return

        self._closing = True
        if self._tray is not None:
            self._tray.hide()
        if self._process.state() != QProcess.ProcessState.NotRunning:
            self.stop_monitor()
            return
        app.quit()


def main() -> int:
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setWindowIcon(_carregar_icone_app(app))
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
