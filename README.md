# Monitor de Arquivos

Sistema em Python para monitoramento seguro de pastas no Windows.  
Detecta arquivos novos em pastas configuradas, verifica integridade e os copia automaticamente para pastas de destino.

---

## 🧭 Funcionalidades

- 📂 Monitora múltiplas pastas simultaneamente
- 🔐 Copia apenas arquivos 100% gravados (verificação de integridade)
- 📁 Filtra por tipo de extensão (opcional)
- 🔁 Evita duplicações via hash MD5 persistente
- 📝 Cria logs rotativos por pasta de origem
- 🧠 Detecta arquivos em uso ou instáveis e os ignora
- 🗂️ Salva o histórico de arquivos processados na pasta `hashes/`
- 🛑 Evita múltiplas instâncias simultâneas via `.lock`
- 🔧 Configuração via arquivo externo `configuracao.json`
- 📦 Empacotável como `.exe` com ícone de bandeja
- 🖥️ Exibe janela de log em tempo real ao clicar no ícone

---

## 📦 Instalação de dependências

```bash
pip install -r requirements.txt
```

---

## ⚙️ Exemplo de configuracao.json

```json
{
  "pastas_monitoradas": [
    {
      "origem": "C:\\Users\\Desktop\\origem",
      "destino": "C:\\Users\\Desktop\\destino",
      "extensoes": [".txt", ".csv"]
    }
  ],
  "segundos_intervalo_scan": 60
}
```

## 🔨 Gerando executável para Windows

1. Instale o [PyInstaller](https://pyinstaller.org) com:
   ```bash
   pip install pyinstaller
   ```
2. Execute na pasta do projeto:
   ```bash
   pyinstaller --onefile --windowed --icon monitor_icone.ico monitor_de_arquivos.py
   ```
3. O executável final estará em `dist/monitor_de_arquivos.exe`.

Ao executar o programa, um ícone será mostrado na bandeja do sistema. Utilize o
menu do ícone para abrir a janela de log ou encerrar a aplicação.
