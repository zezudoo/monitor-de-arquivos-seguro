# Monitor de Arquivos

Aplicação em Python para monitoramento (por varredura) de pastas no Windows.
Detecta arquivos novos/estáveis em pastas configuradas e os copia automaticamente para pastas de destino.

## Funcionalidades

- Monitora múltiplas pastas simultaneamente (threads)
- Copia apenas arquivos estáveis (tamanho + data de modificação sem mudanças por N tentativas)
- Deduplicação por hash persistente (`sha256` por padrão; configurável)
- Cópia atômica (copia para `.tmp` e renomeia no destino)
- Logs rotativos diários em `logs/` e histórico de hashes em `hashes/`
- Evita múltiplas instâncias simultâneas via `monitor.lock` (file-lock)
- Configuração via `configuracao.json`

## Como executar

- Padrão: `python monitor_de_arquivos.py`
- Outro arquivo de config: `python monitor_de_arquivos.py --config .\\configuracao.json`
- Uma única varredura (útil para testes): `python monitor_de_arquivos.py --once`
- Debug: `python monitor_de_arquivos.py --debug`

## Exemplo de configuracao.json

```json
{
  "pastas_monitoradas": [
    {
      "origem": "%USERPROFILE%\\Desktop\\origem",
      "destino": "%USERPROFILE%\\Desktop\\destino",
      "extensoes": [".txt", ".csv"]
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

- Destino/origem podem apontar para compartilhamentos SMB, mas em JSON é obrigatório escapar barras invertidas.
- Exemplo (UNC): `"destino": "\\\\servidor\\pasta"` (isso vira `\\servidor\pasta` em tempo de execução).
- Alternativa (sem escape): `"destino": "//servidor/pasta"`.

## Observações de segurança

- Mantenha a pasta de destino com permissões restritas.
- Se habilitar `permitir_symlinks`, um link dentro da pasta monitorada pode apontar para fora dela (risco de exfiltração).
