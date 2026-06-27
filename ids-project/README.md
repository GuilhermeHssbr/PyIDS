# 🛡️ PyIDS — Python Intrusion Detection System

Sistema de detecção de intrusão de rede em tempo real com dashboard interativo no terminal.

---

## 📋 Sumário

- [Visão Geral](#visão-geral)
- [Funcionalidades](#funcionalidades)
- [Arquitetura](#arquitetura)
- [Instalação](#instalação)
- [Como Usar](#como-usar)
- [Regras de Detecção](#regras-de-detecção)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Testes](#testes)
- [Logs](#logs)
- [Limitações e Próximos Passos](#limitações-e-próximos-passos)

---

## Visão Geral

O **PyIDS** é um sistema de detecção de intrusão (IDS) baseado em rede, desenvolvido em Python. Ele captura pacotes em tempo real usando a biblioteca Scapy, aplica um conjunto de regras de detecção e exibe um dashboard interativo no terminal via `curses`.

> ⚠️ **Uso educacional:** este projeto foi desenvolvido para fins de estudo em cibersegurança. Utilize somente em redes e ambientes que você possui autorização para monitorar.

---

## Funcionalidades

- **Captura em tempo real** de pacotes TCP, UDP, ICMP e ARP
- **Motor de regras** com 7 tipos de ataques detectados
- **Dashboard no terminal** com curses — atualizado a cada 500ms
- **Logs automáticos** em formato JSONL com timestamp
- **Testes unitários** cobrindo todas as regras

---

## Arquitetura

```
Tráfego de Rede
      │
      ▼
 NetworkSniffer          ← captura pacotes (Scapy)
      │
      ▼
  RuleEngine             ← aplica regras de detecção
      │
      ▼
   Alerter               ← gerencia e persiste alertas
      │
      ▼
  Dashboard              ← exibe tudo no terminal (curses)
```

---

## Instalação

### Pré-requisitos

- Python 3.8+
- Linux (testado em Ubuntu/Debian)
- Privilégio root (necessário para captura de pacotes)

### Passo a passo

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/ids-project.git
cd ids-project

# Crie um ambiente virtual
python3 -m venv venv
source venv/bin/activate

# Instale as dependências
pip install -r requirements.txt
```

---

## Como Usar

### Listar interfaces disponíveis

```bash
sudo python3 main.py --list-interfaces
```

### Iniciar monitoramento

```bash
# Especificando a interface
sudo python3 main.py -i eth0

# Deixar o programa perguntar
sudo python3 main.py
```

### Dashboard

```
┌─────────────────────────────────────────────────────────────────┐
│  🛡  PyIDS — Intrusion Detection System      2024-12-01 14:32:05 │
├─────────────────────────────────────────────────────────────────┤
│ TRÁFEGO                                                          │
│ Pacotes: 4821   TCP: 3100   UDP: 890   ICMP: 201   Bytes: 2.3MB │
│                                                                  │
│ ALERTAS                                                          │
│ CRITICAL: 2   HIGH: 5   MEDIUM: 1   LOW: 0                      │
├─────────────────────────────────────────────────────────────────┤
│ HORA       SEV        TIPO                  ORIGEM    DETALHE    │
│ 14:31:50   CRITICAL   ARP SPOOFING          10.0.0.1  MAC mudou  │
│ 14:31:44   HIGH       PORT SCAN             10.0.0.5  20 portas  │
│ 14:30:12   HIGH       SUSPICIOUS PAYLOAD    10.0.0.9  SQL inject │
└─────────────────────────────────────────────────────────────────┘
  [Q] Sair  |  Atualiza a cada 500ms  |  Logs salvos automaticamente
```

Pressione **Q** para encerrar.

---

## Regras de Detecção

| Tipo             | Severidade | Descrição                                                     |
|------------------|------------|---------------------------------------------------------------|
| PORT SCAN        | HIGH       | Mais de 15 portas únicas acessadas em 10 segundos            |
| PACKET FLOOD     | CRITICAL   | Mais de 200 pacotes/segundo do mesmo IP                       |
| SYN FLOOD        | CRITICAL   | Mais de 100 SYNs em 2 segundos (sem ACK)                     |
| NULL SCAN        | MEDIUM     | Pacote TCP sem nenhuma flag definida                          |
| XMAS SCAN        | MEDIUM     | Flags FIN + PSH + URG ativas simultaneamente                  |
| ICMP FLOOD       | HIGH       | Mais de 50 pings/segundo do mesmo IP                          |
| ARP SPOOFING     | CRITICAL   | Mudança de MAC para um IP já registrado na tabela ARP         |
| SUSPICIOUS PAYLOAD | HIGH     | Padrões de SQLi, XSS, path traversal ou shell injection       |

Os limiares podem ser ajustados diretamente em `src/rules.py`.

---

## Estrutura do Projeto

```
ids-project/
├── main.py              # Ponto de entrada
├── requirements.txt     # Dependências
├── .gitignore
├── README.md
├── src/
│   ├── __init__.py
│   ├── sniffer.py       # Captura de pacotes
│   ├── rules.py         # Motor de regras
│   ├── alerter.py       # Gerenciamento de alertas
│   └── dashboard.py     # Dashboard no terminal
├── tests/
│   └── test_rules.py    # Testes unitários
├── logs/                # Logs gerados em runtime (ignorados pelo git)
└── docs/
    └── architecture.png # (opcional) diagrama de arquitetura
```

---

## Testes

```bash
# Com o venv ativo
pytest tests/ -v
```

Todos os testes não requerem root e rodam sem tráfego real — os pacotes são criados sinteticamente com Scapy.

---

## Logs

Cada execução cria um arquivo `logs/ids_YYYYMMDD_HHMMSS.jsonl`. Cada linha é um JSON com:

```json
{
  "severity": "HIGH",
  "type": "PORT SCAN",
  "src_ip": "192.168.1.50",
  "detail": "20 portas únicas em 10s",
  "timestamp": "14:31:44",
  "epoch": 1733060704.21
}
```

---

## Limitações e Próximos Passos

- [ ] Adicionar whitelist de IPs confiáveis
- [ ] Suporte a múltiplas interfaces simultâneas
- [ ] Exportação de relatório em HTML/PDF
- [ ] Integração com notificações (e-mail, Telegram)
- [ ] Modo passivo com arquivo de captura `.pcap`

---

## Tecnologias

- [Scapy](https://scapy.net/) — captura e análise de pacotes
- [curses](https://docs.python.org/3/library/curses.html) — dashboard no terminal
- [pytest](https://pytest.org/) — testes unitários

---

## Licença

MIT — veja [LICENSE](LICENSE) para detalhes.
