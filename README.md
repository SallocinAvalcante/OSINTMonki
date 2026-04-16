# 🐒 OSINTMonki

Ferramenta modular de recon e OSINT focada em coleta, correlação e enriquecimento de dados de superfície de ataque digital.

Projetada para uso em Blue Team, DFIR, Threat Intelligence e investigações de segurança.

---

## 🎯 Objetivo

O OSINTMonki não é um scanner de vulnerabilidades. O foco é mapeamento de superfície, pivoting investigativo e correlação de múltiplas fontes, tanto de infraestrutura web quanto de transações blockchain.

---

## ⚙️ Funcionalidades

### 🌐 Recon de Domínio
- Enumeração de subdomínios via crt.sh e bruteforce DNS
- HTTP probing e fingerprint de tecnologias
- Detecção de CDN/WAF
- Origin discovery (identificação de IP real por trás de CDN)
- ASN mapping e expansão de infraestrutura
- TLS pivot via CertSpotter
- Reverse IP

### ⛓️ Análise de Blockchain
- Análise de transações BTC e ETH
- Pivot via endereço → transações associadas
- Clusterização de endereços (multi-input heuristic)
- Heurísticas: self-transfer, batch transaction, exchange detection
- Risk scoring por transação e consolidado por carteira
- Fallback automático entre providers (Blockstream, Blockchair, Etherscan)

---

## 🎥 Demonstração

Vídeos de uso disponíveis em [`/evidence`](./evidence/).






---

## 🚀 Como usar

**1. Clone o projeto**
```bash
git clone https://github.com/SallocinAvalcante/OSINTMonki.git
cd OSINTMonki
```

**2. Configure o ambiente**
```bash
cp .env.example .env
```

Edite o `.env` com suas chaves:
```env
SHODAN_API_KEY=
CENSYS_API_SECRET=
ETHERSCAN_API_KEY=
BLOCKCHAIR_API_KEY=
```

**3. Instale as dependências**
```bash
pip install -r requirements.txt
```

**4. Execute**
```bash
python main.py
```

---

## 🗂️ Estrutura do Projeto

```
OSINTMonki/
├── connectors/          # Integrações com APIs externas (coleta pura, sem lógica)
│   ├── blockchain/      # Blockstream, Etherscan, Blockchair, BTC Explorer
│   └── domain/          # crt.sh, CertSpotter, Shodan, Censys, Reverse IP
│
├── core/                # Orquestração central
│   ├── menu.py          # Interface CLI e fluxo do usuário
│   ├── output.py        # Renderização no terminal
│   ├── reports/         # Geradores de relatório (TX, consolidado, domínio)
│   └── scoring/         # Risk engine
│
├── modules/             # Lógica de análise principal
│   ├── blockchain/      # tx_scan, address_scan, parsers por provider
│   ├── domain/          # domain_scan, http_probe, fingerprint,
│   │                    # origin_discovery, pivot TLS
│   └── network/         # ASN lookup/expansion, CDN detection,
│                        # port scan, traceroute
│
├── models/              # Estruturas de dados padronizadas
│
├── utils/               # Helpers reutilizáveis
│   ├── blockchain/      # Resolver de tipo, formatadores, traduções
│   ├── common/          # Config loader, cache, rate limiter
│   └── domain/          # Normalização de domínio
│
├── reports/             # Relatórios gerados (ignorado no git)
├── config.yml
├── .env
└── main.py
```

**Fluxo — Domínio:**
```
Input → crt.sh / bruteforce → DNS resolve → HTTP probe
→ Fingerprint → CDN detection → Origin discovery
→ ASN mapping → TLS pivot → Reverse IP → Relatório
```

**Fluxo — Blockchain:**
```
Input (hash ou endereço) → Detecção de tipo → Connector
→ Parser → Heurísticas → Risk scoring → Relatório
```

---

## ⚠️ Limitações conhecidas

- Pipelines dependentes de fontes externas. Multiplos providers, se todos estiverem indisponiveis simultaneamente(casos raros), pode retornar sem dados na etapa
- Fingerprint baseado em regras, sem análise profunda de comportamento
- Self-transfer heuristic pode gerar falso positivo em transações de exchange com alto volume de outputs
- Execução sequencial, sem paralelismo

---

## 🛣️ Roadmap

- Refinar origin discovery e reduzir falsos positivos
- Melhorar engine de fingerprint
- Paralelismo (threading/async)
- Expansão de blockchain intelligence (graph expansion, wallet clustering)
- Cache inteligente entre sessões

---

## 📄 Licença

MIT

---

## 👨‍💻 Autor

Nicollas Cavalcante Souza
