# 🐒 OSINTMonki

Ferramenta de reconhecimento (recon) focada em coleta, correlação e enriquecimento de dados de superfície de ataque digital.

Projetada para uso em:

* Blue Team
* DFIR (Digital Forensics and Incident Response)
* Threat Intelligence
* OSINT Investigations

---

## 🎯 Objetivo

O **OSINTMonki** não é um scanner tradicional de vulnerabilidades.

Seu foco é:

* Coleta **passiva e semi-passiva**
* Correlação de múltiplas fontes
* Descoberta de ativos expostos
* Expansão de superfície via pivoting
* Análise de infraestrutura (IP, ASN, CDN)
* Apoio a investigações de segurança

A ferramenta atua como base para:

* Attack Surface Mapping
* Threat Hunting
* Validação de exposição

---

## ⚙️ Funcionalidades

### 🌐 Recon de Domínio

* Enumeração de subdomínios (crt.sh, bruteforce)
* HTTP probing
* Fingerprint de tecnologias
* Detecção de CDN/WAF
* Origin discovery (bypass de CDN)
* ASN mapping e expansão
* TLS Pivot
* Reverse IP

---

### ⛓️ Análise de Blockchain

* Análise de transações (BTC / ETH)
* Pivot via endereço → transações
* Clusterização de endereços
* Heurísticas de comportamento
* Risk scoring
* Suporte a múltiplos providers (fallback automático)

---

## 🎥 Demonstração

Vídeos de uso da ferramenta estão disponíveis em:

```
/evidence/
```

---

## 🚀 Como usar

### 1. Clone o projeto

```bash
git clone https://github.com/seu-usuario/osintmonki.git
cd osintmonki
```

---

### 2. Configure o ambiente

Crie um arquivo `.env` baseado no exemplo:

```bash
cp .env.example .env
```

Edite com suas API Keys:

```env
SHODAN_API_KEY=
CENSYS_API_SECRET=
ETHERSCAN_API_KEY=
BLOCKCHAIR_API_KEY=
```

---

### 3. Instale dependências

```bash
pip install -r requirements.txt
```

---

### 4. Execute

```bash
python main.py
```

---

## 🧠 Arquitetura

O projeto segue arquitetura modular:

* **connectors/** → Integração com APIs externas
* **modules/** → Lógica de análise e processamento
* **core/** → Orquestração, providers e relatórios
* **utils/** → Funções auxiliares

Pipeline:

```
Entrada → Coleta → Enumeração → Validação → Enriquecimento
→ Pivoting → Correlação → Relatório
```

---

## ⚠️ Limitações atuais

* Dependência de APIs externas
* Fingerprint baseado em regras simples
* Possíveis falsos positivos em origin discovery
* Execução sequencial (sem paralelismo)

---

## 🛣️ Roadmap

* Melhorar engine de fingerprint
* Refinar origin discovery
* Sistema de scoring mais robusto
* Paralelismo (threading/async)
* Expansão de blockchain intelligence

---

## 📄 Licença

Uso educacional e para pesquisa em segurança.

---

## 👨‍💻 Autor

Nicollas Cavalcante Souza
