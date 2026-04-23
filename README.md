# SOC Analyst AI Agent
**MSCS 670 — Agentic AI · Spring 2026**

An autonomous Tier 1 SOC (Security Operations Center) AI agent. Give it a raw security alert, and it investigates it step-by-step — calling tools, gathering evidence — and delivers a structured verdict: **Malicious** or **Benign**.

> **Benchmark: 65/65 — 100% accuracy** across Easy, Medium, and Hard security alerts.

---

## Quick Start

### 1. Clone the repo

```bash
git clone https://github.com/almurikhi974/SOC-project.git
cd SOC-project
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Add your API key

Create a `.env` file in the project folder:

**Option A — OpenRouter (free tier available)**
```
OPENROUTER_API_KEY=sk-or-your-key-here
```
Get a free key at: https://openrouter.ai

**Option B — Anthropic**
```
ANTHROPIC_API_KEY=sk-ant-your-key-here
```
Get a key at: https://console.anthropic.com

### 4. Launch the dashboard

```bash
streamlit run app.py
```

Open your browser at **http://localhost:8501**

---

## How to Use

### Single Alert
- Go to **Investigate** tab → **Single Alert (JSON)** or **Quick Sample**
- Paste a JSON alert or pick a sample
- Click **Investigate** and watch the agent reason step-by-step

### Batch Mode
- Go to **Investigate** tab → **Batch (JSON Upload)**
- Upload `65_alerts_with_labels.json` (included in the repo)
- Click **Investigate All** to process all 65 alerts

### Benchmark
- Go to the **Benchmark** tab
- Click **▶ Run Full Benchmark**
- See accuracy broken down by Easy / Medium / Hard

---

## Alert Format

```json
{
  "alert_id": "evt_001",
  "timestamp": "2026-04-12T09:15:30Z",
  "source_ip": "45.133.1.22",
  "destination_ip": "192.168.1.10",
  "service": "http_server",
  "log_payload": "GET /login.php?user=admin' OR '1'='1 HTTP/1.1 User-Agent: sqlmap/1.5"
}
```

**Output:**
```json
{
  "verdict": "Malicious",
  "confidence": 0.98,
  "reasoning": "Decoded payload reveals SQL injection. Source IP risk score 92/100. sqlmap user-agent confirmed as automated attack tool."
}
```

---

## Architecture

The agent uses a **ReAct loop** (Reason → Act → Observe):

```
Alert JSON
    │
    ▼
[LLM reads alert, forms hypothesis]
    │
    ▼  ┌──────────────────────────────┐
       │  LOOP  (max 8 iterations)    │
       │                              │
       │  LLM reasons → calls tools   │
       │  Gets results → updates      │
       │  hypothesis → loops again    │
       │                              │
       │  No more tools needed?       │
       │  → emit structured verdict   │
       └──────────────────────────────┘
```

---

## The 7 Investigative Tools

| Tool | What it does |
|------|-------------|
| `verify_ip_reputation` | Risk score, threat categories, ISP for any IP |
| `decode_payload` | URL/Base64/HTML decode + 40+ attack pattern signatures |
| `lookup_known_attack_signature` | LOLBins, CVEs, EventIDs, process names, user-agents |
| `get_user_activity_history` | Login history, auth method baseline anomalies |
| `analyze_network_traffic_context` | Volume baselines, C2 IP list, off-hours detection |
| `cve_lookup` | CVE details by ID or service + version |
| `get_geolocation_and_asn` | Country, ASN type, hosting flag, geofence violations |

---

## Benchmark Results

| Difficulty | Alerts | Correct | Accuracy |
|------------|--------|---------|----------|
| Easy | 20 | 20 / 20 | ✅ 100% |
| Medium | 20 | 20 / 20 | ✅ 100% |
| Hard | 25 | 25 / 25 | ✅ 100% |
| **Total** | **65** | **65 / 65** | ✅ **100%** |

Hard cases include: Golden Ticket attacks, LOLBin abuse (certutil, MSBuild, rundll32), C2 beaconing disguised as DNS, LSASS memory dumps, container escapes, and PAM backdoors.

---

## Files

| File | Description |
|------|-------------|
| `agent.py` | ReAct loop, InvestigationMemory, run_soc_agent() |
| `prompts.py` | System prompt, 12 few-shot examples, JSON validator |
| `tools.py` | All 7 investigative tools |
| `app.py` | Streamlit dashboard (Investigate + Benchmark + About tabs) |
| `requirements.txt` | Python dependencies |
| `65_alerts_with_labels.json` | 65 labeled test alerts |
| `65_ground_truth.json` | Ground truth labels and explanations |

---

## Deploy to Streamlit Cloud (share with anyone — no install needed)

1. Fork this repo on GitHub
2. Go to **https://share.streamlit.io** → sign in with GitHub → **New app**
3. Select your fork, branch `master`, file `app.py`
4. Click **Advanced settings → Secrets** and paste:
   ```toml
   OPENROUTER_API_KEY = "sk-or-your-key-here"
   ```
5. Click **Deploy**

Your app gets a public URL like `https://yourname-soc-project.streamlit.app` — anyone can open it in a browser with no installation required.

---

## Requirements

- Python 3.10+
- OpenRouter API key (free at https://openrouter.ai) **or** Anthropic API key
- ~500MB disk for packages
