# SOC Analyst AI Agent
**MSCS 670 — Agentic AI | Spring 2026**

An autonomous Tier 1 SOC (Security Operations Center) Analyst powered by Anthropic Claude and LangChain. The agent receives a JSON security alert, reasons through it step-by-step using a ReAct loop, calls investigative tools, and produces a structured verdict.

---

## Setup

### 1. Clone and install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure API key

Create a `.env` file in the project root:

```
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

### 3. Run the web dashboard

```bash
streamlit run app.py
```

### 4. Or run from the CLI

```bash
# Investigate alerts from a JSON file
python agent.py --alert sample_alerts.json

# Investigate a single alert inline
python agent.py --json '{"alert_id":"evt_001","timestamp":"2026-04-12T09:15:30Z","source_ip":"45.133.1.22","destination_ip":"192.168.1.10","service":"http_server","log_payload":"GET /login.php?user=admin%27+OR+%271%27%3D%271 HTTP/1.1 User-Agent: sqlmap/1.5"}'
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    app.py (Streamlit UI)                     │
│  ┌──────────┐    ┌────────────────────────────────────────┐  │
│  │ Sidebar  │    │    Investigation Trace Panel (stream)  │  │
│  │ - Input  │    │  [Thought]→[Action]→[Observation]→...  │  │
│  │ - History│    │               [Verdict]                │  │
│  └──────────┘    └────────────────────────────────────────┘  │
└──────────────────────────┬──────────────────────────────────┘
                           │ threading + queue.Queue
┌──────────────────────────▼──────────────────────────────────┐
│                    agent.py (ReAct Loop)                     │
│  InvestigationMemory [messages: list grows per step]         │
│  ┌─────────┐    ┌──────────────────┐    ┌────────────────┐  │
│  │  Alert  │───▶│ llm_with_tools   │───▶│ Tool Executor  │  │
│  │  JSON   │    │ .invoke(messages)│    │ TOOL_MAP[name] │  │
│  └─────────┘    └──────────────────┘    └────────────────┘  │
│                      ▲         │ tool_calls                  │
│                      └─────────┘ ToolMessage appended        │
└────────────────────────┬────────────────────────────────────┘
          ┌──────────────┼──────────────────────────┐
┌─────────▼──┐  ┌────────▼──┐  ┌────────────────────▼──────┐
│ prompts.py │  │  tools.py │  │  langchain_anthropic       │
│ SYSTEM_    │  │  7 Tools  │  │  ChatAnthropic             │
│ PROMPT     │  │  mock DB  │  │  .bind_tools(ALL_TOOLS)    │
│ VerdictSchema  │  → real API│  │  → Anthropic API          │
└────────────┘  └───────────┘  └───────────────────────────┘
```

### ReAct Loop

The agent follows Reason → Act → Observe cycles until it reaches a conclusion:

```
Input Alert
    │
    ▼
[Initial Triage Thought]
    │
    ▼
┌─────────────────────────────────────────────────┐
│  LOOP (max 8 iterations)                        │
│                                                  │
│  Claude reasons about what to investigate next  │
│         │                                        │
│    Has tool calls?                               │
│    YES ─────────────────────────────────┐        │
│         │                               │        │
│    Emit "action" event to UI queue      │        │
│    execute_tool(name, args)             │        │
│    Emit "observation" event             │        │
│    Append ToolMessage to memory         │        │
│    Loop again ◄─────────────────────────┘        │
│         │                                        │
│    NO (no tool calls)                            │
│    extract_and_validate_json(content)            │
│    Emit "verdict" event to UI                    │
│    RETURN verdict dict                           │
└─────────────────────────────────────────────────┘
```

---

## Tools

| Tool | Purpose | Real API |
|------|---------|----------|
| `verify_ip_reputation` | Risk score, categories, ISP for any IP | AbuseIPDB / VirusTotal |
| `decode_payload` | URL/Base64/HTML decode + attack pattern matching | stdlib only (no API needed) |
| `lookup_known_attack_signature` | Match user-agents, tools, CVEs to threat intel | Internal KB |
| `get_user_activity_history` | Login events, failure counts, anomaly flags per user | SIEM / Active Directory |
| `analyze_network_traffic_context` | Volume, time-of-day, C2 destination, port anomalies | Firewall/SIEM |
| `cve_lookup` | CVE details by ID or service+version | NVD API |
| `get_geolocation_and_asn` | Country, ASN, geofence violation | MaxMind GeoLite2 |

---

## Input / Output Format

**Input:**
```json
{
  "alert_id": "evt_5501",
  "timestamp": "2026-04-12T09:15:30Z",
  "source_ip": "45.133.1.22",
  "destination_ip": "192.168.1.10",
  "service": "http_server",
  "log_payload": "GET /login.php?user=admin%27+OR+%271%27%3D%271 HTTP/1.1 User-Agent: sqlmap/1.5"
}
```

**Output:**
```json
{
  "verdict": "Malicious",
  "confidence": 0.98,
  "reasoning": "Decoded payload reveals SQL injection (OR '1'='1'). Source IP 45.133.1.22 has risk score 92/100. User-Agent 'sqlmap/1.5' confirmed as automated SQL injection tool."
}
```

---

## Files

| File | Description |
|------|-------------|
| `agent.py` | ReAct loop, `InvestigationMemory`, `run_soc_agent()`, CLI entry point |
| `prompts.py` | `SYSTEM_PROMPT` (CoT + ReAct), `format_alert()`, `VerdictSchema`, injection sanitizer |
| `tools.py` | All 7 `@tool`-decorated functions with mock databases |
| `app.py` | Streamlit dashboard with streaming trace, verdict visualization, CSV batch mode |
| `requirements.txt` | Pinned Python dependencies |

---

## Model

**Primary:** `claude-sonnet-4-6` (Anthropic)
- Temperature: 0.1 (for consistent, deterministic reasoning)
- Max tokens: 4096 per response
- Tool binding: all 7 tools injected via LangChain `.bind_tools()`
