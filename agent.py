"""
agent.py — SOC Analyst AI Agent: ReAct Loop + InvestigationMemory
Implements the autonomous Tier 1 SOC Analyst using LangChain + Anthropic Claude.

Auto-detects API key type:
  - ANTHROPIC_API_KEY (sk-ant-...) → uses langchain_anthropic directly
  - OPENROUTER_API_KEY (sk-or-...)  → uses langchain_openai with OpenRouter base URL

Usage (CLI):
    python agent.py --alert sample_alerts.json
    python agent.py --json '{"alert_id":"evt_001","timestamp":"...","source_ip":"...","destination_ip":"...","service":"...","log_payload":"..."}'
"""

import json
import os
import queue
import sys
import time
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from dotenv import load_dotenv
from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, ToolMessage

from prompts import SYSTEM_PROMPT, format_alert, extract_and_validate_json
from tools import ALL_TOOLS, TOOL_MAP

load_dotenv()

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAX_ITERATIONS = 6

# OpenRouter model names
OPENROUTER_PRIMARY_MODEL = "qwen/qwen-turbo"
OPENROUTER_REPAIR_MODEL = "qwen/qwen-turbo"

# Direct Anthropic model names
ANTHROPIC_PRIMARY_MODEL = "claude-sonnet-4-6"
ANTHROPIC_REPAIR_MODEL = "claude-haiku-4-5-20251001"

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

# ---------------------------------------------------------------------------
# LLM Initialization — auto-detect key type
# ---------------------------------------------------------------------------

def _detect_api_mode() -> str:
    """Returns 'anthropic' or 'openrouter' based on available env vars."""
    if os.getenv("ANTHROPIC_API_KEY", "").startswith("sk-ant-"):
        return "anthropic"
    if os.getenv("OPENROUTER_API_KEY", ""):
        return "openrouter"
    raise EnvironmentError(
        "No valid API key found. Set ANTHROPIC_API_KEY (sk-ant-...) or OPENROUTER_API_KEY in .env"
    )


def _build_llm(primary: bool = True):
    """Build the appropriate LLM based on detected API mode."""
    mode = _detect_api_mode()
    if mode == "anthropic":
        from langchain_anthropic import ChatAnthropic
        model = ANTHROPIC_PRIMARY_MODEL if primary else ANTHROPIC_REPAIR_MODEL
        return ChatAnthropic(
            model=model,
            temperature=0.1,
            max_tokens=4096,
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
        )
    else:
        from langchain_openai import ChatOpenAI
        model = OPENROUTER_PRIMARY_MODEL if primary else OPENROUTER_REPAIR_MODEL
        return ChatOpenAI(
            model=model,
            temperature=0.1,
            max_tokens=4096,
            openai_api_key=os.getenv("OPENROUTER_API_KEY"),
            openai_api_base=OPENROUTER_BASE_URL,
            default_headers={
                "HTTP-Referer": "https://github.com/soc-analyst-ai",
                "X-Title": "SOC Analyst AI - MSCS 670",
            },
        )


# Primary LLM with all tools bound (tool schemas injected into API call)
_llm_primary = None


def get_primary_llm():
    global _llm_primary
    if _llm_primary is None:
        _llm_primary = _build_llm(primary=True).bind_tools(ALL_TOOLS)
    return _llm_primary


# ---------------------------------------------------------------------------
# InvestigationMemory
# ---------------------------------------------------------------------------

class InvestigationMemory:
    """
    Manages the full message history for a single alert investigation.
    The complete message list is passed to Claude on every call, giving it
    full context of all prior Thought → Action → Observation steps.
    """

    def __init__(self, alert: dict):
        self.alert_id = alert.get("alert_id", "unknown")
        self.messages: list = [SystemMessage(content=SYSTEM_PROMPT)]
        self.tool_call_log: list = []  # Structured feed for Streamlit rendering
        self.step_count: int = 0
        self._seen_calls: set = set()  # For loop-detection / caching

    def add_human_alert(self, alert_text: str) -> None:
        self.messages.append(HumanMessage(content=alert_text))

    def add_ai_response(self, ai_message: AIMessage) -> None:
        self.messages.append(ai_message)
        self.step_count += 1

    def add_tool_result(self, tool_call_id: str, result: str, tool_name: str) -> None:
        self.messages.append(ToolMessage(content=result, tool_call_id=tool_call_id))
        self.tool_call_log.append({
            "step": self.step_count,
            "tool": tool_name,
            "result": result,
        })

    def get_messages(self) -> list:
        return self.messages

    def is_duplicate_call(self, tool_name: str, tool_args: dict) -> bool:
        """Detect if we've already made this exact tool call (loop prevention)."""
        key = f"{tool_name}:{json.dumps(tool_args, sort_keys=True)}"
        if key in self._seen_calls:
            return True
        self._seen_calls.add(key)
        return False

    def estimate_tokens(self) -> int:
        """Rough token estimate: 1 token ≈ 4 characters."""
        return sum(len(str(getattr(m, "content", ""))) for m in self.messages) // 4


# ---------------------------------------------------------------------------
# Tool Executor — global cache (persists across alerts in batch), parallel execution
# ---------------------------------------------------------------------------

# Global cache: persists across the entire batch run (same IP/payload = instant result)
_tool_cache: dict = {}
_TOOL_EXECUTOR = ThreadPoolExecutor(max_workers=7)  # one worker per tool


def execute_tool(tool_name: str, tool_args: dict) -> str:
    """Execute a tool, returning a compact JSON string. Results cached globally."""
    cache_key = f"{tool_name}:{json.dumps(tool_args, sort_keys=True)}"
    if cache_key in _tool_cache:
        return _tool_cache[cache_key]

    if tool_name not in TOOL_MAP:
        result = f"ERROR: Tool '{tool_name}' does not exist. Available: {list(TOOL_MAP.keys())}"
    else:
        try:
            raw = TOOL_MAP[tool_name].invoke(tool_args)
            # Compact JSON (no indent) to cut token count ~40%
            result = json.dumps(raw, separators=(',', ':')) if isinstance(raw, (dict, list)) else str(raw)
        except Exception as e:
            result = f"ERROR: {str(e)}"

    _tool_cache[cache_key] = result
    return result


def execute_tools_parallel(tool_calls: list) -> dict:
    """
    Execute multiple tool calls concurrently.
    Returns {tool_call_id: result_str} mapping.
    """
    futures = {}
    for tc in tool_calls:
        future = _TOOL_EXECUTOR.submit(execute_tool, tc["name"], tc["args"])
        futures[future] = tc["id"]

    results = {}
    for future in as_completed(futures):
        call_id = futures[future]
        try:
            results[call_id] = future.result()
        except Exception as e:
            results[call_id] = f"ERROR: {str(e)}"
    return results


def clear_tool_cache() -> None:
    """Clear only the per-alert transient cache entries (keep cross-alert cache intact)."""
    pass  # Global cache retained — repeated IPs/payloads get instant hits across alerts


def reset_global_cache() -> None:
    """Full reset — call between independent batch runs."""
    _tool_cache.clear()


# ---------------------------------------------------------------------------
# Force Final Verdict (safety cap)
# ---------------------------------------------------------------------------

_FORCE_VERDICT_PROMPT = (
    'Based on all the evidence collected so far, output your final verdict as raw JSON only '
    '(no markdown, no extra text): '
    '{"verdict": "Malicious" or "Benign", "confidence": <float>, "reasoning": "<string>"}'
)

_FALLBACK_VERDICT = {
    "verdict": "Benign",
    "confidence": 0.50,
    "reasoning": "Agent failed to produce a parseable verdict. Manual review required.",
}


def force_final_verdict(memory: InvestigationMemory) -> dict:
    """
    Forces the LLM to produce a JSON verdict based on evidence collected so far.
    Called when: (a) max_iterations reached, or (b) model output non-JSON text with no tool calls.
    Retries up to 3 times with exponential backoff before returning a fallback.
    """
    plain_llm = _build_llm(primary=True)
    msgs = memory.get_messages() + [HumanMessage(content=_FORCE_VERDICT_PROMPT)]
    for attempt in range(3):
        try:
            if attempt > 0:
                time.sleep(2 ** attempt)  # 2s, 4s backoff
            response = plain_llm.invoke(msgs)
            verdict = extract_and_validate_json(response.content)
            if verdict is not None:
                return verdict
        except Exception:
            pass
    return _FALLBACK_VERDICT.copy()


# ---------------------------------------------------------------------------
# Core ReAct Loop
# ---------------------------------------------------------------------------

def run_soc_agent(alert: dict, event_queue: Optional[queue.Queue] = None) -> dict:
    """
    ReAct loop with parallel tool execution and global caching.
    Multiple tool calls returned in one LLM response are executed concurrently.
    """
    memory = InvestigationMemory(alert)
    memory.add_human_alert(format_alert(alert))

    def emit(event: dict) -> None:
        if event_queue is not None:
            event_queue.put(event)
        else:
            etype = event.get("type", "")
            if etype == "thought":
                print(f"\n[THOUGHT]\n{event['content']}")
            elif etype == "action":
                print(f"\n[ACTION] Tool: {event['tool']}")
                print(f"  Args: {json.dumps(event['args'])}")
            elif etype == "observation":
                print(f"\n[OBSERVATION] {event['tool']}\n{event['result'][:400]}")
            elif etype == "verdict":
                print(f"\n{'='*60}\n[FINAL VERDICT]")
                print(json.dumps(event["data"], indent=2))
                print('='*60)

    llm = get_primary_llm()

    for iteration in range(MAX_ITERATIONS):
        if memory.estimate_tokens() > 140_000:
            break

        response = llm.invoke(memory.get_messages())
        memory.add_ai_response(response)

        # Emit thought text
        content = response.content
        if isinstance(content, str) and content.strip():
            emit({"type": "thought", "content": content.strip()})
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text" and block.get("text", "").strip():
                    emit({"type": "thought", "content": block["text"].strip()})

        if not response.tool_calls:
            # No tool calls — extract or force verdict
            verdict = extract_and_validate_json(response.content if isinstance(response.content, str) else "")
            if verdict is None:
                verdict = force_final_verdict(memory)
            emit({"type": "verdict", "data": verdict})
            if event_queue is not None:
                event_queue.put({"type": "done"})
            return verdict

        # --- PARALLEL tool execution ---
        # Filter out duplicate calls first
        valid_calls = []
        for tc in response.tool_calls:
            if memory.is_duplicate_call(tc["name"], tc["args"]):
                emit({"type": "observation", "result": f"[cached duplicate skipped]", "tool": tc["name"]})
                memory.add_tool_result(tc["id"], "[duplicate call skipped]", tc["name"])
            else:
                emit({"type": "action", "tool": tc["name"], "args": tc["args"]})
                valid_calls.append(tc)

        if valid_calls:
            # Execute all valid tool calls at the same time
            results_map = execute_tools_parallel(valid_calls)
            for tc in valid_calls:
                result = results_map.get(tc["id"], "ERROR: no result")
                emit({"type": "observation", "result": result, "tool": tc["name"]})
                memory.add_tool_result(tc["id"], result, tc["name"])

    # Safety cap
    verdict = force_final_verdict(memory) or _FALLBACK_VERDICT.copy()
    emit({"type": "verdict", "data": verdict})
    if event_queue is not None:
        event_queue.put({"type": "done"})
    return verdict


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def _load_alert_from_file(path: str) -> list:
    """Load one or more alerts from a JSON file (object or array)."""
    with open(path, "r") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    return [data]


def main():
    parser = argparse.ArgumentParser(description="SOC Analyst AI Agent — CLI Mode")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--alert", metavar="FILE", help="Path to a JSON file containing one or more alerts.")
    group.add_argument("--json", metavar="JSON_STRING", help="Raw JSON string of a single alert.")
    args = parser.parse_args()

    if args.alert:
        alerts = _load_alert_from_file(args.alert)
    else:
        alerts = [json.loads(args.json)]

    results = []
    for alert in alerts:
        print(f"\n{'='*60}")
        print(f"Investigating alert: {alert.get('alert_id', 'unknown')}")
        print(f"{'='*60}")
        verdict = run_soc_agent(alert)
        results.append({"alert_id": alert.get("alert_id"), "verdict": verdict})

    if len(results) > 1:
        print(f"\n{'='*60}")
        print("BATCH SUMMARY")
        print(f"{'='*60}")
        for r in results:
            v = r["verdict"]
            print(f"  {r['alert_id']}: {v['verdict']} (confidence={v['confidence']:.2f})")


if __name__ == "__main__":
    main()
