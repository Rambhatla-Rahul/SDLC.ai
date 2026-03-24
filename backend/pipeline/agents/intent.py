from core.config import llm, INTENT_SCHEMA
from core.state import DevState, should_stop
from core.utils import extract_json, make_audit_entry


def intent_agent(state: DevState) -> dict:
    if should_stop(state):
        print("[intent_agent] pipeline stopped — skipping")
        return {}
    print("[intent_agent] Starting")
    prompt = f"""
        You are an AI software architect. Convert the user description into a structured intent manifest.

        IMPORTANT: If there is a [Human modification] or [HITL feedback] section below,
        you MUST follow those instructions and they override everything else.
        If told to use PostgreSQL, use PostgreSQL — not MongoDB.
        The modification is a hard requirement, not a suggestion.

        User input:
        {state["raw_input"]}

        Respond ONLY with valid JSON, no explanation, no markdown:
        {INTENT_SCHEMA}
    """
    response = llm.invoke(prompt)
    manifest = extract_json(response.text)
    print(f"[intent_agent] Done — app_type: {manifest.get('app_type')}, modules: {[m['name'] for m in manifest.get('modules', [])]}")
    return {
        "intent_manifest": manifest,
        "audit_log": [make_audit_entry("intent_agent", f"Parsed intent for: {state['raw_input'][:80]}", {"app_type": manifest.get("app_type")})],
    }