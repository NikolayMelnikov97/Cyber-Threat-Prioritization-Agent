import os
from pathlib import Path
from dotenv import load_dotenv

# Load backend/.env if it exists (no-op when absent)
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

_client = None
_model_name: str = ""
_fallback_model: str = ""
_enabled = False

SYSTEM_PROMPT = """You are an expert cybersecurity analyst and SOC (Security Operations Center) assistant.
You help security teams prioritize and respond to CVE vulnerabilities.

Your responses must:
- Be written in clear, professional analyst language
- Explain WHY a vulnerability is dangerous, not just what it is
- Include concrete recommended actions
- Reference the specific data provided (risk scores, KEV status, cluster, anomaly flags)
- Be concise but complete — 3 to 5 paragraphs maximum
- Never mention that you are an AI or that you are using a language model
- Speak as a senior threat intelligence analyst would

When CVE data is provided, always reference:
- The risk score and what drives it
- KEV status if applicable
- Exploit availability if applicable
- Cluster context (what family of vulnerabilities this belongs to)
- Anomaly flag if present
- Recommended immediate actions"""


def _init():
    global _client, _model_name, _fallback_model, _enabled
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        print("[llm_client] No GEMINI_API_KEY — offline template mode")
        return
    _model_name = os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite").strip()
    _fallback_model = os.getenv("GEMINI_FALLBACK_MODEL", "gemini-2.0-flash-lite").strip()
    try:
        from google import genai  # type: ignore
        _client = genai.Client(api_key=api_key)
        _enabled = True
        print(f"[llm_client] Gemini initialized with model {_model_name} (fallback: {_fallback_model})")
    except Exception as e:
        print(f"[llm_client] Gemini init failed: {e}")


_init()


def is_enabled() -> bool:
    return _enabled


def generate(context: str, question: str) -> str:
    if _enabled and _client is not None:
        return _call_gemini(context, question)
    return context  # offline: chat_agent returns template response directly


def _call_gemini(context: str, question: str) -> str:
    prompt = (
        f"{SYSTEM_PROMPT}\n\n"
        f"--- THREAT INTELLIGENCE DATA ---\n{context}\n"
        f"--- END DATA ---\n\n"
        f"Analyst question: {question}"
    )
    result = _try_model(_model_name, prompt)
    if result is not None:
        return result

    # Primary model failed — try fallback if it's a different model
    if _fallback_model and _fallback_model != _model_name:
        print(f"[llm_client] Trying fallback model {_fallback_model}")
        result = _try_model(_fallback_model, prompt)
        if result is not None:
            return result

    # Both failed — return raw context for offline template rendering
    return context


def _try_model(model: str, prompt: str) -> str | None:
    try:
        response = _client.models.generate_content(model=model, contents=prompt)
        text = response.text
        if not text:
            raise ValueError("Empty response")
        return text.strip()
    except Exception as e:
        err = str(e)
        if "429" in err or "RESOURCE_EXHAUSTED" in err:
            print(f"[llm_client] {model} quota exhausted — trying fallback")
        else:
            print(f"[llm_client] {model} call failed: {e}")
        return None
