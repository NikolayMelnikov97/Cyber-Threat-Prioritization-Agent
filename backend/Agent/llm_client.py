import os

_model = None
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
    global _model, _enabled
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        print("[llm_client] No GEMINI_API_KEY — offline template mode")
        return
    try:
        import google.generativeai as genai  # type: ignore
        genai.configure(api_key=api_key)
        _model = genai.GenerativeModel("gemini-1.5-flash")
        _enabled = True
        print("[llm_client] Gemini 1.5 Flash initialized")
    except Exception as e:
        print(f"[llm_client] Gemini init failed: {e}")


_init()


def is_enabled() -> bool:
    return _enabled


def generate(context: str, question: str) -> str:
    if _enabled and _model is not None:
        return _call_gemini(context, question)
    return context  # offline: chat_agent builds the template response directly


def _call_gemini(context: str, question: str) -> str:
    prompt = (
        f"{SYSTEM_PROMPT}\n\n"
        f"--- THREAT INTELLIGENCE DATA ---\n{context}\n"
        f"--- END DATA ---\n\n"
        f"Analyst question: {question}"
    )
    try:
        response = _model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        print(f"[llm_client] Gemini call failed: {e}")
        return context
