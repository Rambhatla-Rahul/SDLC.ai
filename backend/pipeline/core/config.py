import os
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
# from langchain_ollama import ChatOllama

load_dotenv()

llm = ChatGoogleGenerativeAI(
    model="gemini-3.1-flash-lite-preview",
    api_key=os.getenv("GEMINI_API_KEY"),
    temperature=0.1,
)

# code_gen_llm = ChatOllama(
#     model="qwen3.5:9b",
#     temperature=0.1,
# )

KNOWN_LICENSES = {
    "fastapi":    {"license": "MIT",        "risk": "low"},
    "sqlalchemy": {"license": "MIT",        "risk": "low"},
    "pydantic":   {"license": "MIT",        "risk": "low"},
    "uvicorn":    {"license": "BSD",        "risk": "low"},
    "postgresql": {"license": "PostgreSQL", "risk": "low"},
    "alembic":    {"license": "MIT",        "risk": "low"},
    "passlib":    {"license": "BSD",        "risk": "low"},
    "jose":       {"license": "MIT",        "risk": "low"},
    "httpx":      {"license": "BSD",        "risk": "low"},
    "starlette":  {"license": "BSD",        "risk": "low"},
    "asyncpg":    {"license": "Apache-2.0", "risk": "low"},
    "pyjwt":      {"license": "MIT",        "risk": "low"},
    "jinja2":     {"license": "BSD",        "risk": "low"},
    "celery":     {"license": "BSD",        "risk": "low"},
    "redis":      {"license": "BSD",        "risk": "low"},
    "gpl":        {"license": "GPL",        "risk": "high"},
    "mysql":      {"license": "GPL",        "risk": "high"},
}

COMPLIANCE_FRAMEWORKS = {
    "gdpr": {
        "full_name": "General Data Protection Regulation",
        "triggers":  ["user data", "login", "personal data", "email", "profile", "authentication"],
        "rules": [
            "User data must be encrypted at rest and in transit",
            "Users must be able to request data deletion",
            "Explicit consent required before data collection",
            "Data breach notification within 72 hours",
            "Minimal data collection principle must be followed",
        ],
    },
    "owasp": {
        "full_name": "OWASP Top 10",
        "triggers":  ["login", "authentication", "api", "web", "dashboard", "jwt", "password"],
        "rules": [
            "Protect against SQL injection via parameterised queries",
            "Implement proper session management and token expiry",
            "Enforce HTTPS and secure cookie flags",
            "Rate limit authentication endpoints",
            "Validate and sanitise all user inputs",
        ],
    },
    "hipaa": {
        "full_name": "Health Insurance Portability and Accountability Act",
        "triggers":  ["health", "medical", "patient", "diagnosis", "prescription"],
        "rules": [
            "PHI must be encrypted at rest and in transit",
            "Access logs must be maintained for all PHI access",
            "Role-based access control for all health data",
        ],
    },
    "pci_dss": {
        "full_name": "Payment Card Industry Data Security Standard",
        "triggers":  ["payment", "card", "billing", "checkout", "stripe", "transaction"],
        "rules": [
            "Card data must never be stored in plaintext",
            "Use tokenisation for all payment data",
            "Strict access control to cardholder data",
        ],
    },
}

ARCHITECTURE_PATTERNS = {
    "layered":          {"description": "Traditional N-tier",                                       "best_for": ["web apps", "dashboards"],    "trade_offs": {"scalability": "medium", "complexity": "low",  "security": "high"}},
    "microservices":    {"description": "Independent services via APIs",                            "best_for": ["large teams", "high scale"], "trade_offs": {"scalability": "high",   "complexity": "high", "security": "medium"}},
    "modular_monolith": {"description": "Single deployable with strict internal module boundaries", "best_for": ["small teams", "early stage"],"trade_offs": {"scalability": "medium", "complexity": "low",  "security": "high"}},
}

SECURITY_RULES = {
    "hardcoded_secrets": {"pattern": r'(SECRET_KEY|PASSWORD|API_KEY|TOKEN|secret|password)\s*=\s*["\'][^"\']+["\']', "severity": "critical", "owasp": "A02:2021 Cryptographic Failures",    "fix": "Move to environment variables"},
    "sql_injection":     {"pattern": r'execute\s*\(\s*[f"\'].*\{',                                                  "severity": "critical", "owasp": "A03:2021 Injection",                  "fix": "Use SQLAlchemy ORM or parameterized queries"},
    "debug_mode":        {"pattern": r'DEBUG\s*=\s*True|reload\s*=\s*True',                                         "severity": "high",     "owasp": "A05:2021 Security Misconfiguration",  "fix": "Disable debug/reload in production"},
    "http_not_https":    {"pattern": r'http://(?!localhost|127\.0\.0\.1)',                                           "severity": "high",     "owasp": "A02:2021 Cryptographic Failures",    "fix": "Use HTTPS for all external URLs"},
    "bare_except":       {"pattern": r'except\s*:',                                                                 "severity": "medium",   "owasp": "A09:2021 Security Logging Failures", "fix": "Catch specific exceptions"},
    "unlicensed_import": {"pattern": None,                                                                           "severity": "high",     "owasp": "IP Compliance",                      "fix": "Use only IP-cleared libraries"},
}

INTENT_SCHEMA         = '{"app_type":"string","modules":[{"name":"string","description":"string","tech_stack":["string"]}],"constraints":{"security":["string"],"compliance":["string"],"performance":["string"],"ip_notes":["string"]},"acceptance_criteria":["string"]}'
IP_SCAN_SCHEMA        = '{"scanned_libraries":[{"name":"string","license":"string","risk_level":"low|medium|high","reason":"string"}],"overall_risk":"low|medium|high","flagged_items":["string"],"recommendation":"string"}'
COMPLIANCE_SCHEMA     = '{"applicable_frameworks":[{"name":"string","reason":"string","rules":["string"],"priority":"mandatory|recommended"}],"consolidated_rules":[{"rule":"string","framework":"string","implementation_hint":"string"}],"gaps":["string"],"overall_compliance_risk":"low|medium|high"}'
ARCHITECTURE_SCHEMA   = '{"selected_pattern":"string","pattern_rationale":"string","layers":[{"name":"string","responsibility":"string","components":["string"],"tech":["string"],"compliance_controls":["string"]}],"infrastructure":{"database":"string","cache":"string","tls":"string","rate_limiter":"string","audit_store":"string"},"security_controls":["string"],"trade_off_matrix":{"scalability":"low|medium|high","complexity":"low|medium|high","security":"low|medium|high","compliance_fit":"low|medium|high"},"gaps_addressed":["string"],"residual_risks":["string"]}'
CODEGEN_SCHEMA        = '{"modules":[{"filename":"string","layer":"string","description":"string","rationale":"string","compliance_controls":["string"],"code":"string"}],"project_structure":["string"],"setup_instructions":["string"],"dependencies":["string"]}'
OPTIMIZER_SCHEMA      = '{"optimizations":[{"filename":"string","type":"performance|readability|security|tech_debt","original":"string","improved":"string","reason":"string"}],"rewritten_modules":[{"filename":"string","code":"string"}],"tech_debt_score":"number","summary":"string"}'
SECURITY_SCHEMA       = '{"findings":[{"filename":"string","rule":"string","severity":"critical|high|medium|low","owasp_ref":"string","line_hint":"string","fix":"string"}],"unlicensed_imports":["string"],"compliance_tag_coverage":{"files_with_tags":"number","files_without_tags":["string"],"coverage_percent":"number"},"overall_security_risk":"critical|high|medium|low","passed":"boolean","summary":"string"}'
QUALITY_SCHEMA        = '{"test_results":[{"filename":"string","test_name":"string","status":"pass|fail|warning","detail":"string"}],"acceptance_criteria_check":[{"criterion":"string","status":"met|not_met|partial","evidence":"string"}],"code_quality":{"has_docstrings":"boolean","has_type_hints":"boolean","has_error_handling":"boolean","has_async_support":"boolean","missing_docstrings_in":["string"],"missing_error_handling_in":["string"]},"security_integration":{"security_findings_addressed":"boolean","critical_blockers":["string"],"ready_for_deploy":"boolean"},"overall_quality_score":"number","passed":"boolean","recommendations":["string"],"summary":"string"}'
EXPLAINABILITY_SCHEMA = '{"decision_log":[{"decision_point":"string","what_was_decided":"string","why":"string","alternatives_considered":["string"],"trade_offs_accepted":["string"],"constraint_satisfied":["string"]}],"module_explanations":[{"filename":"string","purpose":"string","key_decisions":["string"],"compliance_mapping":["string"]}],"glossary":[{"term":"string","plain_english":"string"}],"audit_narrative":"string"}'