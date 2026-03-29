# ShieldPipe Python SDK

Privacy middleware for LLM & AI pipelines — PII detection, pseudonymization, and rehydration.

## Installation

```bash
pip install shieldpipe
```

## Quick Start

```python
from shieldpipe import ShieldPipe

shield = ShieldPipe()
result = shield.shield("Send the report to alice@acme.com")
print(result.text)  # "Send the report to EMAIL_1"

# Rehydrate LLM response
llm_response = "I've sent the report to EMAIL_1."
print(result.rehydrate(llm_response))  # "I've sent the report to alice@acme.com."
```

## License

MIT
