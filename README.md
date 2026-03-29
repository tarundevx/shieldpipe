# ShieldPipe

**PII guard for LLM & AI pipelines — in JavaScript and Python**

[![CI](https://img.shields.io/github/actions/workflow/status/tarundevx/shieldpipe/ci.yml?style=flat-square)](https://github.com/tarundevx/shieldpipe/actions)
[![npm](https://img.shields.io/npm/v/shieldpipe?style=flat-square&label=npm)](https://www.npmjs.com/package/shieldpipe)
[![PyPI](https://img.shields.io/pypi/v/shieldpipe?style=flat-square&label=pypi)](https://pypi.org/project/shieldpipe/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](LICENSE)

```
Your App  ──▶  ShieldPipe  ──▶  OpenAI / Anthropic / Ollama
                   │                        │
           Detect & Replace           Process safely
           alice@acme.com → EMAIL_1         │
                   │                        │
           Rehydrate Response  ◀────────────┘
           EMAIL_1 → alice@acme.com
```

Every LLM call you make sends raw text to a third-party API. Names, emails, phone numbers, internal URLs, dollar amounts, API keys — all in plaintext. **ShieldPipe intercepts your prompts, replaces sensitive entities with consistent pseudonyms, forwards the sanitized request, then swaps the tokens back in the response.** Your LLM provider never sees real data.

---

## Features

- 🛡️ **Multi-layer detection** — emails, phones, IPs, API keys, JWTs, credit cards, amounts, custom regex
- 🔄 **Consistent pseudonymization** — `alice@acme.com` always maps to `EMAIL_1` across requests
- 🔐 **Encrypted vault** — AES-256-GCM at rest; mappings persist across sessions
- 📡 **SSE-aware rehydration** — handles tokens split across streaming chunks
- 📝 **Audit logging** — JSONL logs with entity metadata, never raw values
- ⚡ **Drop-in proxy** — one URL change protects your whole app
- 🧩 **SDK wrappers** — `shield.wrap_openai(client)` or Express middleware
- 📦 **No heavy deps** — pure Node.js / pure Python, zero ML models required

---

## Quickstart

### Python

```bash
pip install shieldpipe
```

```python
from shieldpipe import ShieldPipe

shield = ShieldPipe()

result = shield.shield(
    "Hi, please analyze the contract for alice@acme.com — budget is $2.4M"
)
print(result.text)
# → "Hi, please analyze the contract for EMAIL_1 — budget is AMOUNT_1"

# Call your LLM with result.text, then rehydrate:
llm_response = call_my_llm(result.text)
print(result.rehydrate(llm_response))
# → original values restored in the response
```

**Wrap the OpenAI client directly — zero code changes:**

```python
import openai
from shieldpipe import ShieldPipe

shield = ShieldPipe()
client = shield.wrap_openai(openai.OpenAI())

# Use exactly like normal — PII is auto-shielded and rehydrated
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Email alice@acme.com the Q3 numbers: $2.4M revenue"}]
)
print(response.choices[0].message.content)  # → real values in response, never sent to OpenAI
```

---

### Node.js / TypeScript

```bash
npm install shieldpipe
```

```typescript
import { createShield } from "shieldpipe";

const shield = createShield();

const { text, entities, rehydrate } = shield.shield(
  "Send the report to bob@company.com — deal is worth $5M"
);
console.log(text);
// → "Send the report to EMAIL_1 — deal is worth AMOUNT_1"

const llmResponse = await callMyLLM(text);
console.log(rehydrate(llmResponse)); // → real values back
```

**Wrap `fetch` for transparent protection:**

```typescript
import OpenAI from "openai";
import { createShield } from "shieldpipe";

const shield = createShield();
const protectedFetch = shield.wrapFetch();

const client = new OpenAI({ fetch: protectedFetch });
// All requests auto-shielded, all responses auto-rehydrated
```

**Express middleware:**

```typescript
import express from "express";
import { createShield } from "shieldpipe";

const app = express();
app.use(express.json());
app.use(createShield().expressMiddleware());
// All request bodies are now PII-free
```

---

### CLI Proxy (drop-in, no code changes)

```bash
npm install -g shieldpipe

# Or with Python:
pip install shieldpipe
```

```bash
# Initialize config
shieldpipe init

# Set your keys
export OPENAI_API_KEY=sk-...
export SHIELDPIPE_VAULT_KEY=$(openssl rand -hex 32)

# Start the proxy
shieldpipe start
# ✅ Listening on http://127.0.0.1:8910
```

Point **any** OpenAI-compatible client at `http://127.0.0.1:8910/v1` — nothing else changes:

```python
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:8910/v1")  # ← only change
```

```typescript
const client = new OpenAI({ baseURL: "http://127.0.0.1:8910/v1" });
```

Works with LangChain, LlamaIndex, Vercel AI SDK, Ollama, and any OpenAI-compatible client.

---

## Test Detection (no API key needed)

```bash
shieldpipe test
```

```
📋 Input text:
────────────────────────────────────────────────────────────
Hey Bob, please send the Q3 report to alice@acme-corp.com.
Budget is $2.4M. Call me at +1 (555) 867-5309.
Internal: http://192.168.1.42/dashboard
API key: sk-abc123xyz789def456ghi012jkl345mno678pqr
────────────────────────────────────────────────────────────

🔍 Detected 5 entities:

  EMAIL          "alice@acme-corp.com"       →  EMAIL_1
  AMOUNT         "$2.4M"                     →  AMOUNT_1
  PHONE          "+1 (555) 867-5309"         →  PHONE_1
  URL_INTERNAL   "http://192.168.1.42/..."   →  URL_INTERNAL_1
  API_KEY        "sk-abc123xyz..."            →  API_KEY_1

🛡️  Pseudonymized:
────────────────────────────────────────────────────────────
Hey Bob, please send the Q3 report to EMAIL_1.
Budget is AMOUNT_1. Call me at PHONE_1.
Internal: URL_INTERNAL_1
API key: API_KEY_1
────────────────────────────────────────────────────────────

♻️  Rehydrated: ✅ Roundtrip OK
```

---

## Detection Layers

| Layer | What it catches | Examples |
|---|---|---|
| **Emails** | All email addresses | `alice@acme.com` |
| **Phones** | US/intl phone numbers | `+1 (555) 867-5309` |
| **IP Addresses** | IPv4 addresses | `192.168.1.42` |
| **Internal URLs** | localhost, RFC-1918, `.internal` domains | `http://192.168.1.1/api` |
| **API Keys** | OpenAI, AWS, generic tokens | `sk-abc...`, `AKIA...` |
| **JWTs** | JSON Web Tokens | `eyJhbGciOi...` |
| **Credit Cards** | Visa, Mastercard, Amex, Discover | `4111111111111111` |
| **SSNs** | US Social Security Numbers | `123-45-6789` |
| **Amounts** | Multi-currency monetary values | `$2.4M`, `Rs 3.4L Cr`, `€50k` |
| **Dates** | Various date formats | `Q3 2025`, `Jan 15, 2025` |
| **Custom** | Your own regex patterns | Codenames, client IDs, etc. |

---

## Configuration

### Python

```python
from shieldpipe import ShieldPipe, DetectionConfig

shield = ShieldPipe(
    detection=DetectionConfig(
        emails=True,
        phones=True,
        ip_addresses=True,
        amounts=True,
        ssns=False,                       # off by default
        custom_patterns=[
            {"name": "project", "regex": r"Project\s+(Alpha|Beta)", "category": "PROJECT"},
        ],
        preserve=["OpenAI", "GPT-4"],     # never pseudonymize
        force=["ACME Corp"],              # always pseudonymize
    ),
    vault_path="./vault.enc",             # encrypted persistence
    vault_key=os.environ["SHIELD_KEY"],
    audit_dir="./audit-logs",
)
```

### Node.js

```typescript
const shield = createShield({
  detection: {
    emails: true,
    phones: true,
    amounts: true,
    customPatterns: [
      { name: "codename", regex: /Project\s+(Alpha|Beta)/g, category: "PROJECT" },
    ],
    preserve: ["OpenAI", "Claude"],
  },
  vault: { path: "./vault.enc", keyEnv: "SHIELD_KEY" },
  audit: { enabled: true, logDir: "./audit" },
  onRedact: (entities, requestId) => {
    console.log(`[${requestId}] Redacted: ${entities.map(e => e.type).join(", ")}`);
  },
});
```

### CLI (`shieldpipe.json`)

```json
{
  "listen": "127.0.0.1",
  "port": 8910,
  "upstream": "https://api.openai.com",
  "apiKeyEnv": "OPENAI_API_KEY",
  "vaultPath": "./vault.enc",
  "vaultKeyEnv": "SHIELDPIPE_VAULT_KEY",
  "detection": {
    "emails": true,
    "phones": true,
    "ipAddresses": true,
    "apiKeys": true,
    "amounts": true,
    "customPatterns": [
      { "name": "codename", "regex": "Project\\s+(Alpha|Beta)", "category": "PROJECT" }
    ],
    "preserve": ["OpenAI", "GPT-4o"],
    "force": ["ACME Corp"]
  },
  "auditDir": "./audit"
}
```

---

## How It Works

```
1. DETECT    Multi-layer regex engine scans the prompt for PII entities
2. REPLACE   Each unique value gets a consistent token (EMAIL_1, AMOUNT_3...)
             Same value always maps to the same token — preserves semantics
3. FORWARD   Sanitized prompt is sent to your LLM provider
4. REHYDRATE Tokens in the response are swapped back to real values
5. AUDIT     Request metadata logged (counts/types only — never raw values)
```

The vault ensures consistency across requests: `alice@acme.com` always maps to `EMAIL_1`, even across separate sessions. This preserves the semantic structure that embeddings and RAG pipelines rely on.

---

## Package Structure

| Package | Install | Description |
|---|---|---|
| `shieldpipe` | `npm install shieldpipe` | Node.js SDK (TypeScript) |
| `shieldpipe` | `pip install shieldpipe` | Python SDK + OpenAI wrapper + CLI |

---

## Roadmap

| Version | Feature | Status |
|---|---|---|
| v0.1 | Multi-layer detection, pseudonymization, encrypted vault, proxy, audit | ✅ Released |
| v0.2 | LangChain & LlamaIndex adapters | 🔜 Planned |
| v0.3 | Streaming (SSE) rehydration for real-time responses | 🔜 Planned |
| v0.4 | International patterns (IBAN, Aadhaar, NHS numbers, etc.) | 🔜 Planned |
| v0.5 | Named entity recognition (optional, transformer-based) | 🔜 Planned |
| v0.6 | Vercel AI SDK adapter | 🔜 Planned |

---

## Security

- **Vault encryption**: AES-256-GCM. Keys are never written to disk.
- **Audit logs**: Record entity counts and types only. Raw values are never logged.
- **No telemetry**: ShieldPipe sends zero data anywhere. Proxy connects only to your configured upstream.
- **Memory safety**: Python: keys zeroed after use. Node.js: keys kept in process memory, never serialized.

To report a security vulnerability, please use [GitHub Security Advisories](https://github.com/tarundevx/shieldpipe/security/advisories/new) — do not open a public issue.

---

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions.

Good first issues: adding detection patterns for new countries/regions, writing adapters for popular LLM frameworks, and improving test coverage.

---

## License

[MIT](LICENSE)
