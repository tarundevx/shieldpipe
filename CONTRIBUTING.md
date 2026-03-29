# Contributing to ShieldPipe

Thank you for your interest in contributing! ShieldPipe is a community-driven project and all contributions are welcome.

## Ways to Contribute

- 🐛 **Bug reports** — Open an issue with a minimal reproduction
- ✨ **New detection patterns** — Improve PII coverage
- 🌍 **Internationalization** — Phone/ID patterns for non-US regions
- 📖 **Documentation** — Improve examples, add guides
- 🧪 **Tests** — Increase coverage, add edge cases
- 🔌 **Integrations** — LangChain, LlamaIndex, Vercel AI SDK adapters

## Project Structure

```
shieldpipe/
├── js/                 # Node.js SDK (TypeScript)
│   ├── src/            # Source code
│   └── README.md       # JS-specific docs
├── python/             # Python SDK (Python)
│   ├── shieldpipe/     # Source code
│   ├── tests/          # Python tests
│   └── README.md       # Python-specific docs
├── LICENSE             # MIT License
└── README.md           # Global project docs
```

## Development Setup

### Node.js (JS SDK)

```bash
cd js
npm install
npm run build
```

### Python (Python SDK)

```bash
cd python
pip install -e .
pip install pytest
pytest tests/
```

## Adding a New Detection Pattern

1. **JS**: Open `js/src/detector.ts` and update `PATTERNS`, `CONFIG_KEY_MAP`, and `DetectionConfig`.
2. **Python**: Open `python/shieldpipe/detector.py` and update `PATTERNS`, `CONFIG_KEY_MAP`, and `DetectionConfig`.
3. **Tests**: Add test cases in `python/tests/test_detector.py` (JS tests coming soon).

## Submitting a PR

1. Fork the repo and create a feature branch: `git checkout -b feat/my-feature`
2. Make your changes and add tests
3. Commit with a conventional commit message: `feat: add IBAN detection pattern`
4. Open a PR against `main`

## Code Style

- TypeScript: strict mode, avoid `any` in public APIs
- Python: type hints required, Python 3.8+ compatible

## Reporting Security Issues

Please **do not** open public issues for security vulnerabilities. Report them privately via GitHub Security Advisories or by contacting the maintainers.
