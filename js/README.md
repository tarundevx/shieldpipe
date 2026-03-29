# ShieldPipe Node.js SDK

Privacy middleware for LLM & AI pipelines — PII detection, pseudonymization, and rehydration.

## Installation

```bash
npm install shieldpipe
```

## Quick Start

```typescript
import { createShield } from 'shieldpipe';

const shield = createShield();
const result = shield.shield("Send the report to alice@acme.com");
console.log(result.text); // "Send the report to EMAIL_1"

// Rehydrate LLM response
const llmResponse = "I've sent the report to EMAIL_1.";
console.log(result.rehydrate(llmResponse)); // "I've sent the report to alice@acme.com."
```

## License

MIT
