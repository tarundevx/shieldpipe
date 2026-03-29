from __future__ import annotations
import re
import json
import hashlib
import os
import time
import uuid
import struct
from dataclasses import dataclass, field
from typing import Optional, Callable, Any
from pathlib import Path

# ─── Entity Types ────────────────────────────────────────────────────────────

ENTITY_TYPES = [
    "EMAIL", "PHONE", "IP_ADDRESS", "URL_INTERNAL",
    "API_KEY", "JWT", "CREDIT_CARD", "SSN",
    "AMOUNT", "DATE", "CUSTOM",
]

PATTERNS: dict[str, re.Pattern] = {
    "EMAIL": re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
    "PHONE": re.compile(r'(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b'),
    "IP_ADDRESS": re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
    "URL_INTERNAL": re.compile(
        r'https?://(?:localhost|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|'
        r'192\.168\.\d+\.\d+|(?:[a-z0-9\-]+\.)?(?:internal|local|intranet|corp|private))[^\s]*',
        re.IGNORECASE
    ),
    "API_KEY": re.compile(
        r'\b(?:sk-[a-zA-Z0-9]{20,}|[a-zA-Z0-9]{32,}(?:key|token|secret|api)[a-zA-Z0-9]*|'
        r'(?:key|token|secret|api)[a-zA-Z0-9]*[=:]\s*[a-zA-Z0-9_\-]{16,})\b',
        re.IGNORECASE
    ),
    "JWT": re.compile(r'\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b'),
    "CREDIT_CARD": re.compile(
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|'
        r'3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b'
    ),
    "SSN": re.compile(r'\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'),
    "AMOUNT": re.compile(
        r'(?:(?:USD|EUR|GBP|INR|Rs\.?|₹|\$|€|£)\s*\d+(?:[.,]\d{3})*(?:\.\d{2,3})?\s*(?:USD|EUR|GBP|INR|million|billion|M|B|K|L|Cr|lakh|crore)?'
        r'|\b\d+(?:[.,]\d{3})*(?:\.\d{2})?\s*(?:USD|EUR|GBP|INR|million|billion|lakh|crore)\b'
        r'|\b\d+(?:\.\d+)?\s*(?:M|B|K)(?:\b))',
        re.IGNORECASE
    ),
    "DATE": re.compile(
        r'\b(?:\d{1,2}[\/\-\.]\d{1,2}[\/\-\.]\d{2,4}|\d{4}[\/\-\.]\d{2}[\/\-\.]\d{2}|'
        r'(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.?\s+\d{1,2},?\s+\d{4}|'
        r'Q[1-4]\s+\d{4})\b',
        re.IGNORECASE
    ),
}

CONFIG_KEY_MAP = {
    "EMAIL": "emails", "PHONE": "phones", "IP_ADDRESS": "ip_addresses",
    "URL_INTERNAL": "internal_urls", "API_KEY": "api_keys", "JWT": "jwts",
    "CREDIT_CARD": "credit_cards", "SSN": "ssns", "AMOUNT": "amounts", "DATE": "dates",
}


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class DetectedEntity:
    type: str
    value: str
    token: str
    start: int
    end: int


@dataclass
class DetectionConfig:
    emails: bool = True
    phones: bool = True
    ip_addresses: bool = True
    internal_urls: bool = True
    api_keys: bool = True
    jwts: bool = True
    credit_cards: bool = True
    ssns: bool = False
    amounts: bool = True
    dates: bool = False
    custom_patterns: list[dict] = field(default_factory=list)
    preserve: list[str] = field(default_factory=list)
    force: list[str] = field(default_factory=list)


@dataclass
class ShieldedResult:
    text: str
    entities: list[DetectedEntity]
    request_id: str
    _detector: "PIIDetector"

    def rehydrate(self, response: str) -> str:
        return self._detector.rehydrate(response)


# ─── Core Detector ────────────────────────────────────────────────────────────

class PIIDetector:
    def __init__(self, config: Optional[DetectionConfig] = None):
        self.config = config or DetectionConfig()
        self._counters: dict[str, int] = {}
        self._vault: dict[str, str] = {}        # value -> token
        self._reverse_vault: dict[str, str] = {} # token -> value

    def detect(self, text: str) -> list[DetectedEntity]:
        entities: list[DetectedEntity] = []
        seen: set[str] = set()
        preserve_set = set(self.config.preserve)

        for type_key, pattern in PATTERNS.items():
            config_key = CONFIG_KEY_MAP.get(type_key)
            if config_key and not getattr(self.config, config_key, True):
                continue

            for match in pattern.finditer(text):
                value = match.group(0)
                key = f"{match.start()}-{value}"
                if value in preserve_set or key in seen:
                    continue
                seen.add(key)

                token = self._get_or_create_token(type_key, value)
                entities.append(DetectedEntity(
                    type=type_key,
                    value=value,
                    token=token,
                    start=match.start(),
                    end=match.end(),
                ))

        # Custom patterns
        for custom in self.config.custom_patterns:
            pattern = re.compile(custom["regex"], re.IGNORECASE)
            category = custom.get("category", "CUSTOM")
            for match in pattern.finditer(text):
                value = match.group(0)
                key = f"{match.start()}-{value}"
                if key in seen:
                    continue
                seen.add(key)
                token = self._get_or_create_token("CUSTOM", value, category)
                entities.append(DetectedEntity(
                    type="CUSTOM", value=value, token=token,
                    start=match.start(), end=match.end(),
                ))

        # Forced values
        for forced in self.config.force:
            idx = text.find(forced)
            if idx != -1:
                key = f"{idx}-{forced}"
                if key not in seen:
                    seen.add(key)
                    token = self._get_or_create_token("CUSTOM", forced, "FORCED")
                    entities.append(DetectedEntity(
                        type="CUSTOM", value=forced, token=token,
                        start=idx, end=idx + len(forced),
                    ))

        return sorted(entities, key=lambda e: e.start)

    def pseudonymize(self, text: str) -> tuple[str, list[DetectedEntity]]:
        all_entities = self.detect(text)

        # Remove overlapping entities (keep the first/longer one)
        used: list[DetectedEntity] = []
        for entity in all_entities:
            if not any(e.start < entity.end and entity.start < e.end for e in used):
                used.append(entity)

        result = list(text)
        offset = 0
        for entity in sorted(used, key=lambda e: e.start):
            start = entity.start + offset
            end = entity.end + offset
            result[start:end] = list(entity.token)
            offset += len(entity.token) - len(entity.value)

        return "".join(result), used

    def rehydrate(self, text: str) -> str:
        for token, value in self._reverse_vault.items():
            text = text.replace(token, value)
        return text

    def rehydrate_chunk(self, chunk: str, buffer: str) -> tuple[str, str]:
        combined = buffer + chunk
        partial = re.search(r'[A-Z_]+_\d*$', combined)
        new_buffer = partial.group(0) if partial else ""
        to_process = combined[:-len(new_buffer)] if new_buffer else combined
        return self.rehydrate(to_process), new_buffer

    def _get_or_create_token(self, type_key: str, value: str, category: Optional[str] = None) -> str:
        if value in self._vault:
            return self._vault[value]

        label = category or type_key
        count = self._counters.get(label, 0) + 1
        self._counters[label] = count

        token = f"{label}_{count}"
        self._vault[value] = token
        self._reverse_vault[token] = value
        return token

    def export_vault(self) -> dict[str, str]:
        return dict(self._vault)

    def import_vault(self, data: dict[str, str]) -> None:
        for value, token in data.items():
            self._vault[value] = token
            self._reverse_vault[token] = value
            parts = token.rsplit("_", 1)
            if len(parts) == 2 and parts[1].isdigit():
                label = parts[0]
                num = int(parts[1])
                self._counters[label] = max(self._counters.get(label, 0), num)

    @property
    def vault_size(self) -> int:
        return len(self._vault)


# ─── Encrypted Vault ──────────────────────────────────────────────────────────

class EncryptedVault:
    """AES-256-GCM encrypted vault for persistent pseudonym mappings."""

    VERSION = 1

    def __init__(self, vault_path: str, key_material: str):
        self.vault_path = Path(vault_path)
        self._key = hashlib.sha256(key_material.encode()).digest()

    def save(self, mappings: dict[str, str]) -> None:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise ImportError("cryptography package required for vault: pip install cryptography")

        data = json.dumps({
            "version": self.VERSION,
            "mappings": mappings,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }).encode()

        iv = os.urandom(12)
        aesgcm = AESGCM(self._key)
        ciphertext = aesgcm.encrypt(iv, data, None)

        version_bytes = struct.pack(">I", self.VERSION)
        self.vault_path.write_bytes(version_bytes + iv + ciphertext)

    def load(self) -> Optional[dict]:
        if not self.vault_path.exists():
            return None

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise ImportError("cryptography package required for vault: pip install cryptography")

        raw = self.vault_path.read_bytes()
        version = struct.unpack(">I", raw[:4])[0]
        if version != self.VERSION:
            raise ValueError(f"Unknown vault version: {version}")

        iv = raw[4:16]
        ciphertext = raw[16:]

        aesgcm = AESGCM(self._key)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        return json.loads(plaintext)

    def load_mappings(self) -> dict[str, str]:
        data = self.load()
        return data.get("mappings", {}) if data else {}

    @staticmethod
    def generate_key() -> str:
        return os.urandom(32).hex()


# ─── ShieldPipe High-Level API ────────────────────────────────────────────────

class ShieldPipe:
    """
    Main ShieldPipe class. Wraps PIIDetector with vault persistence and audit logging.
    """

    def __init__(
        self,
        detection: Optional[DetectionConfig] = None,
        vault_path: Optional[str] = None,
        vault_key: Optional[str] = None,
        audit_dir: Optional[str] = None,
        on_redact: Optional[Callable[[list[DetectedEntity], str], None]] = None,
    ):
        self.on_redact = on_redact
        self._audit_dir = audit_dir

        # Set up vault
        key = vault_key or os.environ.get("SHIELDPIPE_VAULT_KEY")
        if vault_path and key:
            self._vault: Optional[EncryptedVault] = EncryptedVault(vault_path, key)
        else:
            self._vault = None

        # Set up detector
        self._detector = PIIDetector(detection)
        if self._vault:
            self._detector.import_vault(self._vault.load_mappings())

        # Audit
        if audit_dir:
            Path(audit_dir).mkdir(parents=True, exist_ok=True)

    def shield(self, text: str) -> ShieldedResult:
        request_id = f"req_{int(time.time()*1000)}_{uuid.uuid4().hex[:6]}"
        start = time.time()

        result_text, entities = self._detector.pseudonymize(text)

        if self._vault and entities:
            self._vault.save(self._detector.export_vault())

        if entities and self.on_redact:
            self.on_redact(entities, request_id)

        if self._audit_dir and entities:
            self._write_audit(request_id, entities, time.time() - start)

        return ShieldedResult(
            text=result_text,
            entities=entities,
            request_id=request_id,
            _detector=self._detector,
        )

    def wrap_openai(self, client: Any) -> Any:
        return _WrappedOpenAIClient(client, self)

    def _write_audit(self, request_id: str, entities: list[DetectedEntity], latency: float) -> None:
        from datetime import date
        today = date.today().isoformat()
        log_file = Path(self._audit_dir) / f"audit-{today}.jsonl"

        type_counts: dict[str, int] = {}
        for e in entities:
            type_counts[e.type] = type_counts.get(e.type, 0) + 1

        entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "request_id": request_id,
            "direction": "inbound",
            "entity_count": len(entities),
            "entity_types": type_counts,
            "latency_ms": round(latency * 1000, 2),
        }

        with open(log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    @property
    def detector(self) -> PIIDetector:
        return self._detector


class _WrappedOpenAIClient:
    def __init__(self, client: Any, shield: ShieldPipe):
        self._client = client
        self._shield = shield

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._client, name)
        if name == "chat":
            return _WrappedChat(attr, self._shield)
        if name == "embeddings":
            return _WrappedEmbeddings(attr, self._shield)
        return attr


class _WrappedChat:
    def __init__(self, chat: Any, shield: ShieldPipe):
        self._chat = chat
        self._shield = shield

    @property
    def completions(self) -> "_WrappedCompletions":
        return _WrappedCompletions(self._chat.completions, self._shield)


class _WrappedCompletions:
    def __init__(self, completions: Any, shield: ShieldPipe):
        self._completions = completions
        self._shield = shield

    def create(self, **kwargs: Any) -> Any:
        shielded_result = None

        if "messages" in kwargs:
            new_messages = []
            for msg in kwargs["messages"]:
                if isinstance(msg.get("content"), str):
                    result = self._shield.shield(msg["content"])
                    shielded_result = result
                    new_messages.append({**msg, "content": result.text})
                else:
                    new_messages.append(msg)
            kwargs["messages"] = new_messages

        response = self._completions.create(**kwargs)

        if shielded_result:
            for choice in response.choices:
                if hasattr(choice.message, "content") and choice.message.content:
                    choice.message.content = shielded_result.rehydrate(choice.message.content)

        return response


class _WrappedEmbeddings:
    def __init__(self, embeddings: Any, shield: ShieldPipe):
        self._embeddings = embeddings
        self._shield = shield

    def create(self, **kwargs: Any) -> Any:
        if "input" in kwargs and isinstance(kwargs["input"], str):
            result = self._shield.shield(kwargs["input"])
            kwargs["input"] = result.text
        return self._embeddings.create(**kwargs)
