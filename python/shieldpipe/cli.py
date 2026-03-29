#!/usr/bin/env python3
"""
ShieldPipe CLI (Python)
Test PII detection and run the proxy server
"""

import argparse
import sys
import os
import json
import time
from pathlib import Path

BANNER = r"""
 ____  _     _      _     _ ____  _
/ ___|| |__ (_) ___| | __| |  _ \(_)_ __   ___
\___ \| '_ \| |/ _ \ |/ _` | |_) | | '_ \ / _ \
 ___) | | | | |  __/ | (_| |  __/| | |_) |  __/
|____/|_| |_|_|\___|_|\__,_|_|   |_| .__/ \___|
                                    |_|
v0.1.0 — PII Guard for LLM APIs
"""

SAMPLE_TEXT = """
Hey Bob, please send the Q3 financial report to alice@acme-corp.com.
Budget is $2.4M. Call me at +1 (555) 867-5309 if you have questions.
Internal dashboard: http://192.168.1.42/dashboard
Use API key: sk-abc123xyz789def456ghi012jkl345mno678pqr
""".strip()


def cmd_test(args):
    from shieldpipe import PIIDetector

    text = args.text or SAMPLE_TEXT

    print("\n📋 Input text:")
    print("─" * 60)
    print(text)
    print("─" * 60)

    detector = PIIDetector()
    result, entities = detector.pseudonymize(text)

    print(f"\n🔍 Detected {len(entities)} entities:\n")
    for e in entities:
        padding = " " * max(0, 14 - len(e.type))
        print(f'  {e.type}{padding} "{e.value}"  →  {e.token}')

    print("\n🛡️  Pseudonymized:")
    print("─" * 60)
    print(result)
    print("─" * 60)

    rehydrated = detector.rehydrate(result)
    match = rehydrated == text
    print(f"\n♻️  Rehydrated: {'✅ Roundtrip OK' if match else '❌ Mismatch!'}\n")


def cmd_start(args):
    try:
        from http.server import HTTPServer, BaseHTTPRequestHandler
        import urllib.request
    except ImportError:
        print("Standard library required")
        sys.exit(1)

    from shieldpipe import PIIDetector, EncryptedVault

    config_path = args.config or "shieldpipe.json"
    config = {
        "listen": "127.0.0.1",
        "port": 8910,
        "upstream": "https://api.openai.com",
        "api_key_env": "OPENAI_API_KEY",
        "vault_path": "./shieldpipe-vault.enc",
        "vault_key_env": "SHIELDPIPE_VAULT_KEY",
    }

    if Path(config_path).exists():
        with open(config_path) as f:
            config.update(json.load(f))

    vault_key = os.environ.get(config["vault_key_env"])
    if vault_key:
        vault = EncryptedVault(config["vault_path"], vault_key)
        print(f"🔐 Vault: {config['vault_path']} (AES-256-GCM)")
    else:
        vault = None
        print("⚠️  No SHIELDPIPE_VAULT_KEY — using in-memory only")

    detector = PIIDetector()
    if vault:
        detector.import_vault(vault.load_mappings())

    upstream = config["upstream"].rstrip("/")
    api_key = os.environ.get(config["api_key_env"], "")

    class ProxyHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # suppress default logging

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()

            try:
                parsed = json.loads(body)
                if "messages" in parsed:
                    for msg in parsed["messages"]:
                        if isinstance(msg.get("content"), str):
                            result, entities = detector.pseudonymize(msg["content"])
                            msg["content"] = result
                            if entities:
                                types = set(e.type for e in entities)
                                print(f"[{time.strftime('%H:%M:%S')}] Redacted {len(entities)} entities: {', '.join(types)}")
                    body = json.dumps(parsed)
            except json.JSONDecodeError:
                pass

            if vault:
                vault.save(detector.export_vault())

            target_url = f"{upstream}{self.path}"
            req = urllib.request.Request(
                target_url,
                data=body.encode(),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {api_key}",
                },
                method="POST",
            )

            try:
                with urllib.request.urlopen(req) as resp:
                    response_body = resp.read().decode()
                    rehydrated = detector.rehydrate(response_body)
                    self.send_response(resp.status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("X-ShieldPipe-Version", "0.1.0")
                    self.end_headers()
                    self.wfile.write(rehydrated.encode())
            except Exception as e:
                self.send_response(502)
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())

        def do_GET(self):
            if self.path == "/health":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "status": "ok",
                    "vault_size": detector.vault_size,
                    "version": "0.1.0"
                }).encode())

    host = config["listen"]
    port = config["port"]

    print(BANNER)
    print(f"✅ ShieldPipe proxy listening on http://{host}:{port}")
    print(f"   Upstream: {upstream}")
    print(f"\nPoint your app at: http://{host}:{port}/v1\n")

    HTTPServer((host, port), ProxyHandler).serve_forever()


def cmd_init(args):
    config = {
        "listen": "127.0.0.1",
        "port": 8910,
        "upstream": "https://api.openai.com",
        "api_key_env": "OPENAI_API_KEY",
        "vault_path": "./shieldpipe-vault.enc",
        "vault_key_env": "SHIELDPIPE_VAULT_KEY",
        "detection": {
            "emails": True, "phones": True, "ip_addresses": True,
            "internal_urls": True, "api_keys": True, "jwts": True,
            "credit_cards": True, "ssns": False, "amounts": True, "dates": False,
        },
    }
    Path("shieldpipe.json").write_text(json.dumps(config, indent=2))
    print("✅ Created shieldpipe.json")
    print("\nNext steps:")
    print("  export OPENAI_API_KEY=sk-...")
    print("  export SHIELDPIPE_VAULT_KEY=$(python3 -c \"import os,binascii; print(binascii.hexlify(os.urandom(32)).decode())\")")
    print("  shieldpipe start\n")


def main():
    parser = argparse.ArgumentParser(prog="shieldpipe", description="ShieldPipe PII Guard for LLM APIs")
    subparsers = parser.add_subparsers()

    p_test = subparsers.add_parser("test", help="Test PII detection")
    p_test.add_argument("--text", help="Custom text to test")
    p_test.set_defaults(func=cmd_test)

    p_start = subparsers.add_parser("start", help="Start proxy server")
    p_start.add_argument("--config", help="Path to shieldpipe.json")
    p_start.set_defaults(func=cmd_start)

    p_init = subparsers.add_parser("init", help="Create default config file")
    p_init.set_defaults(func=cmd_init)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        print(BANNER)
        parser.print_help()


if __name__ == "__main__":
    main()
