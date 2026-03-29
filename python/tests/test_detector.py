"""Tests for ShieldPipe Python SDK"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shieldpipe import PIIDetector, ShieldPipe, DetectionConfig


class TestPIIDetector:
    def test_email_detection(self):
        d = PIIDetector()
        _, entities = d.pseudonymize("Contact alice@acme.com for details")
        assert any(e.type == "EMAIL" for e in entities)

    def test_phone_detection(self):
        d = PIIDetector()
        _, entities = d.pseudonymize("Call +1 (555) 867-5309 now")
        assert any(e.type == "PHONE" for e in entities)

    def test_ip_detection(self):
        d = PIIDetector()
        _, entities = d.pseudonymize("Server at 192.168.1.42")
        assert any(e.type == "IP_ADDRESS" for e in entities)

    def test_api_key_detection(self):
        d = PIIDetector()
        _, entities = d.pseudonymize("Use sk-abc123xyz789def456ghi012jkl345mno678pqr")
        assert any(e.type == "API_KEY" for e in entities)

    def test_amount_detection(self):
        d = PIIDetector()
        _, entities = d.pseudonymize("Budget is $2.4M for Q3")
        assert any(e.type == "AMOUNT" for e in entities)

    def test_consistent_pseudonymization(self):
        d = PIIDetector()
        text = "alice@acme.com and alice@acme.com again"
        result, entities = d.pseudonymize(text)
        # Both occurrences should map to the same token
        tokens = [e.token for e in entities if e.type == "EMAIL"]
        assert len(set(tokens)) == 1  # both same token

    def test_roundtrip(self):
        d = PIIDetector()
        original = "Send $5M report to bob@company.com from 10.0.0.1"
        pseudonymized, _ = d.pseudonymize(original)
        assert pseudonymized != original
        rehydrated = d.rehydrate(pseudonymized)
        assert rehydrated == original

    def test_preserve_list(self):
        config = DetectionConfig(preserve=["OpenAI"])
        d = PIIDetector(config)
        result, entities = d.pseudonymize("Using OpenAI and alice@x.com")
        assert "OpenAI" in result
        assert not any(e.value == "OpenAI" for e in entities)

    def test_custom_patterns(self):
        config = DetectionConfig(
            custom_patterns=[{"name": "codename", "regex": r"Project\s+(Alpha|Beta)", "category": "PROJECT"}]
        )
        d = PIIDetector(config)
        _, entities = d.pseudonymize("Working on Project Alpha this quarter")
        assert any(e.type == "CUSTOM" for e in entities)

    def test_disabled_detection(self):
        config = DetectionConfig(emails=False)
        d = PIIDetector(config)
        _, entities = d.pseudonymize("Email: alice@acme.com")
        assert not any(e.type == "EMAIL" for e in entities)

    def test_vault_export_import(self):
        d1 = PIIDetector()
        _, _ = d1.pseudonymize("alice@acme.com")
        vault = d1.export_vault()

        d2 = PIIDetector()
        d2.import_vault(vault)
        result2, _ = d2.pseudonymize("alice@acme.com")
        result1, _ = d1.pseudonymize("alice@acme.com")
        assert result1 == result2  # same token


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
