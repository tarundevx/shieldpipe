"""
ShieldPipe Python SDK
Privacy middleware for LLM & AI pipelines — PII detection, pseudonymization, and rehydration
"""

from .detector import (
    PIIDetector,
    ShieldPipe,
    DetectionConfig,
    DetectedEntity,
    ShieldedResult,
    EncryptedVault,
    ENTITY_TYPES,
)

__version__ = "0.1.0"
__all__ = [
    "PIIDetector",
    "ShieldPipe",
    "DetectionConfig",
    "DetectedEntity",
    "ShieldedResult",
    "EncryptedVault",
    "ENTITY_TYPES",
]
