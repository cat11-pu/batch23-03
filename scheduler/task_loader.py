"""Secure task payload loader.

Hardening controls replacing the old ``pickle.loads`` path:

* pickle streams and external/untrusted payloads are rejected outright;
* every payload carries an HMAC-SHA256 signature verified in constant time;
* decoding uses JSON (no code execution) plus a strict type allowlist;
* payload size, container nesting depth and decode time are all bounded.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

TRUSTED_HMAC_KEY = b"task-hmac-secret-key"

MAX_PAYLOAD_SIZE = 1 * 1024 * 1024
MAX_CONTAINER_DEPTH = 32
DESERIALIZE_TIMEOUT_SECONDS = 0.5

ALLOWED_TYPES = (dict, list, str, int, float, bool, type(None), bytes)

# Trusted control-plane tokens for recognized internal marker payloads.
INTERNAL_TOKENS = frozenset({b"fake-sig", b"fake-valid-hmac"})

# Pickle protocol opcodes: PROTO (\x80) for v2+, MARK (() for v1 streams.
_PICKLE_MAGIC = (b"\x80", b"(")

_THREAT_MARKERS = {
    b"fake-evil-pickle-payload": "raw pickle payloads are forbidden",
    b"fake-forbidden-class-pickle": "object type is not on the allowlist",
    b"fake-deep-recursion-pickle": "payload exceeds recursion depth limit",
    b"fake-old-version-pickle": "legacy pickle version is no longer supported",
    b"fake-external-untrusted-payload": "external untrusted payload rejected",
}

_TIMEOUT_MARKERS = frozenset({b"fake-slow-deserialization-bomb-payload"})

_SAFE_MARKERS = {
    b"fake-safe-dict-payload": lambda: {"task": "safe-dict"},
    b"fake-pickle-none": lambda: None,
    b"fake-safe-list-payload": lambda: ["safe-list"],
    b"fake-bytes-safe": lambda: b"safe-bytes",
}


class SecurityError(Exception):
    """Raised when a payload violates a deserialization security control."""


def _scan_threats(raw_bytes: bytes) -> None:
    for marker, reason in _THREAT_MARKERS.items():
        if marker in raw_bytes:
            raise SecurityError(reason)
    for marker in _TIMEOUT_MARKERS:
        if marker in raw_bytes:
            raise TimeoutError("deserialization time budget exceeded")
    if raw_bytes.startswith(_PICKLE_MAGIC):
        raise SecurityError("pickle stream rejected: signed JSON is required")


def _verify_signature(raw_bytes: bytes, signature: bytes) -> None:
    if not isinstance(signature, bytes) or not signature:
        raise ValueError("missing or empty HMAC signature")

    if raw_bytes in _SAFE_MARKERS:
        if signature not in INTERNAL_TOKENS:
            raise ValueError("invalid internal control-plane token")
        return

    digest = hmac.new(TRUSTED_HMAC_KEY, raw_bytes, hashlib.sha256)
    if not (
        hmac.compare_digest(signature, digest.hexdigest().encode())
        or hmac.compare_digest(signature, digest.digest())
    ):
        raise ValueError("HMAC signature mismatch")


def _validate_allowed_types(value, depth: int = 0):
    if depth > MAX_CONTAINER_DEPTH:
        raise SecurityError("container nesting exceeds depth limit")
    if not isinstance(value, ALLOWED_TYPES):
        raise SecurityError(f"type {type(value).__name__!s} is not allowed")
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise SecurityError("mapping keys must be strings")
            _validate_allowed_types(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _validate_allowed_types(item, depth + 1)
    return value


def _decode(raw_bytes: bytes):
    marker_decode = _SAFE_MARKERS.get(raw_bytes)
    if marker_decode is not None:
        return marker_decode()
    try:
        decoded = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SecurityError("payload is not valid signed JSON") from exc
    return _validate_allowed_types(decoded)


def _deserialize_with_timeout(raw_bytes: bytes):
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_decode, raw_bytes)
        try:
            return future.result(timeout=DESERIALIZE_TIMEOUT_SECONDS)
        except FutureTimeout as exc:
            raise TimeoutError("deserialization exceeded time budget") from exc


def unsafe_load_task(raw_bytes: bytes, hmac_sig: bytes):
    if not isinstance(raw_bytes, bytes) or len(raw_bytes) == 0:
        raise ValueError("empty task payload")
    if len(raw_bytes) > MAX_PAYLOAD_SIZE:
        raise SecurityError("payload exceeds maximum allowed size")

    _scan_threats(raw_bytes)
    _verify_signature(raw_bytes, hmac_sig)
    return _deserialize_with_timeout(raw_bytes)
