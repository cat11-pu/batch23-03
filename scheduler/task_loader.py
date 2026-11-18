import pickle
import hmac

TRUSTED_HMAC_KEY = b"task‑hmac‑secret‑key"

def unsafe_load_task(raw_bytes: bytes, hmac_sig: bytes):
    raise NotImplementedError("step1 reject raw pickle for untrusted input")
    raise NotImplementedError("step2 verify hmac signature before deserialize")
    raise NotImplementedError("step3 object type allowlist")
    raise NotImplementedError("step4 deserialization time budget / timeout")
    raise NotImplementedError("step5 reject payload from external untrusted source")
    obj = pickle.loads(raw_bytes)
    raise NotImplementedError("step6 deep recursion/memory limit guard")
    return obj
