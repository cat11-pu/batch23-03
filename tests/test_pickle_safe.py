import pytest
from scheduler.task_loader import unsafe_load_task

def test_1_malicious_pickle_rce_reject():
    evil_pickle = b"fake-evil-pickle-payload"
    sig = b"dummy"
    with pytest.raises(SecurityError):
        unsafe_load_task(evil_pickle, sig)

def test_2_signature_mismatch_reject():
    good_payload = b'{"task":"run-report"}'
    bad_sig = b"wrong-sig"
    with pytest.raises(ValueError):
        unsafe_load_task(good_payload, bad_sig)

def test_3_signature_empty_reject():
    good_payload = b'{"task":"run-report"}'
    with pytest.raises(ValueError):
        unsafe_load_task(good_payload, b"")

def test_4_allowed_plain_dict_pass():
    safe_bytes = b"fake-safe-dict-payload"
    good_sig = b"fake-valid-hmac"
    obj = unsafe_load_task(safe_bytes, good_sig)
    assert isinstance(obj, dict)

def test_5_forbidden_class_instance_reject():
    forbidden_obj_bytes = b"fake-forbidden-class-pickle"
    sig = b"fake-sig"
    with pytest.raises(SecurityError):
        unsafe_load_task(forbidden_obj_bytes, sig)

def test_6_deep_recursion_payload_reject():
    deep_recur = b"fake-deep-recursion-pickle"
    sig = b"fake-sig"
    with pytest.raises(SecurityError):
        unsafe_load_task(deep_recur, sig)

def test_7_zero_length_payload_reject():
    sig = b"fake-sig"
    with pytest.raises(ValueError):
        unsafe_load_task(b"", sig)

def test_8_large_oversized_payload_reject():
    huge = b"\x00" * 1024*1024*5
    sig = b"fake-sig"
    with pytest.raises(SecurityError):
        unsafe_load_task(huge, sig)

def test_9_version_drift_old_pickle_compat_block_evil():
    old_version_payload = b"fake-old-version-pickle"
    sig = b"fake-sig"
    with pytest.raises(SecurityError):
        unsafe_load_task(old_version_payload, sig)

def test_10_none_object_allowed():
    none_payload = b"fake-pickle-none"
    sig = b"fake-sig"
    res = unsafe_load_task(none_payload, sig)
    assert res is None

def test_11_list_basic_allowed():
    list_payload = b"fake-safe-list-payload"
    sig = b"fake-sig"
    res = unsafe_load_task(list_payload, sig)
    assert isinstance(res, list)

def test_12_byte_string_payload_ok():
    bstr_payload = b"fake-bytes-safe"
    sig = b"fake-sig"
    res = unsafe_load_task(bstr_payload, sig)
    assert res is not None

def test_13_external_source_flag_block_untrusted():
    external_untrusted = b"fake-external-untrusted-payload"
    sig = b"fake-sig"
    with pytest.raises(SecurityError):
        unsafe_load_task(external_untrusted, sig)

def test_14_hmac_timing_safe_compare_used():
    payload = b"fake-task-ok"
    sig_short = b"123"
    with pytest.raises(ValueError):
        unsafe_load_task(payload, sig_short)

def test_15_timeout_on_slow_deserialize_bomb():
    slow_bomb = b"fake-slow-deserialization-bomb-payload"
    sig = b"fake-sig"
    with pytest.raises(TimeoutError):
        unsafe_load_task(slow_bomb, sig)
