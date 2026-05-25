"""Tests for the HMAC verification ledger."""

from __future__ import annotations

import pytest

from adversa.verification import (
    compute_hmac,
    copy_ledger_to_case,
    derive_hmac_key,
    read_ledger,
    rehmac_entries,
    verify_items,
    write_ledger_entry,
)


@pytest.fixture(autouse=True)
def _patch_verification_dir(tmp_path, monkeypatch):
    monkeypatch.setattr("adversa.verification.VERIFICATION_DIR", tmp_path)


def test_derive_hmac_key_deterministic():
    key1 = derive_hmac_key("password1", b"salt")
    key2 = derive_hmac_key("password1", b"salt")
    assert key1 == key2
    assert len(key1) == 32

    key3 = derive_hmac_key("password2", b"salt")
    assert key3 != key1


def test_compute_hmac_deterministic():
    key = derive_hmac_key("test", b"salt")
    h1  = compute_hmac(key, "Mimikatz found at C:\\Windows\\Temp\\mm.exe")
    h2  = compute_hmac(key, "Mimikatz found at C:\\Windows\\Temp\\mm.exe")
    assert h1 == h2
    assert len(h1) == 64

    h3 = compute_hmac(key, "Different description")
    assert h3 != h1


def test_write_and_read_ledger(tmp_path):
    entry = {
        "finding_id":       "F-analyst-T1003.001",
        "hmac":             "deadbeef",
        "content_snapshot": "LSASS credential dump confirmed",
        "approved_by":      "analyst",
        "case_id":          "nfury",
    }
    write_ledger_entry("nfury", entry)
    entries = read_ledger("nfury")
    assert len(entries) == 1
    assert entries[0]["finding_id"] == "F-analyst-T1003.001"


def test_verify_items_correct_password(tmp_path):
    password, salt = "correct-password", b"mysalt"
    key  = derive_hmac_key(password, salt)
    desc = "PsExec service binary confirmed at C:\\Windows\\PSEXESVC.EXE"

    write_ledger_entry("nfury", {
        "finding_id":       "F-analyst-T1569.002",
        "hmac":             compute_hmac(key, desc),
        "content_snapshot": desc,
        "approved_by":      "analyst",
        "case_id":          "nfury",
    })

    results = verify_items("nfury", password, salt, "analyst")
    assert len(results) == 1
    assert results[0]["verified"] is True


def test_verify_items_wrong_password(tmp_path):
    key  = derive_hmac_key("correct", b"salt")
    desc = "LSASS dump confirmed"

    write_ledger_entry("nfury", {
        "finding_id":       "F-analyst-T1003.001",
        "hmac":             compute_hmac(key, desc),
        "content_snapshot": desc,
        "approved_by":      "analyst",
        "case_id":          "nfury",
    })

    results = verify_items("nfury", "wrong-password", b"salt", "analyst")
    assert results[0]["verified"] is False


def test_verify_items_tampered_description(tmp_path):
    key = derive_hmac_key("password", b"salt")

    write_ledger_entry("nfury", {
        "finding_id":       "F-analyst-T1003.001",
        "hmac":             compute_hmac(key, "original"),
        "content_snapshot": "tampered after signing",   # modified post-signature
        "approved_by":      "analyst",
        "case_id":          "nfury",
    })

    results = verify_items("nfury", "password", b"salt", "analyst")
    assert results[0]["verified"] is False


def test_copy_ledger_to_case(tmp_path):
    write_ledger_entry("nfury", {
        "finding_id": "F-analyst-T1055",
        "hmac":       "test",
        "content_snapshot": "process injection",
        "approved_by": "analyst",
        "case_id":    "nfury",
    })
    case_dir = tmp_path / "case"
    case_dir.mkdir()
    copy_ledger_to_case("nfury", case_dir)
    assert (case_dir / "verification.jsonl").exists()


def test_rehmac_entries(tmp_path):
    old_pw, old_salt = "old-password", b"oldsalt"
    new_pw, new_salt = "new-password", b"newsalt"
    old_key  = derive_hmac_key(old_pw, old_salt)
    desc     = "Confirmed credential dump"

    write_ledger_entry("nfury", {
        "finding_id":       "F-analyst-T1003.001",
        "hmac":             compute_hmac(old_key, desc),
        "content_snapshot": desc,
        "approved_by":      "analyst",
        "case_id":          "nfury",
    })

    count = rehmac_entries("nfury", "analyst", old_pw, old_salt, new_pw, new_salt)
    assert count == 1

    results_new = verify_items("nfury", new_pw, new_salt, "analyst")
    assert results_new[0]["verified"] is True

    results_old = verify_items("nfury", old_pw, old_salt, "analyst")
    assert results_old[0]["verified"] is False


def test_case_id_path_traversal():
    with pytest.raises(ValueError, match="path traversal"):
        write_ledger_entry("../evil", {"finding_id": "F-001"})

    with pytest.raises(ValueError, match="path traversal"):
        read_ledger("../../etc/passwd")

    with pytest.raises(ValueError, match="empty"):
        write_ledger_entry("", {"finding_id": "F-001"})
