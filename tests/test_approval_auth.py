"""Tests for approval authentication module."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from adversa.approval_auth import (
    _MAX_PASSWORD_ATTEMPTS,
    _MIN_PASSWORD_LENGTH,
    _check_lockout,
    _clear_failures,
    _load_password_entry,
    _recent_failure_count,
    _record_failure,
    _validate_examiner_name,
    get_analyst_salt,
    has_password,
    setup_password,
    verify_password,
)


@pytest.fixture
def config_path(tmp_path):
    return tmp_path / ".adversa" / "config.yaml"


@pytest.fixture
def passwords_dir(tmp_path, monkeypatch):
    d = tmp_path / "passwords"
    d.mkdir()
    monkeypatch.setattr("adversa.approval_auth._PASSWORDS_DIR", d)
    monkeypatch.setattr("adversa.approval_auth._LOCKOUT_FILE",
                        tmp_path / ".adversa" / ".password_lockout")
    return d


class TestPasswordSetup:
    def test_setup_writes_hash_and_salt(self, config_path, passwords_dir):
        with patch("adversa.approval_auth.getpass_prompt",
                   side_effect=["password1!", "password1!"]):
            setup_password(config_path, "analyst", passwords_dir=passwords_dir)

        pw_file = passwords_dir / "analyst.json"
        assert pw_file.exists()
        data = json.loads(pw_file.read_text())
        assert "hash" in data
        assert "salt" in data

    def test_mismatched_passwords_exits(self, config_path, passwords_dir):
        with patch("adversa.approval_auth.getpass_prompt",
                   side_effect=["password1!", "different!"]):
            with pytest.raises(SystemExit):
                setup_password(config_path, "analyst", passwords_dir=passwords_dir)

    def test_short_password_exits(self, config_path, passwords_dir):
        short = "x" * (_MIN_PASSWORD_LENGTH - 1)
        with patch("adversa.approval_auth.getpass_prompt",
                   side_effect=[short, short]):
            with pytest.raises(SystemExit):
                setup_password(config_path, "analyst", passwords_dir=passwords_dir)


class TestPasswordVerification:
    def test_correct_password_verifies(self, config_path, passwords_dir):
        pw = "correct-password!"
        with patch("adversa.approval_auth.getpass_prompt", side_effect=[pw, pw]):
            setup_password(config_path, "analyst", passwords_dir=passwords_dir)

        assert verify_password(config_path, "analyst", pw,
                               passwords_dir=passwords_dir) is True

    def test_wrong_password_fails(self, config_path, passwords_dir):
        with patch("adversa.approval_auth.getpass_prompt",
                   side_effect=["correct-password!", "correct-password!"]):
            setup_password(config_path, "analyst", passwords_dir=passwords_dir)

        assert verify_password(config_path, "analyst", "wrong-password!",
                               passwords_dir=passwords_dir) is False

    def test_has_password_true_after_setup(self, config_path, passwords_dir):
        with patch("adversa.approval_auth.getpass_prompt",
                   side_effect=["password1!", "password1!"]):
            setup_password(config_path, "analyst", passwords_dir=passwords_dir)

        assert has_password(config_path, "analyst",
                            passwords_dir=passwords_dir) is True

    def test_has_password_false_before_setup(self, config_path, passwords_dir):
        assert has_password(config_path, "unknown-analyst",
                            passwords_dir=passwords_dir) is False


class TestLockout:
    def test_lockout_after_max_failures(self, tmp_path, monkeypatch):
        lockout_file = tmp_path / ".password_lockout"
        monkeypatch.setattr("adversa.approval_auth._LOCKOUT_FILE", lockout_file)

        analyst = "lockout-test"
        for _ in range(_MAX_PASSWORD_ATTEMPTS):
            _record_failure(analyst)

        with pytest.raises(SystemExit):
            _check_lockout(analyst)

    def test_clear_failures_removes_lockout(self, tmp_path, monkeypatch):
        lockout_file = tmp_path / ".password_lockout"
        monkeypatch.setattr("adversa.approval_auth._LOCKOUT_FILE", lockout_file)

        analyst = "clear-test"
        for _ in range(_MAX_PASSWORD_ATTEMPTS):
            _record_failure(analyst)

        _clear_failures(analyst)
        assert _recent_failure_count(analyst) == 0


class TestExaminerValidation:
    def test_valid_examiner_names(self):
        for name in ("alice", "bob123", "analyst-1", "a0"):
            _validate_examiner_name(name)  # should not raise

    def test_invalid_examiner_names(self):
        for name in ("Alice", "bob/evil", "../etc", "", "a" * 25, "-start"):
            with pytest.raises(ValueError):
                _validate_examiner_name(name)


class TestSaltRetrieval:
    def test_get_salt_after_setup(self, config_path, passwords_dir):
        with patch("adversa.approval_auth.getpass_prompt",
                   side_effect=["password1!", "password1!"]):
            setup_password(config_path, "analyst", passwords_dir=passwords_dir)

        salt = get_analyst_salt(config_path, "analyst", passwords_dir=passwords_dir)
        assert isinstance(salt, bytes)
        assert len(salt) == 32

    def test_get_salt_missing_raises(self, config_path, passwords_dir):
        with pytest.raises(ValueError, match="No salt"):
            get_analyst_salt(config_path, "no-such-analyst",
                             passwords_dir=passwords_dir)
