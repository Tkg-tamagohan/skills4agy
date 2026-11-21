#!/usr/bin/env python3
"""decision_hygiene.py の単体テスト（テスト ID: DH-01–DH-05）。

境界条件、複数行 PEM ブロックと単独ヘッダのマスク、生値と URL エンコード値のマスク、
Windows/POSIX 両パスの .env 判定、および stdio UTF-8 再設定を検証する。
"""

from __future__ import annotations

import io
from pathlib import Path
import sys
import unittest
import urllib.parse

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import decision_hygiene as dh  # noqa: E402


class TestDecisionHygiene(unittest.TestCase):
    def test_dh01_sk_boundary_and_token_patterns(self) -> None:
        """DH-01: sk- 境界により英単語内識別子を誤検知せず、5 種のトークン形式を正確に検出・マスクする。"""
        safe_identifiers = [
            "flask-app-secret-config-1234567890",
            "task-executor-worker-pool-config",
            "disk-cache-backend-service-0123456789",
            "sk-" + "short1234567890123",  # 19 文字は未達
        ]
        for ident in safe_identifiers:
            with self.subTest(safe_ident=ident):
                self.assertEqual(dh.scan_text_for_secrets(ident), [])
                self.assertEqual(dh.mask_secrets(ident), ident)

        detected_tokens = [
            ("Google API キー (AIza...)", "AIza" + "Xy9" * 8),
            ("GitHub トークン (gh*_...)", "ghp_" + "A1b2" * 6),
            ("GitHub トークン (gh*_...)", "ghs_" + "Z9y8" * 6),
            ("GitHub Fine-grained PAT (github_pat_...)", "github_pat_" + "AbCd1234_" * 3),
            ("API シークレットキー (sk-...)", "sk-" + "projSecretKey1234567890"),
            ("AWS アクセスキー (AKIA...)", "AKIA" + "1234567890ABCDEF"),
        ]
        for expected_label, token in detected_tokens:
            with self.subTest(token_label=expected_label):
                labels = dh.scan_text_for_secrets(f"value={token}")
                self.assertEqual(labels, [expected_label])
                masked = dh.mask_secrets(f"value={token}")
                self.assertNotIn(token, masked)
                self.assertEqual(masked, "value=[REDACTED]")

    def test_dh02_pem_multiline_block_and_unclosed_header_masking(self) -> None:
        """DH-02: 複数行 PEM ブロック全体と閉じ行なし PEM ヘッダの両方を [REDACTED] へ置換する。"""
        pem_block = (
            "prefix\n"
            + "-----BEGIN "
            + "RSA PRIVATE KEY-----\n"
            + "MIIEpAIBAAKCAQEA1234567890abcdef\n"
            + "-----END "
            + "RSA PRIVATE KEY-----\n"
            + "suffix"
        )
        masked_block = dh.mask_secrets(pem_block)
        self.assertEqual(masked_block, "prefix\n[REDACTED]\nsuffix")
        self.assertNotIn("MIIEpAIBAAKCAQEA", masked_block)

        pgp_block = (
            "-----BEGIN "
            + "PGP PRIVATE KEY BLOCK-----\n"
            + "lQOYBFSecretBodyLine==\n"
            + "-----END "
            + "PGP PRIVATE KEY BLOCK-----"
        )
        masked_pgp = dh.mask_secrets(pgp_block)
        self.assertEqual(masked_pgp, "[REDACTED]")

        unclosed_header = "line1\n-----BEGIN " + "OPENSSH PRIVATE KEY-----\nbody"
        masked_header = dh.mask_secrets(unclosed_header)
        self.assertNotIn("-----BEGIN ", masked_header)
        self.assertIn("[REDACTED]", masked_header)

    def test_dh03_raw_url_encoded_and_extra_pattern_masking(self) -> None:
        """DH-03: api_key の生値・URL エンコード値・追加 Bearer パターンをすべてマスクする。"""
        raw_secret = "key+with/special=chars&more"
        encoded_secret = urllib.parse.quote(raw_secret, safe="")
        dummy_bearer = "Bearer " + "AbCdEf1234567890._~+/"
        text = (
            f"raw={raw_secret} url=https://example.test/?k={encoded_secret} "
            f"auth={dummy_bearer}"
        )
        masked = dh.mask_secrets(
            text,
            secrets=(raw_secret, None, ""),
            extra_patterns=(dh.BEARER_TOKEN_RE,),
        )
        self.assertNotIn(raw_secret, masked)
        self.assertNotIn(encoded_secret, masked)
        self.assertNotIn("AbCdEf1234567890", masked)
        self.assertEqual(masked, "raw=[REDACTED] url=https://example.test/?k=[REDACTED] auth=[REDACTED]")

        # mask_secret 単一値ヘルパー互換
        self.assertEqual(dh.mask_secret(f"err: {encoded_secret}", raw_secret), "err: [REDACTED]")
        self.assertEqual(dh.mask_secret("clean text", None), "clean text")

    def test_dh04_blocked_env_path_and_safe_suffix_allowance(self) -> None:
        """DH-04: / と \\ 両区切りの .env 系を遮断し、サフィックス付き雛形ファイルを許容する。"""
        blocked = [
            ".env",
            ".ENV",
            "config/.env",
            r"C:\repo\.env",
            r"C:\repo\.env.local",
            "deploy/.env.production",
            ".env.staging",
        ]
        for p in blocked:
            with self.subTest(blocked=p):
                self.assertTrue(dh.is_blocked_env_path(p))
                self.assertTrue(dh.is_blocked_env_path(Path(p)))

        allowed = [
            ".env.example",
            ".env.sample",
            ".env.template",
            ".env.dist",
            ".env.schema",
            "config/.env.local.example",
            r"C:\repo\.env.production.sample",
            ".env.dev.template",
            ".env.ci.dist",
            ".env.app.schema",
            "settings.env",
            "notes.txt",
        ]
        for p in allowed:
            with self.subTest(allowed=p):
                self.assertFalse(dh.is_blocked_env_path(p))

    def test_dh05_configure_utf8_stdio_calls_reconfigure_and_skips_stringio(self) -> None:
        """DH-05: configure_utf8_stdio が reconfigure を呼び出し、io.StringIO や失敗ストリームを無害スキップする。"""
        calls: list[tuple[str, str]] = []

        class _ReconfStream:
            def __init__(self, name: str) -> None:
                self.name = name

            def reconfigure(self, *, encoding: str) -> None:
                calls.append((self.name, encoding))

        class _FailingStream:
            def reconfigure(self, *, encoding: str) -> None:
                raise ValueError(f"unsupported: {encoding}")

        orig_in, orig_out, orig_err = sys.stdin, sys.stdout, sys.stderr
        try:
            sys.stdin = _ReconfStream("stdin")  # type: ignore[assignment]
            sys.stdout = _ReconfStream("stdout")  # type: ignore[assignment]
            sys.stderr = _ReconfStream("stderr")  # type: ignore[assignment]
            dh.configure_utf8_stdio()
            self.assertEqual(calls, [("stdin", "utf-8"), ("stdout", "utf-8"), ("stderr", "utf-8")])

            # io.StringIO や ValueError 発生ストリームでも例外を出さない
            sys.stdin = io.StringIO()  # type: ignore[assignment]
            sys.stdout = io.StringIO()  # type: ignore[assignment]
            sys.stderr = _FailingStream()  # type: ignore[assignment]
            dh.configure_utf8_stdio()
        finally:
            sys.stdin = orig_in
            sys.stdout = orig_out
            sys.stderr = orig_err


if __name__ == "__main__":
    unittest.main()
