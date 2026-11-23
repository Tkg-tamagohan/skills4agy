#!/usr/bin/env python3
"""check_devin_review.py の単体テスト（テスト ID: DR-01–DR-14）。

ローカル ThreadingHTTPServer モックを使い、外部通信なしで
入力正規化、未設定フォールバック、--dry-run、ステータス機械判定、
トークン/org_id マスク、POST トリガ、およびベース URL 検証を検証する。
"""

from __future__ import annotations

from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import socket
import sys
import threading
from typing import Any, Callable
import unittest
from unittest import mock
import urllib.parse

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import check_devin_review as cdr  # noqa: E402

DUMMY_KEY = "cog_" + "MockSecretKeyValue0123456789AbCdEf" + "9876543210XYZ"
DUMMY_ORG = "org-uuid-1111-2222-3333-444455556666"


class _MockServer:
    """Thread-safe なローカル HTTP モックサーバ。"""

    def __init__(
        self,
        handler_fn: Callable[[str, str, dict[str, str], bytes], tuple[int, dict[str, str], bytes]],
    ) -> None:
        self.requests: list[dict[str, Any]] = []
        self._handler_fn = handler_fn

        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def _handle(self) -> None:
                length = int(self.headers.get("Content-Length", "0") or "0")
                body = self.rfile.read(length) if length > 0 else b""
                headers = {k.lower(): v for k, v in self.headers.items()}
                outer.requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "headers": headers,
                        "body": body,
                    }
                )
                status, resp_headers, resp_body = outer._handler_fn(
                    self.command, self.path, headers, body
                )
                self.send_response(status)
                for hk, hv in resp_headers.items():
                    self.send_header(hk, hv)
                self.end_headers()
                self.wfile.write(resp_body)

            def do_GET(self) -> None:  # noqa: N802
                self._handle()

            def do_POST(self) -> None:  # noqa: N802
                self._handle()

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.base_url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2.0)


def _run_cli(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
) -> tuple[int, str]:
    buf = io.StringIO()
    env_map = {} if env is None else env
    with mock.patch.dict(os.environ, env_map, clear=True):
        with redirect_stdout(buf):
            code = cdr.main(argv)
    return code, buf.getvalue()


def _unused_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class TestCheckDevinReview(unittest.TestCase):
    def test_dr01_pr_url_normalization_and_invalid_rejection(self) -> None:
        """DR-01: PR URL の正規化（サブパス・クエリ除去・短縮記法）と不正 URL 拒否（exit 2）を検証する。"""
        valid_inputs = [
            ("https://github.com/Owner/Repo/pull/39/", "https://github.com/Owner/Repo/pull/39"),
            ("https://www.github.com/Owner/Repo/pull/39/files?w=1#diff-1", "https://github.com/Owner/Repo/pull/39"),
            ("https://github.com/Owner/Repo/pull/39/commits/abcdef1", "https://github.com/Owner/Repo/pull/39"),
            ("https://github.com/Owner/Repo/pull/39/checks", "https://github.com/Owner/Repo/pull/39"),
            ("Owner/Repo#39", "https://github.com/Owner/Repo/pull/39"),
        ]
        for raw, expected in valid_inputs:
            with self.subTest(valid=raw):
                self.assertEqual(cdr.normalize_pr_url(raw), expected)

        invalid_inputs = [
            "",
            "http://github.com/Owner/Repo/pull/39",
            "https://gitlab.com/Owner/Repo/pull/39",
            "https://user:pass@github.com/Owner/Repo/pull/39",
            "https://github.com:8443/Owner/Repo/pull/39",
            "https://github.com/Owner/Repo/issues/39",
            "https://github.com/Owner/Repo/pull/0",
        ]
        for raw in invalid_inputs:
            with self.subTest(invalid=raw):
                code, out = _run_cli(["--pr-url", raw])
                self.assertEqual(code, 2)
                payload = json.loads(out)
                self.assertEqual(payload["decision"], "invalid_input")
                self.assertFalse(payload["can_conclude_clean"])

    def test_dr02_commit_sha_validation(self) -> None:
        """DR-02: --commit-sha の 7〜40 桁 16 進正規化と不正形式拒否（exit 2）を検証する。"""
        self.assertEqual(cdr.normalize_commit_sha("AbCdEf1"), "abcdef1")
        self.assertEqual(cdr.normalize_commit_sha("A" * 40), "a" * 40)
        self.assertIsNone(cdr.normalize_commit_sha(None))

        for bad_sha in ("", "123456", "a" * 41, "zzzzzzz", "abcdefg"):
            with self.subTest(bad_sha=bad_sha):
                code, out = _run_cli(
                    ["--pr-url", "Owner/Repo#39", "--commit-sha", bad_sha]
                )
                self.assertEqual(code, 2)
                payload = json.loads(out)
                self.assertEqual(payload["decision"], "invalid_input")

    def test_dr03_unconfigured_env_fallback_and_strict_failure(self) -> None:
        """DR-03: 環境変数未設定時の GET フォールバック（exit 0）と --require-configured/--trigger 拒否（exit 2）を検証する。"""
        env_cases = [
            {},
            {"DEVIN_API_KEY": DUMMY_KEY},
            {"DEVIN_ORG_ID": DUMMY_ORG},
        ]
        for env_map in env_cases:
            with self.subTest(env_keys=sorted(env_map.keys())):
                code, out = _run_cli(["--pr-url", "Owner/Repo#39"], env=env_map)
                self.assertEqual(code, 0)
                payload = json.loads(out)
                self.assertFalse(payload["configured"])
                self.assertEqual(payload["decision"], "fallback_github_only")
                self.assertFalse(payload["can_conclude_clean"])

                for strict_flag in ("--require-configured", "--trigger"):
                    code_err, out_err = _run_cli(
                        ["--pr-url", "Owner/Repo#39", strict_flag], env=env_map
                    )
                    self.assertEqual(code_err, 2)
                    payload_err = json.loads(out_err)
                    self.assertEqual(payload_err["decision"], "config_error")
                    self.assertNotIn(DUMMY_KEY, out_err)
                    self.assertNotIn(DUMMY_ORG, out_err)

    def test_dr04_dry_run_makes_zero_http_requests_and_masks_secrets(self) -> None:
        """DR-04: --dry-run（GET と --trigger）で外部通信が 0 件であり秘密値が出力されないことを検証する。"""
        srv = _MockServer(lambda *_: (200, {}, b"{}"))
        try:
            env_map = {"DEVIN_API_KEY": DUMMY_KEY, "DEVIN_ORG_ID": DUMMY_ORG}
            for extra in ([], ["--trigger"]):
                code, out = _run_cli(
                    [
                        "--pr-url",
                        "Owner/Repo#39",
                        "--commit-sha",
                        "6f5032b",
                        "--dry-run",
                        "--api-base-url",
                        srv.base_url,
                        *extra,
                    ],
                    env=env_map,
                )
                self.assertEqual(code, 0)
                payload = json.loads(out)
                self.assertTrue(payload["configured"])
                self.assertTrue(payload["dry_run"])
                self.assertEqual(payload["decision"], "dry_run")
                self.assertFalse(payload["can_conclude_clean"])
                self.assertEqual(
                    payload["request_preview"]["endpoint_template"],
                    f"{srv.base_url}/v3/organizations/[ORG_ID]/pr-reviews",
                )
                self.assertNotIn(DUMMY_KEY, out)
                self.assertNotIn(DUMMY_ORG, out)
            self.assertEqual(len(srv.requests), 0)
        finally:
            srv.close()

    def test_dr05_get_200_completed_full_short_and_omitted_sha(self) -> None:
        """DR-05: GET 200 completed（フル SHA・短縮 SHA・SHA 省略）で completed / can_conclude_clean=True を返す。"""
        full_sha = "6f5032b30bbb6e5a7fbb644f76e41ca8f3113882"
        body = json.dumps(
            {
                "status": "completed",
                "repo_path": "github.com/owner/repo",
                "pr_number": 39,
                "commit_sha": full_sha,
                "created_at": "2026-11-23T08:47:50.995649Z",
            }
        ).encode("utf-8")

        srv = _MockServer(
            lambda method, path, headers, req_body: (
                200,
                {"Content-Type": "application/json"},
                body,
            )
        )
        try:
            env_map = {"DEVIN_API_KEY": DUMMY_KEY, "DEVIN_ORG_ID": DUMMY_ORG}
            for sha_args, expected_match in [
                (["--commit-sha", full_sha], True),
                (["--commit-sha", "6f5032b"], True),
                ([], None),
            ]:
                code, out = _run_cli(
                    [
                        "--pr-url",
                        "https://github.com/Owner/Repo/pull/39",
                        "--api-base-url",
                        srv.base_url,
                        *sha_args,
                    ],
                    env=env_map,
                )
                self.assertEqual(code, 0)
                payload = json.loads(out)
                self.assertEqual(payload["decision"], "completed")
                self.assertTrue(payload["can_conclude_clean"])
                self.assertEqual(payload["commit_match"], expected_match)
                self.assertEqual(payload["pr_number"], 39)

            self.assertEqual(len(srv.requests), 3)
            self.assertEqual(
                srv.requests[0]["headers"]["authorization"], f"Bearer {DUMMY_KEY}"
            )
            parsed_url = urllib.parse.urlparse(srv.requests[0]["path"])
            self.assertEqual(
                parsed_url.path, f"/v3/organizations/{DUMMY_ORG}/pr-reviews"
            )
            qs = urllib.parse.parse_qs(parsed_url.query)
            self.assertEqual(qs["pr_url"], ["https://github.com/Owner/Repo/pull/39"])
            self.assertEqual(qs["commit_sha"], [full_sha])
            self.assertNotIn("commit_sha", urllib.parse.parse_qs(urllib.parse.urlparse(srv.requests[2]["path"]).query))
        finally:
            srv.close()

    def test_dr06_get_200_pending_and_running_return_in_progress(self) -> None:
        """DR-06: GET 200 pending および running で in_progress / can_conclude_clean=False を返す。"""
        full_sha = "55893a8053e38e3dc956f49e6501acadc8cb5e23"
        for status_val in ("pending", "running"):
            body = json.dumps(
                {"status": status_val, "commit_sha": full_sha, "pr_number": 39}
            ).encode("utf-8")
            srv = _MockServer(lambda *_, b=body: (200, {}, b))
            try:
                code, out = _run_cli(
                    [
                        "--pr-url",
                        "Owner/Repo#39",
                        "--commit-sha",
                        full_sha,
                        "--api-base-url",
                        srv.base_url,
                    ],
                    env={"DEVIN_API_KEY": DUMMY_KEY, "DEVIN_ORG_ID": DUMMY_ORG},
                )
                self.assertEqual(code, 0)
                payload = json.loads(out)
                self.assertEqual(payload["review_status"], status_val)
                self.assertEqual(payload["decision"], "in_progress")
                self.assertFalse(payload["can_conclude_clean"])
            finally:
                srv.close()

    def test_dr07_get_200_mismatched_sha_returns_stale_commit(self) -> None:
        """DR-07: GET 200 completed でも commit_sha 不一致なら stale_commit / can_conclude_clean=False になる。"""
        body = json.dumps(
            {
                "status": "completed",
                "commit_sha": "55893a8053e38e3dc956f49e6501acadc8cb5e23",
                "pr_number": 39,
            }
        ).encode("utf-8")
        srv = _MockServer(lambda *_: (200, {}, body))
        try:
            code, out = _run_cli(
                [
                    "--pr-url",
                    "Owner/Repo#39",
                    "--commit-sha",
                    "6f5032b30bbb6e5a7fbb644f76e41ca8f3113882",
                    "--api-base-url",
                    srv.base_url,
                ],
                env={"DEVIN_API_KEY": DUMMY_KEY, "DEVIN_ORG_ID": DUMMY_ORG},
            )
            self.assertEqual(code, 0)
            payload = json.loads(out)
            self.assertFalse(payload["commit_match"])
            self.assertEqual(payload["decision"], "stale_commit")
            self.assertFalse(payload["can_conclude_clean"])
        finally:
            srv.close()

    def test_dr08_get_200_unknown_status(self) -> None:
        """DR-08: GET 200 未知 status で unknown_status / can_conclude_clean=False を返す。"""
        body = json.dumps(
            {"status": "failed", "commit_sha": "6f5032b30bbb6e5a7fbb644f76e41ca8f3113882"}
        ).encode("utf-8")
        srv = _MockServer(lambda *_: (200, {}, body))
        try:
            code, out = _run_cli(
                [
                    "--pr-url",
                    "Owner/Repo#39",
                    "--commit-sha",
                    "6f5032b",
                    "--api-base-url",
                    srv.base_url,
                ],
                env={"DEVIN_API_KEY": DUMMY_KEY, "DEVIN_ORG_ID": DUMMY_ORG},
            )
            self.assertEqual(code, 0)
            payload = json.loads(out)
            self.assertEqual(payload["decision"], "unknown_status")
            self.assertFalse(payload["can_conclude_clean"])
        finally:
            srv.close()

    def test_dr09_get_404_not_found_and_masks_org_id(self) -> None:
        """DR-09: GET 404 RFC 7807 応答で not_found（exit 0）を返し org_id を完全マスクする。"""
        body = json.dumps(
            {
                "type": "about:blank",
                "title": "Not Found",
                "status": 404,
                "detail": f"No review found in {DUMMY_ORG} at commit 000000000000.",
                "instance": f"/v3/organizations/{DUMMY_ORG}/pr-reviews",
            }
        ).encode("utf-8")
        srv = _MockServer(lambda *_: (404, {"Content-Type": "application/problem+json"}, body))
        try:
            code, out = _run_cli(
                ["--pr-url", "Owner/Repo#39", "--api-base-url", srv.base_url],
                env={"DEVIN_API_KEY": DUMMY_KEY, "DEVIN_ORG_ID": DUMMY_ORG},
            )
            self.assertEqual(code, 0)
            payload = json.loads(out)
            self.assertEqual(payload["http_status"], 404)
            self.assertEqual(payload["decision"], "not_found")
            self.assertFalse(payload["can_conclude_clean"])
            self.assertNotIn(DUMMY_ORG, out)
            self.assertIn("[REDACTED]", payload["error_detail"])
        finally:
            srv.close()

    def test_dr10_401_and_403_auth_error_masks_all_secrets(self) -> None:
        """DR-10: 401/403 で auth_error（exit 3）を返し、json/summary 両形式でキー・org_id・Bearer をマスクする。"""
        for status_code in (401, 403):
            body = json.dumps(
                {
                    "detail": f"Unauthorized org={DUMMY_ORG} key={DUMMY_KEY} header=Bearer {DUMMY_KEY}",
                    "instance": f"/v3/organizations/{DUMMY_ORG}/pr-reviews",
                }
            ).encode("utf-8")
            srv = _MockServer(lambda *_, sc=status_code, b=body: (sc, {}, b))
            try:
                for fmt in ("json", "summary"):
                    code, out = _run_cli(
                        [
                            "--pr-url",
                            "Owner/Repo#39",
                            "--format",
                            fmt,
                            "--api-base-url",
                            srv.base_url,
                        ],
                        env={"DEVIN_API_KEY": DUMMY_KEY, "DEVIN_ORG_ID": DUMMY_ORG},
                    )
                    self.assertEqual(code, 3)
                    self.assertNotIn(DUMMY_KEY, out)
                    self.assertNotIn(DUMMY_ORG, out)
                    self.assertNotIn("cog_", out)
                    if fmt == "json":
                        payload = json.loads(out)
                        self.assertEqual(payload["decision"], "auth_error")
                        self.assertEqual(payload["http_status"], status_code)
                    else:
                        self.assertIn("decision=auth_error", out)
            finally:
                srv.close()

    def test_dr11_429_rate_limited_extracts_retry_after(self) -> None:
        """DR-11: 429 で rate_limited（exit 4）と Retry-After 整数秒を返す。"""
        body = json.dumps({"detail": "Rate limit exceeded"}).encode("utf-8")
        srv = _MockServer(lambda *_: (429, {"Retry-After": "30"}, body))
        try:
            code, out = _run_cli(
                ["--pr-url", "Owner/Repo#39", "--api-base-url", srv.base_url],
                env={"DEVIN_API_KEY": DUMMY_KEY, "DEVIN_ORG_ID": DUMMY_ORG},
            )
            self.assertEqual(code, 4)
            payload = json.loads(out)
            self.assertEqual(payload["decision"], "rate_limited")
            self.assertEqual(payload["retry_after_seconds"], 30)
            self.assertFalse(payload["can_conclude_clean"])
        finally:
            srv.close()

    def test_dr12_500_non_json_and_connection_error_return_api_error(self) -> None:
        """DR-12: 500、200 非 JSON 応答、および接続不能エラーで api_error（exit 5）を返す。"""
        # 1) HTTP 500
        srv500 = _MockServer(lambda *_: (500, {}, b"internal error"))
        try:
            code, out = _run_cli(
                ["--pr-url", "Owner/Repo#39", "--api-base-url", srv500.base_url],
                env={"DEVIN_API_KEY": DUMMY_KEY, "DEVIN_ORG_ID": DUMMY_ORG},
            )
            self.assertEqual(code, 5)
            self.assertEqual(json.loads(out)["decision"], "api_error")
        finally:
            srv500.close()

        # 2) HTTP 200 非 JSON
        srv_non_json = _MockServer(lambda *_: (200, {}, b"not-json-body"))
        try:
            code, out = _run_cli(
                ["--pr-url", "Owner/Repo#39", "--api-base-url", srv_non_json.base_url],
                env={"DEVIN_API_KEY": DUMMY_KEY, "DEVIN_ORG_ID": DUMMY_ORG},
            )
            self.assertEqual(code, 5)
            self.assertEqual(json.loads(out)["decision"], "api_error")
        finally:
            srv_non_json.close()

        # 3) 接続不能ポート（例外文字列に org_id が含まれてもマスクされること）
        dead_port = _unused_local_port()
        code, out = _run_cli(
            [
                "--pr-url",
                "Owner/Repo#39",
                "--timeout",
                "1.0",
                "--api-base-url",
                f"http://127.0.0.1:{dead_port}",
            ],
            env={"DEVIN_API_KEY": DUMMY_KEY, "DEVIN_ORG_ID": DUMMY_ORG},
        )
        self.assertEqual(code, 5)
        payload = json.loads(out)
        self.assertEqual(payload["decision"], "api_error")
        self.assertNotIn(DUMMY_KEY, out)
        self.assertNotIn(DUMMY_ORG, out)

    def test_dr13_trigger_post_200_202_and_409(self) -> None:
        """DR-13: --trigger POST で 200/202 が triggered、409 が already_running（exit 0）になる。"""
        for status_code, expected_decision, resp_body in [
            (200, "triggered", json.dumps({"status": "pending", "pr_number": 39}).encode("utf-8")),
            (202, "triggered", b""),
            (409, "already_running", json.dumps({"detail": "Review already running"}).encode("utf-8")),
        ]:
            srv = _MockServer(lambda *_, sc=status_code, rb=resp_body: (sc, {}, rb))
            try:
                code, out = _run_cli(
                    [
                        "--pr-url",
                        "Owner/Repo#39",
                        "--trigger",
                        "--api-base-url",
                        srv.base_url,
                    ],
                    env={"DEVIN_API_KEY": DUMMY_KEY, "DEVIN_ORG_ID": DUMMY_ORG},
                )
                self.assertEqual(code, 0)
                payload = json.loads(out)
                self.assertEqual(payload["decision"], expected_decision)
                self.assertFalse(payload["can_conclude_clean"])
                self.assertEqual(len(srv.requests), 1)
                req = srv.requests[0]
                self.assertEqual(req["method"], "POST")
                self.assertEqual(
                    req["path"], f"/v3/organizations/{DUMMY_ORG}/pr-reviews"
                )
                self.assertEqual(
                    json.loads(req["body"].decode("utf-8")),
                    {"pr_url": "https://github.com/Owner/Repo/pull/39"},
                )
            finally:
                srv.close()

    def test_dr14_api_base_url_blocks_non_loopback_external_hosts(self) -> None:
        """DR-14: --api-base-url に既定以外の外部ホストや不正形式を渡すと通信せず exit 2 で拒否される。"""
        bad_urls = [
            "https://evil.example.com",
            "http://api.devin.ai",
            "https://api.devin.ai:8443",
            "ftp://127.0.0.1:8080",
            "http://user:pass@127.0.0.1:8080",
            "http://127.0.0.1:8080/prefix",
        ]
        for bad_url in bad_urls:
            with self.subTest(bad_url=bad_url):
                code, out = _run_cli(
                    ["--pr-url", "Owner/Repo#39", "--api-base-url", bad_url],
                    env={"DEVIN_API_KEY": DUMMY_KEY, "DEVIN_ORG_ID": DUMMY_ORG},
                )
                self.assertEqual(code, 2)
                payload = json.loads(out)
                self.assertEqual(payload["decision"], "invalid_input")
                self.assertNotIn(DUMMY_KEY, out)
                self.assertNotIn(DUMMY_ORG, out)


if __name__ == "__main__":
    unittest.main()
