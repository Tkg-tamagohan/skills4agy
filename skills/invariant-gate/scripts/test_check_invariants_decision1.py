#!/usr/bin/env python3
"""check_invariants_decision1.py の仕様準拠単体テスト（INV-01〜INV-17 / P1-01〜P1-06）。

外部ネットワーク通信を行わず、SDK・REST・git diff・エラー経路をモックして検証する。
"""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock
import urllib.error

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import check_invariants_decision1 as gate  # noqa: E402
import run_decisions  # noqa: E402

SAMPLE_DIFF = """diff --git a/src/app.py b/src/app.py
index 1111111..2222222 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1,3 +1,4 @@
 def run():
-    return 1
+    print("debug")
+    return 2
"""


def _write_file(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _run_cli_capture(
    argv: list[str],
    env_override: dict[str, str | None] | None = None,
    rest_opener: object | None = None,
) -> tuple[int, str, str]:
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    saved_env: dict[str, str | None] = {}
    if env_override:
        for k, v in env_override.items():
            saved_env[k] = os.environ.get(k)
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    try:
        with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
            code = gate.run_cli(argv, rest_opener=rest_opener)  # type: ignore[arg-type]
    finally:
        for k, old_v in saved_env.items():
            if old_v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = old_v
    return code, stdout_buf.getvalue(), stderr_buf.getvalue()


class FakeHTTPResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "FakeHTTPResponse":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        return None


class TestInvariantGate(unittest.TestCase):
    def test_INV_01_empty_diff_skips_api_with_zero(self) -> None:
        """INV-01: 空差分は API を呼ばず終了コード 0 (skipped_empty_diff) を返す。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root / "AGENTS.md", "# Rules\n\n## Coding\n- Keep functions small.\n")
            diff_file = _write_file(root / "empty.diff", "\n   \n")

            with mock.patch.object(gate, "call_decisions_backend") as mock_call:
                code, out, _ = _run_cli_capture(
                    [
                        "--repo-root",
                        str(root),
                        "--diff-file",
                        str(diff_file),
                        "--format",
                        "json",
                    ],
                    env_override={"GEMINI_API_KEY": None},
                )
            self.assertEqual(code, 0)
            mock_call.assert_not_called()
            data = json.loads(out)
            self.assertEqual(data["status"], "skipped_empty_diff")

    def test_INV_02_rule_extraction_filters_and_key_regex(self) -> None:
        """INV-02: frontmatter・対象外・コードブロック内見出しを除いて抽出し、キー制約を満たす。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(
                root / "AGENTS.md",
                "---\n"
                "name: sample\n"
                "description: should be ignored\n"
                "---\n"
                "# Repository Rules\n\n"
                "## Security\n"
                "- Never write hardcoded credentials.\n"
                "```markdown\n"
                "## Fake Heading Inside Fence\n"
                "- Fake bullet inside fence.\n"
                "```\n\n"
                "## 対象外\n"
                "- This out-of-scope bullet must be skipped.\n\n"
                "## Logging\n"
                "- Avoid raw print statements in production code.\n",
            )
            _write_file(
                root / ".agents" / "rules" / ("very_long_rule_filename_" * 4 + ".md"),
                "---\ntrigger: model_decision\n---\n# Long Rule\n\n## Boundary\n- Enforce bounded queues.\n",
            )

            rules = gate.collect_rules(root, ["src/app.py"])
            texts = [r.text for r in rules]

            self.assertTrue(any("Never write hardcoded credentials." in t for t in texts))
            self.assertTrue(any("Avoid raw print statements in production code." in t for t in texts))
            self.assertTrue(any("Enforce bounded queues." in t for t in texts))
            self.assertFalse(any("should be ignored" in t for t in texts))
            self.assertFalse(any("Fake bullet inside fence" in t for t in texts))
            self.assertFalse(any("out-of-scope bullet" in t for t in texts))

            for r in rules:
                self.assertRegex(r.key, run_decisions.QUESTION_KEY_RE)
                self.assertLessEqual(len(r.key), 64)

    def test_INV_03_missing_api_key_and_dry_run(self) -> None:
        """INV-03: 非空差分でキー未設定時は 2、--dry-run 時はキー不要で検証済みペイロードを出し 0。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root / "AGENTS.md", "# Rules\n\n## Style\n- Do not leave debug print.\n")
            diff_file = _write_file(root / "change.diff", SAMPLE_DIFF)

            code_no_key, out_no_key, _ = _run_cli_capture(
                ["--repo-root", str(root), "--diff-file", str(diff_file), "--format", "json"],
                env_override={"GEMINI_API_KEY": None},
            )
            self.assertEqual(code_no_key, 2)
            self.assertEqual(json.loads(out_no_key)["code"], "missing_api_key")

            code_dry, out_dry, _ = _run_cli_capture(
                [
                    "--repo-root",
                    str(root),
                    "--diff-file",
                    str(diff_file),
                    "--dry-run",
                    "--format",
                    "json",
                ],
                env_override={"GEMINI_API_KEY": None},
            )
            self.assertEqual(code_dry, 0)
            dry_data = json.loads(out_dry)
            self.assertEqual(dry_data["status"], "dry_run")
            self.assertEqual(run_decisions.validate_payload(dry_data["payload"]), [])
            self.assertGreaterEqual(len(dry_data["rules"]), 1)

    def test_INV_04_sdk_call_specification(self) -> None:
        """INV-04: SDK 経路で v1beta・gemini-decision-1・改行区切り input・肯定文 noul が 1 回呼ばれる。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root / "AGENTS.md", "# Rules\n\n## Style\n- Do not leave debug print.\n")
            diff_file = _write_file(root / "change.diff", SAMPLE_DIFF)

            init_calls: list[dict[str, object]] = []
            create_calls: list[dict[str, object]] = []

            class FakeDecisionsResource:
                def create(self, **kwargs: object) -> dict[str, object]:
                    create_calls.append(kwargs)
                    q_map = kwargs["questions"]
                    assert isinstance(q_map, dict)
                    return {
                        "answers": {
                            k: {"type": "noul", "noul": 0.12, "confidence": 0.88}
                            for k in q_map
                        }
                    }

            class FakeClient:
                def __init__(self, **kwargs: object) -> None:
                    init_calls.append(kwargs)
                    self.decisions = FakeDecisionsResource()

            fake_google = types.ModuleType("google")
            fake_genai = types.ModuleType("google.genai")
            fake_genai.Client = FakeClient  # type: ignore[attr-defined]
            fake_google.genai = fake_genai  # type: ignore[attr-defined]

            with mock.patch.dict(sys.modules, {"google": fake_google, "google.genai": fake_genai}):
                code, out, _ = _run_cli_capture(
                    [
                        "--repo-root",
                        str(root),
                        "--diff-file",
                        str(diff_file),
                        "--backend",
                        "auto",
                        "--format",
                        "json",
                    ],
                    env_override={"GEMINI_API_KEY": "test-dummy-key-12345"},
                )

            self.assertEqual(code, 0)
            self.assertEqual(len(init_calls), 1)
            self.assertEqual(init_calls[0]["http_options"], {"api_version": "v1beta"})
            self.assertEqual(len(create_calls), 1)
            req = create_calls[0]
            self.assertEqual(req["model"], "gemini-decision-1")
            input_blocks = req["input"]
            assert isinstance(input_blocks, list)
            for block in input_blocks:
                self.assertTrue(block["text"].endswith("\n"))
            questions = req["questions"]
            assert isinstance(questions, dict)
            for q_body in questions.values():
                self.assertEqual(q_body["type"], "noul")
                self.assertIn("violates the following repository rule", q_body["instructions"])
                self.assertIn("Answer No if", q_body["instructions"])
            self.assertEqual(json.loads(out)["backend_used"], "sdk")

    def test_INV_05_fallback_to_rest_on_missing_or_old_sdk(self) -> None:
        """INV-05: ImportError または client.decisions 不在時に run_decisions REST へ自動フォールバックする。"""
        payload = {
            "model": "gemini-decision-1",
            "input": [{"type": "text", "text": "diff\n"}],
            "questions": {"q1": {"type": "noul", "instructions": "Does it violate rule?"}},
        }
        rest_response = {"answers": {"q1": {"type": "noul", "noul": 0.10, "confidence": 0.90}}}

        # Case 1: client.decisions 不在 (google-genai 2.x 相当)
        class OldClient:
            def __init__(self, **kwargs: object) -> None:
                pass

        fake_google = types.ModuleType("google")
        fake_genai = types.ModuleType("google.genai")
        fake_genai.Client = OldClient  # type: ignore[attr-defined]
        fake_google.genai = fake_genai  # type: ignore[attr-defined]

        with mock.patch.dict(sys.modules, {"google": fake_google, "google.genai": fake_genai}):
            with mock.patch.object(run_decisions, "call_decisions_api", return_value=rest_response) as mock_rest:
                resp, backend_used = gate.call_decisions_backend(
                    payload, api_key="dummy-key", backend="auto"
                )
        self.assertEqual(backend_used, "rest")
        self.assertEqual(resp, rest_response)
        mock_rest.assert_called_once()

        # Case 2: ImportError
        with mock.patch.dict(sys.modules, {"google": None, "google.genai": None}):
            with mock.patch.object(run_decisions, "call_decisions_api", return_value=rest_response) as mock_rest2:
                resp2, backend_used2 = gate.call_decisions_backend(
                    payload, api_key="dummy-key", backend="auto"
                )
        self.assertEqual(backend_used2, "rest")
        self.assertEqual(resp2, rest_response)
        mock_rest2.assert_called_once()

    def test_INV_06_thresholds_and_exit_codes(self) -> None:
        """INV-06: noul >= 0.70 で 1、0.40 <= noul < 0.70 で通常 0 / --strict 1、未満で 0。"""
        rules = [
            gate.RuleItem(
                key="r1",
                source_file="AGENTS.md",
                start_line=10,
                end_line=10,
                heading="Test",
                text="rule 1",
                instructions="Does it violate rule 1?",
                matched_files=["src/app.py"],
            )
        ]

        # >= 0.70 -> violation (exit 1)
        rep_viol, code_viol = gate.evaluate_answers(
            {"answers": {"r1": {"type": "noul", "noul": 0.70, "confidence": 0.70}}},
            rules,
        )
        self.assertEqual(code_viol, 1)
        self.assertEqual(len(rep_viol["violation_candidates"]), 1)

        # 0.40 <= noul < 0.70 -> warning (normal 0, strict 1)
        warn_resp = {"answers": {"r1": {"type": "noul", "noul": 0.55, "confidence": 0.55}}}
        rep_warn, code_warn = gate.evaluate_answers(warn_resp, rules, strict=False)
        self.assertEqual(code_warn, 0)
        self.assertEqual(len(rep_warn["warnings"]), 1)

        _, code_warn_strict = gate.evaluate_answers(warn_resp, rules, strict=True)
        self.assertEqual(code_warn_strict, 1)

        # < 0.40 -> pass (exit 0)
        rep_pass, code_pass = gate.evaluate_answers(
            {"answers": {"r1": {"type": "noul", "noul": 0.39, "confidence": 0.61}}},
            rules,
            strict=True,
        )
        self.assertEqual(code_pass, 0)
        self.assertEqual(rep_pass["passed_count"], 1)

    def test_INV_07_custom_invariants_json_override_and_path_globs(self) -> None:
        """INV-07: .agents/invariants.json の追加・上書きと path_globs による絞り込みが動く。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root / "AGENTS.md", "# Rules\n\n## Core\n- Auto extracted rule.\n")
            auto_rules = gate.collect_rules(root, ["src/app.py"])
            auto_key = auto_rules[0].key

            _write_file(
                root / ".agents" / "invariants.json",
                json.dumps(
                    {
                        "questions": {
                            auto_key: {
                                "instructions": "Overridden custom instruction?",
                                "threshold": 0.85,
                            },
                            "py_only": {
                                "instructions": "Does the Python diff violate typing rules?",
                                "path_globs": ["src/**/*.py"],
                            },
                            "rs_only": {
                                "instructions": "Does the Rust diff use unwrap?",
                                "path_globs": ["**/*.rs"],
                            },
                        }
                    }
                ),
            )

            rules = gate.collect_rules(root, ["src/app.py"])
            by_key = {r.key: r for r in rules}
            self.assertIn(auto_key, by_key)
            self.assertEqual(by_key[auto_key].instructions, "Overridden custom instruction?")
            self.assertEqual(by_key[auto_key].threshold, 0.85)
            self.assertIn("py_only", by_key)
            self.assertNotIn("rs_only", by_key)

    def test_INV_08_extra_rules_markdown_outside_repo(self) -> None:
        """INV-08: --rules でリポジトリ外の Markdown を追加ルールとして統合評価できる。"""
        with tempfile.TemporaryDirectory() as tmp_repo, tempfile.TemporaryDirectory() as tmp_ext:
            repo_root = Path(tmp_repo)
            ext_rule = _write_file(
                Path(tmp_ext) / "systems-pre-pr-audit.md",
                "---\nname: systems-pre-pr-audit\n---\n# Audit\n\n## Timeout\n- Set explicit read/write timeouts on IPC sockets.\n",
            )
            diff_file = _write_file(repo_root / "change.diff", SAMPLE_DIFF)

            code, out, _ = _run_cli_capture(
                [
                    "--repo-root",
                    str(repo_root),
                    "--diff-file",
                    str(diff_file),
                    "--rules",
                    str(ext_rule),
                    "--dry-run",
                    "--format",
                    "json",
                ],
                env_override={"GEMINI_API_KEY": None},
            )
            self.assertEqual(code, 0)
            data = json.loads(out)
            self.assertEqual(data["rule_count"], 1)
            q_bodies = list(data["payload"]["questions"].values())
            self.assertIn("Set explicit read/write timeouts on IPC sockets.", q_bodies[0]["instructions"])

    def test_INV_09_input_size_and_question_count_limits(self) -> None:
        """INV-09: 文字数上限超過または 1,000 問超過で無言切り詰めせず終了コード 2 を返す。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root / "AGENTS.md", "# Rules\n\n## Basic\n- Keep changes small.\n")
            big_diff = SAMPLE_DIFF + ("+" + "x" * 1000 + "\n") * 20
            big_diff_file = _write_file(root / "big.diff", big_diff)

            code_chars, out_chars, _ = _run_cli_capture(
                [
                    "--repo-root",
                    str(root),
                    "--diff-file",
                    str(big_diff_file),
                    "--max-chars",
                    "5000",
                    "--dry-run",
                    "--format",
                    "json",
                ],
                env_override={"GEMINI_API_KEY": None},
            )
            self.assertEqual(code_chars, 2)
            self.assertEqual(json.loads(out_chars)["code"], "input_size_limit_exceeded")

            # 1,001 問超過
            many_rules = "# Rules\n\n## Bulk\n" + "".join(
                f"- Invariant rule number {i}.\n" for i in range(1001)
            )
            _write_file(root / "AGENTS.md", many_rules)
            small_diff_file = _write_file(root / "small.diff", SAMPLE_DIFF)

            code_q, out_q, _ = _run_cli_capture(
                [
                    "--repo-root",
                    str(root),
                    "--diff-file",
                    str(small_diff_file),
                    "--dry-run",
                    "--format",
                    "json",
                ],
                env_override={"GEMINI_API_KEY": None},
            )
            self.assertEqual(code_q, 2)
            self.assertEqual(json.loads(out_q)["code"], "question_limit_exceeded")

    def test_INV_10_secret_guard_and_lockfile_exclusions(self) -> None:
        """INV-10: .env / PRIVATE KEY 混入を送信前に 2 で遮断し、git diff にロックファイル除外を渡す。"""
        # 1. git diff 引数にロックファイル除外が含まれる
        cmd = gate.build_git_diff_command(Path("."), base="main")
        for lock_name in gate.DEFAULT_EXCLUDE_LOCKS:
            self.assertTrue(
                any(lock_name in arg and "exclude" in arg for arg in cmd),
                f"lockfile exclusion missing for {lock_name}: {cmd}",
            )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root / "AGENTS.md", "# Rules\n\n## Sec\n- Protect secrets.\n")

            # 2. .env 変更を遮断
            env_diff = _write_file(
                root / "env.diff",
                "diff --git a/.env b/.env\n--- /dev/null\n+++ b/.env\n@@ -0,0 +1 @@\n+API_TOKEN=secret\n",
            )
            code_env, out_env, _ = _run_cli_capture(
                ["--repo-root", str(root), "--diff-file", str(env_diff), "--dry-run", "--format", "json"]
            )
            self.assertEqual(code_env, 2)
            self.assertEqual(json.loads(out_env)["code"], "secret_detected")

            # 3. .env.example は許可
            env_example_diff = _write_file(
                root / "env_example.diff",
                "diff --git a/.env.example b/.env.example\n--- /dev/null\n+++ b/.env.example\n@@ -0,0 +1 @@\n+API_TOKEN=placeholder\n",
            )
            code_ex, _, _ = _run_cli_capture(
                ["--repo-root", str(root), "--diff-file", str(env_example_diff), "--dry-run", "--format", "json"]
            )
            self.assertEqual(code_ex, 0)

            # 4. PRIVATE KEY ヘッダを遮断
            key_diff = _write_file(
                root / "key.diff",
                "diff --git a/certs/dev.pem b/certs/dev.pem\n--- /dev/null\n+++ b/certs/dev.pem\n"
                "@@ -0,0 +1,2 @@\n+-----BEGIN RSA PRIVATE KEY-----\n+MIIEpAIBAAKCAQEA\n",
            )
            code_key, out_key, _ = _run_cli_capture(
                ["--repo-root", str(root), "--diff-file", str(key_diff), "--dry-run", "--format", "json"]
            )
            self.assertEqual(code_key, 2)
            self.assertEqual(json.loads(out_key)["code"], "secret_detected")

    def test_INV_11_safety_block_and_network_error_mask_api_key(self) -> None:
        """INV-11: HTTP 400 安全遮断・HTTP 200 prompt_feedback・通信失敗で API キーを露出せず 2 を返す。"""
        secret_key = "AIzaSySecretKeyValueForMaskingTest123456"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root / "AGENTS.md", "# Rules\n\n## Sec\n- Validate inputs.\n")
            diff_file = _write_file(root / "change.diff", SAMPLE_DIFF)

            base_argv = [
                "--repo-root",
                str(root),
                "--diff-file",
                str(diff_file),
                "--backend",
                "rest",
                "--format",
                "json",
            ]

            # Case 1: HTTP 400 safety block with leaked key in error message
            def opener_http_400(req: object, timeout: float = 30.0) -> object:
                body = json.dumps(
                    {
                        "error": {
                            "code": "safety",
                            "message": f"blocked request for key={secret_key}",
                        }
                    }
                ).encode("utf-8")
                raise urllib.error.HTTPError(
                    url="https://example.invalid",
                    code=400,
                    msg="Bad Request",
                    hdrs=None,  # type: ignore[arg-type]
                    fp=io.BytesIO(body),
                )

            code1, out1, err1 = _run_cli_capture(
                base_argv,
                env_override={"GEMINI_API_KEY": secret_key},
                rest_opener=opener_http_400,
            )
            self.assertEqual(code1, 2)
            self.assertEqual(json.loads(out1)["code"], "safety_blocked")
            self.assertNotIn(secret_key, out1 + err1)

            # Case 2: HTTP 200 prompt_feedback.block_reason
            def opener_http_200_block(req: object, timeout: float = 30.0) -> FakeHTTPResponse:
                return FakeHTTPResponse(
                    {
                        "prompt_feedback": {
                            "block_reason": "PROHIBITED_CONTENT",
                            "block_reason_message": f"denied ({secret_key})",
                        },
                        "answers": {},
                    }
                )

            code2, out2, err2 = _run_cli_capture(
                base_argv,
                env_override={"GEMINI_API_KEY": secret_key},
                rest_opener=opener_http_200_block,
            )
            self.assertEqual(code2, 2)
            self.assertEqual(json.loads(out2)["code"], "safety_blocked")
            self.assertNotIn(secret_key, out2 + err2)

            # Case 3: Network failure (URLError)
            def opener_url_error(req: object, timeout: float = 30.0) -> object:
                raise urllib.error.URLError(f"connection refused with {secret_key}")

            code3, out3, err3 = _run_cli_capture(
                base_argv,
                env_override={"GEMINI_API_KEY": secret_key},
                rest_opener=opener_url_error,
            )
            self.assertEqual(code3, 2)
            self.assertEqual(json.loads(out3)["code"], "api_request_failed")
            self.assertNotIn(secret_key, out3 + err3)

    def test_INV_12_zero_rules_normal_and_strict(self) -> None:
        """INV-12: ルール 0 件時は API を呼ばず通常 0、--strict 時 2 を返す。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diff_file = _write_file(root / "change.diff", SAMPLE_DIFF)

            with mock.patch.object(gate, "call_decisions_backend") as mock_call:
                code_normal, out_normal, _ = _run_cli_capture(
                    ["--repo-root", str(root), "--diff-file", str(diff_file), "--format", "json"],
                    env_override={"GEMINI_API_KEY": None},
                )
                code_strict, out_strict, _ = _run_cli_capture(
                    [
                        "--repo-root",
                        str(root),
                        "--diff-file",
                        str(diff_file),
                        "--strict",
                        "--format",
                        "json",
                    ],
                    env_override={"GEMINI_API_KEY": None},
                )

            mock_call.assert_not_called()
            self.assertEqual(code_normal, 0)
            self.assertEqual(json.loads(out_normal)["status"], "skipped_no_rules")
            self.assertEqual(code_strict, 2)
            self.assertEqual(json.loads(out_strict)["code"], "no_rules_strict")

    def test_P1_01_preset_systems_pre_pr_loads_skill_and_dry_run(self) -> None:
        """P1-01: --preset systems-pre-pr が systems-pre-pr-audit/SKILL.md を読み込み --dry-run が通る。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diff_file = _write_file(root / "change.diff", SAMPLE_DIFF)

            code, out, err = _run_cli_capture(
                [
                    "--repo-root",
                    str(root),
                    "--diff-file",
                    str(diff_file),
                    "--preset",
                    "systems-pre-pr",
                    "--dry-run",
                    "--format",
                    "json",
                ],
                env_override={"GEMINI_API_KEY": None},
            )
            self.assertEqual(code, 0, msg=err)
            data = json.loads(out)
            self.assertEqual(data["status"], "dry_run")
            self.assertGreater(data["rule_count"], 0)
            self.assertEqual(run_decisions.validate_payload(data["payload"]), [])
            self.assertTrue(
                any(
                    r["source_file"].endswith("systems-pre-pr-audit/SKILL.md")
                    for r in data["rules"]
                )
            )
            all_instructions = "\n".join(
                q["instructions"] for q in data["payload"]["questions"].values()
            )
            self.assertIn("unbounded_channel", all_instructions)

    def test_P1_02_preset_deduplicates_with_repeated_flags_and_rules(self) -> None:
        """P1-02: --preset 重複指定や --rules 併用で重複登録されず、不正プリセット名は拒否される。"""
        preset_skill = (
            Path(__file__).resolve().parents[3]
            / "skills"
            / "systems-pre-pr-audit"
            / "SKILL.md"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            diff_file = _write_file(root / "change.diff", SAMPLE_DIFF)

            code1, out1, _ = _run_cli_capture(
                [
                    "--repo-root",
                    str(root),
                    "--diff-file",
                    str(diff_file),
                    "--preset",
                    "systems-pre-pr",
                    "--dry-run",
                    "--format",
                    "json",
                ],
                env_override={"GEMINI_API_KEY": None},
            )
            code2, out2, _ = _run_cli_capture(
                [
                    "--repo-root",
                    str(root),
                    "--diff-file",
                    str(diff_file),
                    "--preset",
                    "systems-pre-pr",
                    "--preset",
                    "systems-pre-pr",
                    "--rules",
                    str(preset_skill),
                    "--dry-run",
                    "--format",
                    "json",
                ],
                env_override={"GEMINI_API_KEY": None},
            )
            self.assertEqual(code1, 0)
            self.assertEqual(code2, 0)
            d1 = json.loads(out1)
            d2 = json.loads(out2)
            self.assertEqual(d1["rule_count"], d2["rule_count"])
            self.assertEqual(
                sorted(d1["payload"]["questions"].keys()),
                sorted(d2["payload"]["questions"].keys()),
            )

        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as ctx:
                gate.build_arg_parser().parse_args(["--preset", "invalid-preset"])
            self.assertNotEqual(ctx.exception.code, 0)

    def test_P1_03_secret_guard_blocks_api_tokens_without_leaking(self) -> None:
        """P1-03: 主要トークン形式を追加行・文脈行で終了コード 2 遮断し、実値を露出しない。"""
        token_cases = [
            ("AIza", "AIza" + "AbCdEfGhIj1234567890xy"),
            ("ghp_", "ghp_" + "A" * 24),
            ("gho_", "gho_" + "B" * 24),
            ("ghu_", "ghu_" + "C" * 24),
            ("ghs_", "ghs_" + "D" * 24),
            ("ghr_", "ghr_" + "E" * 24),
            ("github_pat_", "github_pat_" + "F" * 24),
            ("sk-", "sk-" + "proj-" + "G" * 24),
            ("AKIA", "AKIA" + "01234567" + "ABCDEFGH"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root / "AGENTS.md", "# Rules\n\n## Sec\n- Protect API tokens.\n")

            for label, token in token_cases:
                for line_kind, prefix in (("added", "+"), ("context", " ")):
                    for fmt in ("json", "table"):
                        with self.subTest(label=label, line_kind=line_kind, fmt=fmt):
                            diff_body = (
                                "diff --git a/src/config.py b/src/config.py\n"
                                "index 1111111..2222222 100644\n"
                                "--- a/src/config.py\n"
                                "+++ b/src/config.py\n"
                                "@@ -1,2 +1,2 @@\n"
                                f"{prefix}API_TOKEN = \"{token}\"\n"
                                "+DEBUG = False\n"
                            )
                            diff_file = _write_file(root / "token.diff", diff_body)
                            with mock.patch.object(gate, "call_decisions_backend") as mock_call:
                                code, out, err = _run_cli_capture(
                                    [
                                        "--repo-root",
                                        str(root),
                                        "--diff-file",
                                        str(diff_file),
                                        "--dry-run",
                                        "--format",
                                        fmt,
                                    ],
                                    env_override={"GEMINI_API_KEY": None},
                                )
                            self.assertEqual(code, 2)
                            mock_call.assert_not_called()
                            self.assertNotIn(token, out + err)
                            if fmt == "json":
                                err_payload = json.loads(out)
                                self.assertEqual(err_payload["code"], "secret_detected")
                            else:
                                self.assertIn("secret_detected", err)

            # 削除行のみのトークンや通常のハイフン繋ぎ識別子は誤遮断しない
            safe_token = "ghp_" + "Z" * 24
            safe_diff = _write_file(
                root / "safe.diff",
                "diff --git a/src/config.py b/src/config.py\n"
                "--- a/src/config.py\n"
                "+++ b/src/config.py\n"
                "@@ -1,2 +1,2 @@\n"
                f"-OLD_TOKEN = \"{safe_token}\"\n"
                "+WORKER_NAME = \"task-executor-worker-pool-config\"\n",
            )
            code_safe, _, err_safe = _run_cli_capture(
                [
                    "--repo-root",
                    str(root),
                    "--diff-file",
                    str(safe_diff),
                    "--dry-run",
                    "--format",
                    "json",
                ],
                env_override={"GEMINI_API_KEY": None},
            )
            self.assertEqual(code_safe, 0, msg=err_safe)

    def test_P1_04_mask_secret_redacts_all_token_formats(self) -> None:
        """P1-04: mask_secret が主要 API トークン形式すべてを [REDACTED] へ置換する。"""
        tokens = [
            "AIza" + "AbCdEfGhIj1234567890xy",
            "ghp_" + "A" * 24,
            "github_pat_" + "B" * 24,
            "sk-" + "C" * 24,
            "AKIA" + "01234567" + "ABCDEFGH",
        ]
        env_secret = "custom-env-" + "S" * 16
        raw_msg = "failed with " + " ".join(tokens) + f" and {env_secret}"
        masked = gate.mask_secret(raw_msg, env_secret)
        for tok in tokens + [env_secret]:
            self.assertNotIn(tok, masked)
        self.assertIn("[REDACTED]", masked)

    def test_INV_13_auto_rule_dirs_include_dot_agent_and_underscore_agent(self) -> None:
        """INV-13: .agent/rules と _agent/rules を含む 4 種のルールディレクトリを昇順で自動検出する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root / ".agents" / "rules" / "b.md", "## A1\n- Rule from .agents.\n")
            _write_file(root / ".agents" / "rules" / "a.md", "## A0\n- Rule from .agents a.\n")
            _write_file(root / ".agent" / "rules" / "c.md", "## B1\n- Rule from .agent.\n")
            _write_file(root / "_agents" / "rules" / "d.md", "## C1\n- Rule from _agents.\n")
            _write_file(root / "_agent" / "rules" / "e.md", "## D1\n- Rule from _agent.\n")

            files = gate.discover_rule_files(root)
            rel_files = [p.relative_to(root.resolve()).as_posix() for p in files]
            self.assertEqual(
                rel_files,
                [
                    ".agents/rules/a.md",
                    ".agents/rules/b.md",
                    ".agent/rules/c.md",
                    "_agents/rules/d.md",
                    "_agent/rules/e.md",
                ],
            )
            rules = gate.collect_rules(root, ["src/app.py"])
            self.assertEqual(len(rules), 5)

    def test_INV_14_native_plugin_rules_discovery(self) -> None:
        """INV-14: ネイティブプラグイン構成（JSONC 含む）または rules/AGENTS.md 共存時に rules/*.md を重複なく検出する。"""
        manifest_cases = [
            ("plugin.json", '{\n  // JSONC comment\n  "name": "sample",\n}\n'),
            (".antigravity-plugin/plugin.json", '{"name": "sample"}\n'),
            (".gemini-plugin/plugin.json", '{"name": "sample"}\n'),
        ]
        for manifest_rel, manifest_body in manifest_cases:
            with self.subTest(manifest=manifest_rel):
                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    _write_file(root / manifest_rel, manifest_body)
                    _write_file(root / "rules" / "AGENTS.md", "## Core\n- Rule AGENTS.\n")
                    _write_file(root / "rules" / "GEMINI.md", "## Gem\n- Rule GEMINI.\n")
                    _write_file(root / "rules" / "alpha.md", "## Alpha\n- Rule alpha.\n")
                    _write_file(root / "rules" / "sub" / "nested.md", "## Nested\n- Should not recurse.\n")
                    _write_file(root / "rules" / "legacy.mdc", "## Legacy\n- Should ignore mdc.\n")

                    self.assertTrue(gate.is_native_plugin_repo(root))
                    files = gate.discover_rule_files(root)
                    rel_files = [p.relative_to(root.resolve()).as_posix() for p in files]
                    self.assertEqual(
                        rel_files,
                        ["rules/AGENTS.md", "rules/GEMINI.md", "rules/alpha.md"],
                    )

        # rules/AGENTS.md 単独でもプラグインルール探索が有効になり重複しない
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root / "rules" / "AGENTS.md", "## Core\n- Rule AGENTS.\n")
            _write_file(root / "rules" / "domain.md", "## Domain\n- Rule domain.\n")
            self.assertTrue(gate.is_native_plugin_repo(root))
            files = gate.discover_rule_files(root)
            rel_files = [p.relative_to(root.resolve()).as_posix() for p in files]
            self.assertEqual(rel_files, ["rules/AGENTS.md", "rules/domain.md"])

    def test_INV_15_non_plugin_repo_ignores_rules_dir(self) -> None:
        """INV-15: マニフェストも rules/AGENTS.md もない通常リポジトリでは rules/*.md を自動検出しない。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root / "rules" / "domain.md", "## Domain\n- Should not auto-load.\n")
            diff_file = _write_file(root / "change.diff", SAMPLE_DIFF)

            self.assertFalse(gate.is_native_plugin_repo(root))
            self.assertEqual(gate.discover_rule_files(root), [])

            code_normal, out_normal, _ = _run_cli_capture(
                ["--repo-root", str(root), "--diff-file", str(diff_file), "--format", "json"],
                env_override={"GEMINI_API_KEY": None},
            )
            code_strict, out_strict, _ = _run_cli_capture(
                ["--repo-root", str(root), "--diff-file", str(diff_file), "--strict", "--format", "json"],
                env_override={"GEMINI_API_KEY": None},
            )
            self.assertEqual(code_normal, 0)
            self.assertEqual(json.loads(out_normal)["status"], "skipped_no_rules")
            self.assertEqual(code_strict, 2)
            self.assertEqual(json.loads(out_strict)["code"], "no_rules_strict")

    def test_INV_16_same_basename_files_produce_unique_keys(self) -> None:
        """INV-16: 同名ルールファイルが複数階層に併存しても重複せず 64 文字以内の一意キーを採番する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root / "plugin.json", '{"name": "dup-test"}\n')
            targets = [
                root / "AGENTS.md",
                root / "rules" / "AGENTS.md",
                root / ".agents" / "rules" / "common.md",
                root / ".agent" / "rules" / "common.md",
                root / "_agents" / "rules" / "common.md",
                root / "_agent" / "rules" / "common.md",
                root / "rules" / "common.md",
            ]
            for path in targets:
                _write_file(path, "# Rules\n\n## Shared\n- Enforce deterministic invariant.\n")

            rules = gate.collect_rules(root, ["src/app.py"])
            self.assertEqual(len(rules), len(targets))
            keys = [r.key for r in rules]
            self.assertEqual(len(keys), len(set(keys)))
            for key in keys:
                self.assertRegex(key, run_decisions.QUESTION_KEY_RE)

    def test_INV_17_shared_skills_repo_dry_run_consistency(self) -> None:
        """INV-17: shared-skills 実構成で rules/AGENTS.md を含むルールを抽出し --dry-run ペイロードが整合する。"""
        real_root = Path(__file__).resolve().parents[3]
        self.assertTrue(gate.is_native_plugin_repo(real_root))
        discovered = gate.discover_rule_files(real_root)
        rel_discovered = [p.relative_to(real_root.resolve()).as_posix() for p in discovered]
        self.assertIn("rules/AGENTS.md", rel_discovered)

        with tempfile.TemporaryDirectory() as tmp:
            diff_file = _write_file(Path(tmp) / "change.diff", SAMPLE_DIFF)
            code, out, err = _run_cli_capture(
                [
                    "--repo-root",
                    str(real_root),
                    "--diff-file",
                    str(diff_file),
                    "--dry-run",
                    "--format",
                    "json",
                ],
                env_override={"GEMINI_API_KEY": None},
            )
        self.assertEqual(code, 0, msg=err)
        data = json.loads(out)
        self.assertEqual(data["status"], "dry_run")
        self.assertGreater(data["rule_count"], 0)
        self.assertEqual(run_decisions.validate_payload(data["payload"]), [])
        self.assertTrue(any(r["source_file"] == "rules/AGENTS.md" for r in data["rules"]))

    def test_P1_05_mask_secret_redacts_multiline_pem_and_standalone_header(self) -> None:
        """P1-05: mask_secret が複数行 PEM ブロック全体と閉じ行なし PEM ヘッダを [REDACTED] に置換する。"""
        begin_rsa = "-----BEGIN " + "RSA PRIVATE KEY-----"
        end_rsa = "-----END " + "RSA PRIVATE KEY-----"
        pem_body = "MIIEowIBAAKCAQEAv7FakeKeyBodyLine1234567890"
        pem_block = f"{begin_rsa}\n{pem_body}\n{end_rsa}"
        standalone_header = "-----BEGIN " + "OPENSSH PRIVATE KEY-----"

        masked_block = gate.mask_secret(f"error loading key:\n{pem_block}\ntrailing")
        self.assertNotIn(begin_rsa, masked_block)
        self.assertNotIn(pem_body, masked_block)
        self.assertNotIn(end_rsa, masked_block)
        self.assertIn("[REDACTED]", masked_block)
        self.assertIn("trailing", masked_block)

        masked_header = gate.mask_secret(f"truncated: {standalone_header} ABC")
        self.assertNotIn(standalone_header, masked_header)
        self.assertIn("[REDACTED]", masked_header)

    def test_P1_06_env_file_arg_blocks_and_utf8_reconfigure(self) -> None:
        """P1-06: --diff-file / --rules / --questions-file の .env 遮断と UTF-8 stdio 再構成を検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_file(root / "AGENTS.md", "# Rules\n\n## Check\n- Keep clean.\n")
            valid_diff = _write_file(root / "valid.diff", SAMPLE_DIFF)
            env_file = _write_file(root / ".env", "GEMINI_API_KEY=dummy\n")
            env_local = _write_file(root / ".env.local", "SECRET=dummy\n")
            env_example = _write_file(root / ".env.example", "GEMINI_API_KEY=\n")

            cases = [
                (["--diff-file", str(env_file)], "diff-file .env"),
                (["--diff-file", str(env_local)], "diff-file .env.local"),
                (["--diff-file", str(valid_diff), "--rules", str(env_file)], "rules .env"),
                (["--diff-file", str(valid_diff), "--questions-file", str(env_local)], "questions-file .env.local"),
            ]
            for extra_args, label in cases:
                with self.subTest(case=label):
                    code, out, _ = _run_cli_capture(
                        ["--repo-root", str(root), *extra_args, "--dry-run", "--format", "json"],
                        env_override={"GEMINI_API_KEY": None},
                    )
                    self.assertEqual(code, 2)
                    self.assertEqual(json.loads(out)["code"], "secret_env_file")

            # 雛形 .env.example は is_sensitive_env_path で遮断されない
            self.assertFalse(gate.is_sensitive_env_path(str(env_example)))
            code_ex, _, err_ex = _run_cli_capture(
                [
                    "--repo-root",
                    str(root),
                    "--diff-file",
                    str(valid_diff),
                    "--rules",
                    str(env_example),
                    "--dry-run",
                    "--format",
                    "json",
                ],
                env_override={"GEMINI_API_KEY": None},
            )
            self.assertEqual(code_ex, 0, msg=err_ex)

            # configure_utf8_stdio は reconfigure 対応ストリームへ encoding="utf-8" を呼び、StringIO では失敗しない
            fake_stream = mock.MagicMock()
            with (
                mock.patch.object(sys, "stdin", io.StringIO()),
                mock.patch.object(sys, "stdout", fake_stream),
                mock.patch.object(sys, "stderr", io.StringIO()),
            ):
                gate.configure_utf8_stdio()
            fake_stream.reconfigure.assert_called_once_with(encoding="utf-8")

            # PYTHONIOENCODING=cp932 環境でも日本語・絵文字を含むドライラン出力が文字化け/例外にならない
            import subprocess

            _write_file(root / "AGENTS.md", "# Rules\n\n## 日本語見出し 🚀\n- 日本語ルールを確認する。\n")
            env_cp932 = os.environ.copy()
            env_cp932["PYTHONIOENCODING"] = "cp932"
            env_cp932.pop("PYTHONUTF8", None)
            proc = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(Path(__file__).resolve().parent / "check_invariants_decision1.py"),
                    "--repo-root",
                    str(root),
                    "--diff-file",
                    str(valid_diff),
                    "--dry-run",
                    "--format",
                    "json",
                ],
                env=env_cp932,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, msg=proc.stderr.decode("utf-8", "replace"))
            parsed = json.loads(proc.stdout.decode("utf-8"))
            self.assertEqual(parsed["status"], "dry_run")
            self.assertIn("🚀", json.dumps(parsed, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
