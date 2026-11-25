#!/usr/bin/env python3
"""pr_ops.py の単体テスト。

4 サブコマンド（status / invariant-check / apply-triage / commit-push）の
正常系、秘密情報遮断、U+FFFD / BOM 拒否、保護ブランチ拒否、GraphQL ページネーション、
事後検証失敗、ローカル git リポジトリ連携を外部ネットワークなしで検証する。
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

import pr_ops  # noqa: E402


def _run_cli_capture(argv: list[str], *, runner=None) -> tuple[int, str, str]:
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    with mock.patch.object(sys, "stdout", stdout_buf), mock.patch.object(sys, "stderr", stderr_buf):
        code = pr_ops.main(argv, runner=runner or pr_ops._default_runner)
    return code, stdout_buf.getvalue(), stderr_buf.getvalue()


def _init_git_repo_with_bare_remote(base_dir: Path, branch: str = "feat/demo") -> tuple[Path, Path]:
    bare = base_dir / "origin.git"
    work = base_dir / "work"
    subprocess.run(["git", "init", "--bare", str(bare)], check=True, capture_output=True)
    subprocess.run(["git", "init", str(work)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(work), "config", "user.name", "Test User"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(work), "config", "user.email", "test@example.com"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(work), "remote", "add", "origin", str(bare)], check=True, capture_output=True)
    (work / "README.md").write_text("init\n", encoding="utf-8", newline="\n")
    subprocess.run(["git", "-C", str(work), "add", "README.md"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(work), "commit", "-m", "initial"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(work), "branch", "-M", "main"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(work), "push", "-u", "origin", "main"], check=True, capture_output=True)
    if branch != "main":
        subprocess.run(["git", "-C", str(work), "checkout", "-b", branch], check=True, capture_output=True)
    return work, bare


class TestPrOpsStatus(unittest.TestCase):
    def test_status_pagination_guardrails_devin_and_save_files(self) -> None:
        calls: list[tuple[list[str], str | None]] = []

        def fake_runner(cmd: list[str], cwd: Path, input_text: str | None) -> pr_ops.CmdResult:
            calls.append((cmd, input_text))
            if cmd[:4] == ["git", "remote", "get-url", "origin"]:
                return pr_ops.CmdResult(0, "https://github.com/octo/repo.git\n", "")
            if cmd[:3] == ["gh", "pr", "view"]:
                pr_view = {
                    "number": 12,
                    "url": "https://github.com/octo/repo/pull/12",
                    "title": "PR title",
                    "state": "OPEN",
                    "headRefName": "feat/x",
                    "headRefOid": "abcdef1234567890",
                    "baseRefName": "main",
                    "body": "PR body",
                    "comments": [
                        {
                            "id": "IC_1",
                            "author": {"login": "bot"},
                            "createdAt": "2026-11-25T00:00:00Z",
                            "body": (
                                "<!-- pr-review-triage:guardrails:v1 -->\n"
                                "## 再発防止策（PR 内引き継ぎ）\n\n"
                                "- [PRG-001] (active) 対象: `skills/**` | ルール: BOM なし UTF-8 を使う\n"
                                "<!-- /pr-review-triage:guardrails:v1 -->"
                            ),
                        }
                    ],
                    "reviews": [],
                    "statusCheckRollup": [
                        {"name": "ci-summary", "status": "COMPLETED", "conclusion": "SUCCESS"},
                        {"name": "lint", "status": "IN_PROGRESS", "conclusion": ""},
                    ],
                }
                return pr_ops.CmdResult(0, json.dumps(pr_view, ensure_ascii=False), "")
            if cmd[:3] == ["gh", "api", "graphql"]:
                payload = json.loads(input_text or "{}")
                cursor = (payload.get("variables") or {}).get("cursor")
                if cursor is None:
                    page1 = {
                        "data": {
                            "repository": {
                                "pullRequest": {
                                    "headRefOid": "abcdef1234567890",
                                    "reviewThreads": {
                                        "pageInfo": {"hasNextPage": True, "endCursor": "CUR_1"},
                                        "nodes": [
                                            {
                                                "id": "PRRT_thread001",
                                                "isResolved": False,
                                                "isOutdated": False,
                                                "path": "a.py",
                                                "line": 10,
                                                "originalLine": 10,
                                                "comments": {"nodes": [{"id": "c1", "author": {"login": "devin"}, "body": "指摘1", "createdAt": "2026-11-25T01:00:00Z", "url": "https://example/1"}]},
                                            }
                                        ],
                                    },
                                }
                            }
                        }
                    }
                    return pr_ops.CmdResult(0, json.dumps(page1, ensure_ascii=False), "")
                page2 = {
                    "data": {
                        "repository": {
                            "pullRequest": {
                                "headRefOid": "abcdef1234567890",
                                "reviewThreads": {
                                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                                    "nodes": [
                                        {
                                            "id": "PRRT_thread002",
                                            "isResolved": True,
                                            "isOutdated": False,
                                            "path": "b.py",
                                            "line": 20,
                                            "originalLine": 20,
                                            "comments": {"nodes": []},
                                        }
                                    ],
                                },
                            }
                        }
                    }
                }
                return pr_ops.CmdResult(0, json.dumps(page2, ensure_ascii=False), "")
            if len(cmd) >= 2 and cmd[1].endswith("check_devin_review.py"):
                return pr_ops.CmdResult(
                    0,
                    json.dumps({"decision": "completed", "can_conclude_clean": True}),
                    "",
                )
            raise AssertionError(f"Unexpected command: {cmd}")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            out_file = tmp_dir / "status.json"
            pr_file = tmp_dir / "pr.json"
            code, stdout, stderr = _run_cli_capture(
                [
                    "status",
                    "--pr",
                    "12",
                    "--cwd",
                    tmp,
                    "--check-devin",
                    "--output",
                    str(out_file),
                    "--save-pr-json",
                    str(pr_file),
                ],
                runner=fake_runner,
            )
            self.assertEqual(code, 0, stderr)
            data = json.loads(stdout)
            self.assertEqual(data["repo"], "octo/repo")
            self.assertEqual(data["review_threads"]["total"], 2)
            self.assertEqual(data["review_threads"]["unresolved_count"], 1)
            self.assertEqual(data["checks"]["passing_count"], 1)
            self.assertEqual(data["checks"]["pending_count"], 1)
            self.assertEqual(data["guardrails"]["active_count"], 1)
            self.assertEqual(data["devin_review"]["decision"], "completed")
            self.assertTrue(out_file.exists())
            self.assertTrue(pr_file.exists())
            self.assertFalse(out_file.read_bytes().startswith(b"\xef\xbb\xbf"))


class TestPrOpsInvariantCheck(unittest.TestCase):
    def test_invariant_check_writes_rules_md_and_propagates_exit_code(self) -> None:
        observed_rules_text = ""

        def fake_runner(cmd: list[str], cwd: Path, input_text: str | None) -> pr_ops.CmdResult:
            nonlocal observed_rules_text
            if len(cmd) >= 2 and cmd[1].endswith("check_invariants_decision1.py"):
                rules_idx = cmd.index("--rules")
                rules_path = Path(cmd[rules_idx + 1])
                observed_rules_text = rules_path.read_text(encoding="utf-8")
                return pr_ops.CmdResult(0, json.dumps({"violations": []}), "")
            raise AssertionError(f"Unexpected command: {cmd}")

        with tempfile.TemporaryDirectory() as tmp:
            pr_json = Path(tmp) / "pr.json"
            pr_json.write_text(
                json.dumps(
                    {
                        "body": "",
                        "comments": [
                            {
                                "author": {"login": "bot"},
                                "createdAt": "2026-11-25T00:00:00Z",
                                "body": (
                                    "<!-- pr-review-triage:guardrails:v1 -->\n"
                                    "## 再発防止策（PR 内引き継ぎ）\n\n"
                                    "- [PRG-001] (active) 対象: `skills/**` | ルール: UTF-8 BOM を禁止する\n"
                                    "<!-- /pr-review-triage:guardrails:v1 -->"
                                ),
                            }
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            code, stdout, stderr = _run_cli_capture(
                ["invariant-check", "--pr-json", str(pr_json), "--cwd", tmp, "--dry-run"],
                runner=fake_runner,
            )
            self.assertEqual(code, 0, stderr)
            self.assertIn("UTF-8 BOM を禁止する", observed_rules_text)
            self.assertIn('"violations"', stdout)


class TestPrOpsApplyTriage(unittest.TestCase):
    def test_apply_triage_dry_run_replaces_placeholders_and_never_mutates(self) -> None:
        calls: list[list[str]] = []

        def fake_runner(cmd: list[str], cwd: Path, input_text: str | None) -> pr_ops.CmdResult:
            calls.append(cmd)
            if cmd[:4] == ["git", "remote", "get-url", "origin"]:
                return pr_ops.CmdResult(0, "git@github.com:octo/repo.git\n", "")
            if cmd[:3] == ["gh", "pr", "view"]:
                return pr_ops.CmdResult(0, json.dumps({"body": "", "comments": [], "reviews": []}), "")
            raise AssertionError(f"Dry-run must not mutate: {cmd}")

        with tempfile.TemporaryDirectory() as tmp:
            plan_path = Path(tmp) / "plan.json"
            plan_path.write_text(
                json.dumps(
                    {
                        "replies": [
                            {
                                "thread_id": "PRRT_12345678",
                                "body": "コミット {{COMMIT_SHORT}} ({{COMMIT_SHA}}) で修正しました。",
                                "resolve": True,
                            }
                        ],
                        "summary_comment": "対応コミット: <次コミットハッシュ>",
                        "guardrail_items": [
                            {"scope": "scripts/**", "rule": "秘密検査を必須にする", "evidence": "commit {{COMMIT_SHORT}}"}
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            code, stdout, stderr = _run_cli_capture(
                [
                    "apply-triage",
                    "--pr",
                    "6",
                    "--cwd",
                    tmp,
                    "--plan",
                    str(plan_path),
                    "--commit-sha",
                    "1234567890abcdef",
                    "--dry-run",
                ],
                runner=fake_runner,
            )
            self.assertEqual(code, 0, stderr)
            out = json.loads(stdout)
            self.assertTrue(out["dry_run"])
            self.assertIn("1234567 (1234567890abcdef)", out["replies"][0]["body"])
            self.assertIn("対応コミット: 1234567", out["summary_preview"])
            self.assertIn("<!-- pr-review-triage:guardrails:v1 -->", out["summary_preview"])
            self.assertEqual(len(calls), 2)

    def test_apply_triage_executes_mutations_and_verifies(self) -> None:
        mutations: list[str] = []
        posted_summary = ""

        def fake_runner(cmd: list[str], cwd: Path, input_text: str | None) -> pr_ops.CmdResult:
            nonlocal posted_summary
            if cmd[:4] == ["git", "remote", "get-url", "origin"]:
                return pr_ops.CmdResult(0, "https://github.com/octo/repo.git\n", "")
            if cmd[:3] == ["gh", "pr", "view"]:
                return pr_ops.CmdResult(
                    0,
                    json.dumps(
                        {
                            "body": "",
                            "comments": [{"author": {"login": "me"}, "createdAt": "2026-11-25T02:00:00Z", "body": posted_summary}]
                            if posted_summary
                            else [],
                            "reviews": [],
                        },
                        ensure_ascii=False,
                    ),
                    "",
                )
            if cmd[:3] == ["gh", "pr", "comment"]:
                bf_idx = cmd.index("--body-file")
                posted_summary = Path(cmd[bf_idx + 1]).read_text(encoding="utf-8")
                return pr_ops.CmdResult(0, "https://github.com/octo/repo/pull/6#issuecomment-1\n", "")
            if cmd[:3] == ["gh", "api", "graphql"]:
                payload = json.loads(input_text or "{}")
                query = payload.get("query") or ""
                if "addPullRequestReviewThreadReply" in query:
                    mutations.append("reply")
                    return pr_ops.CmdResult(0, json.dumps({"data": {"addPullRequestReviewThreadReply": {"comment": {"id": "C1"}}}}), "")
                if "resolveReviewThread" in query:
                    mutations.append("resolve")
                    return pr_ops.CmdResult(0, json.dumps({"data": {"resolveReviewThread": {"thread": {"id": "PRRT_12345678", "isResolved": True}}}}), "")
                if "reviewThreads" in query:
                    return pr_ops.CmdResult(
                        0,
                        json.dumps(
                            {
                                "data": {
                                    "repository": {
                                        "pullRequest": {
                                            "headRefOid": "1234567890abcdef",
                                            "reviewThreads": {
                                                "pageInfo": {"hasNextPage": False, "endCursor": None},
                                                "nodes": [{"id": "PRRT_12345678", "isResolved": True, "isOutdated": False, "comments": {"nodes": []}}],
                                            },
                                        }
                                    }
                                }
                            }
                        ),
                        "",
                    )
            raise AssertionError(f"Unexpected command: {cmd}")

        with tempfile.TemporaryDirectory() as tmp:
            plan_path = Path(tmp) / "plan.json"
            plan_path.write_text(
                json.dumps(
                    {
                        "replies": [{"thread_id": "PRRT_12345678", "body": "修正済み {{COMMIT_SHORT}}", "resolve": True}],
                        "summary_comment": "テスト結果: 全通過",
                        "guardrail_items": [{"scope": "scripts/**", "rule": "入力検証を維持する", "evidence": "commit {{COMMIT_SHORT}}"}],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            code, stdout, stderr = _run_cli_capture(
                [
                    "apply-triage",
                    "--pr",
                    "6",
                    "--cwd",
                    tmp,
                    "--plan",
                    str(plan_path),
                    "--commit-sha",
                    "1234567890abcdef",
                ],
                runner=fake_runner,
            )
            self.assertEqual(code, 0, stderr)
            out = json.loads(stdout)
            self.assertEqual(mutations, ["reply", "resolve"])
            self.assertTrue(out["summary_posted"])
            self.assertEqual(out["verification"]["unresolved_count"], 0)
            self.assertTrue(out["verification"]["commit_sha_match"])
            self.assertTrue(out["verification"]["guardrails_strict_ok"])

    def test_apply_triage_blocks_secrets_ufffd_bom_and_unresolved_placeholders(self) -> None:
        def fail_runner(cmd: list[str], cwd: Path, input_text: str | None) -> pr_ops.CmdResult:
            raise AssertionError(f"Validation failure must not invoke commands: {cmd}")

        fake_gh_token = "ghp_" + "A" * 36
        fake_bearer = "Bearer " + "TokenValue1234567890"

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)

            secret_plan = tmp_dir / "secret.json"
            secret_plan.write_text(
                json.dumps({"replies": [{"thread_id": "PRRT_12345678", "body": f"leak {fake_gh_token}"}]}, ensure_ascii=False),
                encoding="utf-8",
            )
            code, _, err = _run_cli_capture(
                ["apply-triage", "--pr", "6", "--cwd", tmp, "--plan", str(secret_plan)],
                runner=fail_runner,
            )
            self.assertEqual(code, 2)
            self.assertNotIn(fake_gh_token, err)

            bearer_plan = tmp_dir / "bearer.json"
            bearer_plan.write_text(
                json.dumps({"summary_comment": f"auth: {fake_bearer}"}, ensure_ascii=False),
                encoding="utf-8",
            )
            code, _, err = _run_cli_capture(
                ["apply-triage", "--pr", "6", "--cwd", tmp, "--plan", str(bearer_plan)],
                runner=fail_runner,
            )
            self.assertEqual(code, 2)
            self.assertNotIn("TokenValue1234567890", err)

            ufffd_plan = tmp_dir / "ufffd.json"
            ufffd_plan.write_text(
                json.dumps({"summary_comment": "文字化け \ufffd あり"}, ensure_ascii=False),
                encoding="utf-8",
            )
            code, _, _ = _run_cli_capture(
                ["apply-triage", "--pr", "6", "--cwd", tmp, "--plan", str(ufffd_plan)],
                runner=fail_runner,
            )
            self.assertEqual(code, 2)

            bom_plan = tmp_dir / "bom.json"
            bom_plan.write_bytes(b"\xef\xbb\xbf" + b'{"summary_comment": "ok"}')
            code, _, _ = _run_cli_capture(
                ["apply-triage", "--pr", "6", "--cwd", tmp, "--plan", str(bom_plan)],
                runner=fail_runner,
            )
            self.assertEqual(code, 2)

            placeholder_plan = tmp_dir / "ph.json"
            placeholder_plan.write_text(
                json.dumps({"summary_comment": "commit <次コミットハッシュ>"}, ensure_ascii=False),
                encoding="utf-8",
            )
            code, _, _ = _run_cli_capture(
                ["apply-triage", "--pr", "6", "--cwd", tmp, "--plan", str(placeholder_plan)],
                runner=fail_runner,
            )
            self.assertEqual(code, 2)

            # シンボリックリンク / リパースポイント拒否（Windows 権限非依存でモック検証）
            symlink_plan = tmp_dir / "link.json"
            symlink_plan.write_text(json.dumps({"summary_comment": "ok"}), encoding="utf-8")
            with mock.patch.object(pr_ops, "_is_reparse_or_symlink", return_value=True):
                code, _, _ = _run_cli_capture(
                    ["apply-triage", "--pr", "6", "--cwd", tmp, "--plan", str(symlink_plan)],
                    runner=fail_runner,
                )
            self.assertEqual(code, 2)

    def test_apply_triage_verify_failure_returns_exit_1(self) -> None:
        def fake_runner(cmd: list[str], cwd: Path, input_text: str | None) -> pr_ops.CmdResult:
            if cmd[:4] == ["git", "remote", "get-url", "origin"]:
                return pr_ops.CmdResult(0, "https://github.com/octo/repo.git\n", "")
            if cmd[:3] == ["gh", "pr", "view"]:
                return pr_ops.CmdResult(0, json.dumps({"body": "", "comments": [], "reviews": []}), "")
            if cmd[:3] == ["gh", "pr", "comment"]:
                return pr_ops.CmdResult(0, "https://github.com/octo/repo/pull/6#issuecomment-1\n", "")
            if cmd[:3] == ["gh", "api", "graphql"]:
                return pr_ops.CmdResult(
                    0,
                    json.dumps(
                        {
                            "data": {
                                "repository": {
                                    "pullRequest": {
                                        "headRefOid": "9999999999999999",
                                        "reviewThreads": {
                                            "pageInfo": {"hasNextPage": False, "endCursor": None},
                                            "nodes": [],
                                        },
                                    }
                                }
                            }
                        }
                    ),
                    "",
                )
            raise AssertionError(f"Unexpected command: {cmd}")

        with tempfile.TemporaryDirectory() as tmp:
            plan_path = Path(tmp) / "plan.json"
            plan_path.write_text(
                json.dumps({"summary_comment": "commit {{COMMIT_SHORT}}"}, ensure_ascii=False),
                encoding="utf-8",
            )
            code, stdout, _ = _run_cli_capture(
                [
                    "apply-triage",
                    "--pr",
                    "6",
                    "--cwd",
                    tmp,
                    "--plan",
                    str(plan_path),
                    "--commit-sha",
                    "1234567890abcdef",
                ],
                runner=fake_runner,
            )
            self.assertEqual(code, 1)
            out = json.loads(stdout)
            self.assertFalse(out["ok"])
            self.assertFalse(out["verification"]["commit_sha_match"])


class TestPrOpsCommitPush(unittest.TestCase):
    def test_commit_push_real_git_repo_success_and_guards(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            work, bare = _init_git_repo_with_bare_remote(tmp_dir, branch="feat/pr-ops-test")
            target_file = work / "hello.txt"
            target_file.write_text("hello world\n", encoding="utf-8", newline="\n")
            msg_file = tmp_dir / "commit_msg.txt"
            msg_file.write_text("feat: add hello\n", encoding="utf-8", newline="\n")

            code, stdout, stderr = _run_cli_capture(
                [
                    "commit-push",
                    "--cwd",
                    str(work),
                    "--files",
                    "hello.txt",
                    "--message-file",
                    str(msg_file),
                    "-u",
                ]
            )
            self.assertEqual(code, 0, stderr)
            out = json.loads(stdout)
            self.assertTrue(out["pushed"])
            self.assertEqual(out["branch"], "feat/pr-ops-test")

            remote_sha = subprocess.run(
                ["git", "--git-dir", str(bare), "rev-parse", "refs/heads/feat/pr-ops-test"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            self.assertEqual(remote_sha, out["commit_sha"])

            # 保護ブランチ main での commit-push は拒否
            subprocess.run(["git", "-C", str(work), "checkout", "main"], check=True, capture_output=True)
            (work / "bad.txt").write_text("x\n", encoding="utf-8")
            code, _, _ = _run_cli_capture(
                [
                    "commit-push",
                    "--cwd",
                    str(work),
                    "--files",
                    "bad.txt",
                    "--message-file",
                    str(msg_file),
                ]
            )
            self.assertEqual(code, 2)

            # 危険なパス指定（., -A, .env, id_rsa, ワイルドカード）および非 origin は拒否
            subprocess.run(["git", "-C", str(work), "checkout", "feat/pr-ops-test"], check=True, capture_output=True)
            for bad_files in ([".",], ["--files=-A"], [".env"], ["id_rsa"], ["*.py"]):
                argv_files = bad_files if bad_files[0].startswith("--files=") else ["--files", *bad_files]
                code, _, _ = _run_cli_capture(
                    [
                        "commit-push",
                        "--cwd",
                        str(work),
                        *argv_files,
                        "--message-file",
                        str(msg_file),
                    ]
                )
                self.assertEqual(code, 2, f"Expected reject for files={bad_files}")

            # detached HEAD は拒否
            subprocess.run(["git", "-C", str(work), "checkout", "--detach"], check=True, capture_output=True)
            code, _, _ = _run_cli_capture(
                [
                    "commit-push",
                    "--cwd",
                    str(work),
                    "--files",
                    "hello.txt",
                    "--message-file",
                    str(msg_file),
                ]
            )
            self.assertEqual(code, 2)
            subprocess.run(["git", "-C", str(work), "checkout", "feat/pr-ops-test"], check=True, capture_output=True)

            code, _, _ = _run_cli_capture(
                [
                    "commit-push",
                    "--cwd",
                    str(work),
                    "--files",
                    "hello.txt",
                    "--message-file",
                    str(msg_file),
                    "--remote",
                    "upstream",
                ]
            )
            self.assertEqual(code, 2)

            # 秘密トークンを含むファイルはステージング前に遮断
            secret_file = work / "leak.txt"
            secret_file.write_text("token=" + ("sk-" + "B" * 24) + "\n", encoding="utf-8")
            code, _, _ = _run_cli_capture(
                [
                    "commit-push",
                    "--cwd",
                    str(work),
                    "--files",
                    "leak.txt",
                    "--message-file",
                    str(msg_file),
                ]
            )
            self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
