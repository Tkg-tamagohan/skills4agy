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

    def test_status_resolves_omitted_pr_masks_secrets_propagates_devin_exit_and_detects_truncation(self) -> None:
        observed_pr_cmds: list[list[str]] = []
        fake_gh_token = "ghp_" + "Z" * 36

        def make_runner(*, devin_code: int = 0, comments_has_next: bool = False):
            def fake_runner(cmd: list[str], cwd: Path, input_text: str | None) -> pr_ops.CmdResult:
                if cmd[:4] == ["git", "remote", "get-url", "origin"]:
                    return pr_ops.CmdResult(0, "https://github.com/octo/repo.git\n", "")
                if cmd[:3] == ["git", "branch", "--show-current"]:
                    return pr_ops.CmdResult(0, "feat/current\n", "")
                if cmd[:3] == ["gh", "pr", "view"]:
                    observed_pr_cmds.append(cmd)
                    if "--json" in cmd and cmd[cmd.index("--json") + 1] in {"number", "number,url"}:
                        return pr_ops.CmdResult(
                            0,
                            json.dumps({"number": 77, "url": "https://github.com/upstream/repo/pull/77"}),
                            "",
                        )
                    return pr_ops.CmdResult(
                        0,
                        json.dumps(
                            {
                                "number": 77,
                                "url": "https://github.com/octo/repo/pull/77",
                                "title": f"title {fake_gh_token}",
                                "state": "OPEN",
                                "headRefName": "feat/current",
                                "headRefOid": "1234567890abcdef",
                                "baseRefName": "main",
                                "body": f"body {fake_gh_token}",
                                "comments": [],
                                "reviews": [],
                                "statusCheckRollup": [],
                            }
                        ),
                        "",
                    )
                if cmd[:3] == ["gh", "api", "graphql"]:
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
                                                "nodes": [
                                                    {
                                                        "id": "PRRT_thread1234",
                                                        "isResolved": False,
                                                        "isOutdated": False,
                                                        "path": "a.py",
                                                        "line": 1,
                                                        "originalLine": 1,
                                                        "comments": {
                                                            "pageInfo": {"hasNextPage": comments_has_next},
                                                            "nodes": [
                                                                {
                                                                    "id": "C1",
                                                                    "author": {"login": "bot"},
                                                                    "body": f"token leak {fake_gh_token}",
                                                                    "createdAt": "2026-11-25T00:00:00Z",
                                                                    "url": "https://example/1",
                                                                }
                                                            ],
                                                        },
                                                    }
                                                ],
                                            },
                                        }
                                    }
                                }
                            }
                        ),
                        "",
                    )
                if len(cmd) >= 2 and cmd[1].endswith("check_devin_review.py"):
                    return pr_ops.CmdResult(devin_code, json.dumps({"decision": "auth_error"}), "")
                raise AssertionError(f"Unexpected command: {cmd}")

            return fake_runner

        with tempfile.TemporaryDirectory() as tmp:
            pr_file = Path(tmp) / "saved_pr.json"
            # --pr と --repo を両方省略時は `gh pr view --json number,url` の repo/number を一致させて使い、秘密マスク＋終了コード伝播を検証
            code, stdout, _ = _run_cli_capture(
                ["status", "--cwd", tmp, "--check-devin", "--save-pr-json", str(pr_file)],
                runner=make_runner(devin_code=3),
            )
            self.assertEqual(code, 3)
            self.assertEqual(observed_pr_cmds[0], ["gh", "pr", "view", "--json", "number,url"])
            self.assertEqual(json.loads(stdout)["repo"], "upstream/repo")
            self.assertNotIn(fake_gh_token, stdout)
            self.assertIn("[REDACTED]", stdout)
            self.assertNotIn(fake_gh_token, pr_file.read_text(encoding="utf-8"))

            # --repo 明示・--pr 省略時は現在ブランチ名を selector に渡す
            observed_pr_cmds.clear()
            code, _, _ = _run_cli_capture(
                ["status", "--repo", "octo/repo", "--cwd", tmp],
                runner=make_runner(devin_code=0),
            )
            self.assertEqual(code, 0)
            self.assertEqual(
                observed_pr_cmds[0],
                ["gh", "pr", "view", "feat/current", "--repo", "octo/repo", "--json", "number"],
            )

            # comments.pageInfo.hasNextPage == True はサイレント打ち切りせずエラー終了 (code=2)
            code, _, _ = _run_cli_capture(
                ["status", "--pr", "77", "--cwd", tmp],
                runner=make_runner(comments_has_next=True),
            )
            self.assertEqual(code, 2)


class TestPrOpsInvariantCheck(unittest.TestCase):
    def test_invariant_check_writes_rules_md_and_propagates_exit_code(self) -> None:
        observed_rules_text = ""
        observed_cmd: list[str] = []

        def fake_runner(cmd: list[str], cwd: Path, input_text: str | None) -> pr_ops.CmdResult:
            nonlocal observed_rules_text, observed_cmd
            if cmd[:4] == ["git", "-c", "core.quotePath=false", "status"]:
                return pr_ops.CmdResult(0, "", "")
            if cmd[:3] == ["git", "rev-parse", "--show-toplevel"]:
                return pr_ops.CmdResult(0, str(cwd), "")
            if cmd[:3] == ["git", "rev-parse", "--verify"]:
                return pr_ops.CmdResult(0, "deadbeef1234567890abcdef1234567890abcdef\n", "")
            if len(cmd) >= 2 and cmd[1].endswith("check_invariants_decision1.py"):
                observed_cmd = list(cmd)
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
            self.assertEqual(observed_cmd.count("--rules"), 1)

    def test_invariant_check_includes_worktree_diff_and_combines_multiple_rules(self) -> None:
        observed_cmd: list[str] = []
        observed_diff = ""

        def fake_runner(cmd: list[str], cwd: Path, input_text: str | None) -> pr_ops.CmdResult:
            nonlocal observed_cmd, observed_diff
            if cmd[:3] == ["git", "rev-parse", "--show-toplevel"]:
                return pr_ops.CmdResult(0, str(cwd), "")
            if cmd[:3] == ["git", "rev-parse", "--verify"]:
                return pr_ops.CmdResult(0, "deadbeef1234567890abcdef1234567890abcdef\n", "")
            if cmd[:4] == ["git", "-c", "core.quotePath=false", "status"]:
                return pr_ops.CmdResult(0, " M app.py\n", "")
            if cmd[:2] == ["git", "merge-base"]:
                return pr_ops.CmdResult(0, "base123\n", "")
            if cmd[:4] == ["git", "-c", "core.quotePath=false", "diff"]:
                return pr_ops.CmdResult(0, "diff --git a/app.py b/app.py\n+print('uncommitted')\n", "")
            if cmd[:4] == ["git", "-c", "core.quotePath=false", "ls-files"]:
                return pr_ops.CmdResult(0, "", "")
            if len(cmd) >= 2 and cmd[1].endswith("check_invariants_decision1.py"):
                observed_cmd = list(cmd)
                df_idx = cmd.index("--diff-file")
                observed_diff = Path(cmd[df_idx + 1]).read_text(encoding="utf-8")
                return pr_ops.CmdResult(0, json.dumps({"violations": []}), "")
            raise AssertionError(f"Unexpected command: {cmd}")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            pr_json = tmp_dir / "pr.json"
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
                                    "- [PRG-001] (active) 対象: `**` | ルール: 例外を握りつぶさない\n"
                                    "<!-- /pr-review-triage:guardrails:v1 -->"
                                ),
                            }
                        ],
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            rule1 = tmp_dir / "r1.md"
            rule2 = tmp_dir / "r2.md"
            rule1.write_text("# R1\n", encoding="utf-8")
            rule2.write_text("# R2\n", encoding="utf-8")
            code, _, stderr = _run_cli_capture(
                [
                    "invariant-check",
                    "--pr-json",
                    str(pr_json),
                    "--cwd",
                    tmp,
                    "--rules",
                    "r1.md",
                    "--rules",
                    "r2.md",
                    "--dry-run",
                ],
                runner=fake_runner,
            )
            self.assertEqual(code, 0, stderr)
            self.assertIn("--diff-file", observed_cmd)
            self.assertIn("uncommitted", observed_diff)
            self.assertEqual(observed_cmd.count("--rules"), 1)
            r_idx = observed_cmd.index("--rules")
            self.assertEqual(len(observed_cmd[r_idx + 1 : r_idx + 4]), 3)

    def test_invariant_check_real_git_untracked_subdir_reverted_and_base_flag_injection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            work, _ = _init_git_repo_with_bare_remote(tmp_dir, branch="feat/inv-worktree")
            (work / "sub").mkdir()
            (work / "sibling.py").write_text("sibling = 1\n", encoding="utf-8", newline="\n")
            subprocess.run(["git", "-C", str(work), "add", "sibling.py"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(work), "commit", "-m", "add sibling"], check=True, capture_output=True)

            # 1. --base への Git オプション注入は拒否
            pr_json = tmp_dir / "pr.json"
            pr_json.write_text(json.dumps({"body": "", "comments": []}), encoding="utf-8")
            code, _, _ = _run_cli_capture(
                ["invariant-check", "--pr-json", str(pr_json), "--cwd", str(work), "--base=--output=evil.txt", "--dry-run"]
            )
            self.assertEqual(code, 2)

            # 2. サブディレクトリ実行でも兄弟ファイルの変更＋未追跡新規ファイルが統合 --diff-file へ含まれ、ロックファイルは除外される
            (work / "sibling.py").write_text("sibling = 2\n", encoding="utf-8", newline="\n")
            (work / "Cargo.lock").write_text("lock = 1\n", encoding="utf-8", newline="\n")
            (work / "sub" / "untracked_new.py").write_text("x = 42\n", encoding="utf-8", newline="\n")
            captured_diff = ""

            def inspect_runner(cmd: list[str], cwd: Path, input_text: str | None) -> pr_ops.CmdResult:
                nonlocal captured_diff
                if len(cmd) >= 2 and cmd[1].endswith("check_invariants_decision1.py"):
                    self.assertIn("--diff-file", cmd)
                    captured_diff = Path(cmd[cmd.index("--diff-file") + 1]).read_text(encoding="utf-8")
                    return pr_ops.CmdResult(0, json.dumps({"status": "dry_run"}), "")
                return pr_ops._default_runner(cmd, cwd, input_text)

            code, _, stderr = _run_cli_capture(
                ["invariant-check", "--pr-json", str(pr_json), "--cwd", str(work / "sub"), "--base", "main", "--dry-run"],
                runner=inspect_runner,
            )
            self.assertEqual(code, 0, stderr)
            self.assertIn("sibling.py", captured_diff)
            self.assertIn("sub/untracked_new.py", captured_diff)
            self.assertIn("+x = 42", captured_diff)
            self.assertNotIn("Cargo.lock", captured_diff)

            # 3. コミット済み変更を作業ツリーで打ち消して空差分にしたときは --base へ戻らず空 --diff-file を渡す
            (work / "Cargo.lock").unlink()
            (work / "sub" / "untracked_new.py").unlink()
            (work / "sibling.py").unlink()
            # main の内容から sibling.py を削除状態にし、untracked なしで未コミット差分が空でない状態ではなく
            # 実際に「commit した変更を作業ツリーで元に戻す」ケースを作る
            subprocess.run(["git", "-C", str(work), "checkout", "--", "sibling.py"], check=True, capture_output=True)
            (work / "temp_commit.txt").write_text("v1\n", encoding="utf-8", newline="\n")
            subprocess.run(["git", "-C", str(work), "add", "temp_commit.txt"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(work), "commit", "-m", "temp commit"], check=True, capture_output=True)
            # 1 コミット前（main + sibling）を base にして、作業ツリーで temp_commit.txt を消した状態にする
            prev_sha = subprocess.run(
                ["git", "-C", str(work), "rev-parse", "HEAD~1"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            (work / "temp_commit.txt").unlink()
            reverted_diff = "NOT_SET"

            def reverted_runner(cmd: list[str], cwd: Path, input_text: str | None) -> pr_ops.CmdResult:
                nonlocal reverted_diff
                if len(cmd) >= 2 and cmd[1].endswith("check_invariants_decision1.py"):
                    self.assertIn("--diff-file", cmd)
                    self.assertNotIn("--base", cmd)
                    reverted_diff = Path(cmd[cmd.index("--diff-file") + 1]).read_text(encoding="utf-8")
                    return pr_ops.CmdResult(0, json.dumps({"status": "skipped_empty_diff"}), "")
                return pr_ops._default_runner(cmd, cwd, input_text)

            code, _, stderr = _run_cli_capture(
                ["invariant-check", "--pr-json", str(pr_json), "--cwd", str(work), "--base", prev_sha, "--dry-run"],
                runner=reverted_runner,
            )
            self.assertEqual(code, 0, stderr)
            self.assertEqual(reverted_diff.strip(), "")

            # 4. status.showUntrackedFiles=no でも未追跡新規ファイル・先頭空白ファイル・2MiB超スキップ警告を検証
            subprocess.run(["git", "-C", str(work), "checkout", "--", "temp_commit.txt"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(work), "config", "status.showUntrackedFiles", "no"], check=True, capture_output=True)
            (work / " leading_space.py").write_text("lead = 1\n", encoding="utf-8", newline="\n")
            (work / "oversize.txt").write_bytes(b"a" * (pr_ops.MAX_FILE_SECRET_SCAN_BYTES + 10))
            captured_untracked = ""

            def untracked_runner(cmd: list[str], cwd: Path, input_text: str | None) -> pr_ops.CmdResult:
                nonlocal captured_untracked
                if len(cmd) >= 2 and cmd[1].endswith("check_invariants_decision1.py"):
                    captured_untracked = Path(cmd[cmd.index("--diff-file") + 1]).read_text(encoding="utf-8")
                    return pr_ops.CmdResult(0, json.dumps({"status": "dry_run"}), "")
                return pr_ops._default_runner(cmd, cwd, input_text)

            code, _, err_untracked = _run_cli_capture(
                ["invariant-check", "--pr-json", str(pr_json), "--cwd", str(work), "--base", prev_sha, "--dry-run"],
                runner=untracked_runner,
            )
            self.assertEqual(code, 0, err_untracked)
            self.assertIn(" leading_space.py", captured_untracked)
            self.assertIn("oversize.txt (exceeds_2MiB_limit)", err_untracked)
            (work / " leading_space.py").unlink()
            (work / "oversize.txt").unlink()
            subprocess.run(["git", "-C", str(work), "config", "--unset", "status.showUntrackedFiles"], check=True, capture_output=True)

            # 5. 削除をコミット済みのファイルを元と同じ内容で作り直した場合は削除・追加の重複が出ない
            (work / "recreated.py").write_text("orig = 1\n", encoding="utf-8", newline="\n")
            subprocess.run(["git", "-C", str(work), "add", "recreated.py"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(work), "commit", "-m", "add recreated"], check=True, capture_output=True)
            base_with_rec = subprocess.run(
                ["git", "-C", str(work), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            subprocess.run(["git", "-C", str(work), "rm", "recreated.py"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(work), "commit", "-m", "rm recreated"], check=True, capture_output=True)
            (work / "recreated.py").write_text("orig = 1\n", encoding="utf-8", newline="\n")
            rec_same_diff = "NOT_SET"

            def rec_runner(cmd: list[str], cwd: Path, input_text: str | None) -> pr_ops.CmdResult:
                nonlocal rec_same_diff
                if len(cmd) >= 2 and cmd[1].endswith("check_invariants_decision1.py"):
                    rec_same_diff = Path(cmd[cmd.index("--diff-file") + 1]).read_text(encoding="utf-8")
                    return pr_ops.CmdResult(0, json.dumps({"status": "skipped_empty_diff"}), "")
                return pr_ops._default_runner(cmd, cwd, input_text)

            code, _, stderr = _run_cli_capture(
                ["invariant-check", "--pr-json", str(pr_json), "--cwd", str(work), "--base", base_with_rec, "--dry-run"],
                runner=rec_runner,
            )
            self.assertEqual(code, 0, stderr)
            self.assertEqual(rec_same_diff.strip(), "")

            # 内容が変わった場合は削除＋新規ではなく通常の変更 diff になる
            (work / "recreated.py").write_text("orig = 2\n", encoding="utf-8", newline="\n")
            code, _, stderr = _run_cli_capture(
                ["invariant-check", "--pr-json", str(pr_json), "--cwd", str(work), "--base", base_with_rec, "--dry-run"],
                runner=rec_runner,
            )
            self.assertEqual(code, 0, stderr)
            self.assertNotIn("deleted file mode", rec_same_diff)
            self.assertNotIn("new file mode", rec_same_diff)
            self.assertIn("+orig = 2", rec_same_diff)
            (work / "recreated.py").unlink()

            # 6. _release など有効な Git ブランチ名を --base に指定して --committed-only 有無とも動作する
            subprocess.run(["git", "-C", str(work), "branch", "_release", base_with_rec], check=True, capture_output=True)
            for extra in ([], ["--committed-only"]):
                code, _, stderr = _run_cli_capture(
                    ["invariant-check", "--pr-json", str(pr_json), "--cwd", str(work), "--base", "_release", *extra, "--dry-run"],
                    runner=lambda c, cw, inp: (
                        pr_ops.CmdResult(0, json.dumps({"status": "dry_run"}), "")
                        if len(c) >= 2 and c[1].endswith("check_invariants_decision1.py")
                        else pr_ops._default_runner(c, cw, inp)
                    ),
                )
                self.assertEqual(code, 0, stderr)


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
                            "headRefOid": "1234567890abcdef",
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
        gql_calls = 0

        def fake_runner(cmd: list[str], cwd: Path, input_text: str | None) -> pr_ops.CmdResult:
            nonlocal gql_calls
            if cmd[:4] == ["git", "remote", "get-url", "origin"]:
                return pr_ops.CmdResult(0, "https://github.com/octo/repo.git\n", "")
            if cmd[:3] == ["gh", "pr", "view"]:
                return pr_ops.CmdResult(
                    0,
                    json.dumps({"headRefOid": "1234567890abcdef", "body": "", "comments": [], "reviews": []}),
                    "",
                )
            if cmd[:3] == ["gh", "pr", "comment"]:
                return pr_ops.CmdResult(0, "https://github.com/octo/repo/pull/6#issuecomment-1\n", "")
            if cmd[:3] == ["gh", "api", "graphql"]:
                gql_calls += 1
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

    def test_apply_triage_blocks_pre_write_sha_mismatch_and_foreign_thread(self) -> None:
        mutations_called = 0

        def make_runner(remote_head: str, thread_ids: list[str]):
            def fake_runner(cmd: list[str], cwd: Path, input_text: str | None) -> pr_ops.CmdResult:
                nonlocal mutations_called
                if cmd[:4] == ["git", "remote", "get-url", "origin"]:
                    return pr_ops.CmdResult(0, "https://github.com/octo/repo.git\n", "")
                if cmd[:3] == ["gh", "pr", "view"]:
                    return pr_ops.CmdResult(
                        0,
                        json.dumps({"headRefOid": remote_head, "body": "", "comments": [], "reviews": []}),
                        "",
                    )
                if cmd[:3] == ["gh", "api", "graphql"]:
                    payload = json.loads(input_text or "{}")
                    q = payload.get("query") or ""
                    if "reviewThreads" in q:
                        return pr_ops.CmdResult(
                            0,
                            json.dumps(
                                {
                                    "data": {
                                        "repository": {
                                            "pullRequest": {
                                                "headRefOid": remote_head,
                                                "reviewThreads": {
                                                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                                                    "nodes": [
                                                        {"id": tid, "isResolved": False, "isOutdated": False, "comments": {"nodes": []}}
                                                        for tid in thread_ids
                                                    ],
                                                },
                                            }
                                        }
                                    }
                                }
                            ),
                            "",
                        )
                    mutations_called += 1
                    raise AssertionError(f"Mutation must not run before pre-checks: {q}")
                if cmd[:3] == ["gh", "pr", "comment"]:
                    mutations_called += 1
                    raise AssertionError("Comment must not run before pre-checks")
                raise AssertionError(f"Unexpected command: {cmd}")

            return fake_runner

        with tempfile.TemporaryDirectory() as tmp:
            plan_path = Path(tmp) / "plan.json"
            plan_path.write_text(
                json.dumps(
                    {
                        "replies": [{"thread_id": "PRRT_foreign_1234", "body": "fix {{COMMIT_SHORT}}", "resolve": True}],
                        "summary_comment": "done {{COMMIT_SHA}}",
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            # 1. リモート HEAD 不一致なら書き込みゼロで終了コード 2
            code, _, _ = _run_cli_capture(
                ["apply-triage", "--pr", "6", "--cwd", tmp, "--plan", str(plan_path), "--commit-sha", "1234567"],
                runner=make_runner("9999999999abcdef1234567890abcdef12345678", ["PRRT_foreign_1234"]),
            )
            self.assertEqual(code, 2)
            self.assertEqual(mutations_called, 0)

            # 2. リモート HEAD 一致でも別 PR のスレッド ID が含まれるなら書き込みゼロで終了コード 2
            code, _, _ = _run_cli_capture(
                ["apply-triage", "--pr", "6", "--cwd", tmp, "--plan", str(plan_path), "--commit-sha", "1234567"],
                runner=make_runner("1234567890abcdef1234567890abcdef12345678", ["PRRT_belongs_to_pr6"]),
            )
            self.assertEqual(code, 2)
            self.assertEqual(mutations_called, 0)

            # 3. 短縮 SHA 指定で一致かつ所属一致時はフル SHA へ正規化されて展開される
            code, stdout, stderr = _run_cli_capture(
                ["apply-triage", "--pr", "6", "--cwd", tmp, "--plan", str(plan_path), "--commit-sha", "1234567", "--dry-run"],
                runner=make_runner("1234567890abcdef1234567890abcdef12345678", ["PRRT_foreign_1234"]),
            )
            self.assertEqual(code, 0, stderr)
            out = json.loads(stdout)
            self.assertEqual(out["commit_sha"], "1234567890abcdef1234567890abcdef12345678")
            self.assertIn("1234567890abcdef1234567890abcdef12345678", out["summary_preview"])

    def test_apply_triage_membership_check_uses_id_only_query_without_comment_limit(self) -> None:
        def fake_runner(cmd: list[str], cwd: Path, input_text: str | None) -> pr_ops.CmdResult:
            if cmd[:4] == ["git", "remote", "get-url", "origin"]:
                return pr_ops.CmdResult(0, "https://github.com/octo/repo.git\n", "")
            if cmd[:3] == ["gh", "pr", "view"]:
                return pr_ops.CmdResult(
                    0,
                    json.dumps({"headRefOid": "1234567890abcdef1234567890abcdef12345678", "body": "", "comments": [], "reviews": []}),
                    "",
                )
            if cmd[:3] == ["gh", "api", "graphql"]:
                payload = json.loads(input_text or "{}")
                q = payload.get("query") or ""
                if "reviewThreads" in q:
                    # 事前所属確認クエリには comments フィールドが含まれないこと
                    self.assertNotIn("comments(", q)
                    return pr_ops.CmdResult(
                        0,
                        json.dumps(
                            {
                                "data": {
                                    "repository": {
                                        "pullRequest": {
                                            "headRefOid": "1234567890abcdef1234567890abcdef12345678",
                                            "reviewThreads": {
                                                "pageInfo": {"hasNextPage": False, "endCursor": None},
                                                "nodes": [{"id": "PRRT_target_1234"}],
                                            },
                                        }
                                    }
                                }
                            }
                        ),
                        "",
                    )
                if "resolveReviewThread" in q:
                    return pr_ops.CmdResult(0, json.dumps({"data": {"resolveReviewThread": {"thread": {"id": "PRRT_target_1234", "isResolved": True}}}}), "")
            raise AssertionError(f"Unexpected command: {cmd}")

        with tempfile.TemporaryDirectory() as tmp:
            plan_path = Path(tmp) / "plan.json"
            plan_path.write_text(json.dumps({"resolve_only": ["PRRT_target_1234"]}), encoding="utf-8")
            code, stdout, stderr = _run_cli_capture(
                ["apply-triage", "--pr", "6", "--cwd", tmp, "--plan", str(plan_path), "--no-verify"],
                runner=fake_runner,
            )
            self.assertEqual(code, 0, stderr)
            self.assertTrue(json.loads(stdout)["ok"])

    def test_apply_triage_fork_fallback_resolves_origin_pr_when_implicit_gh_fails(self) -> None:
        observed_cmds: list[list[str]] = []

        def fake_runner(cmd: list[str], cwd: Path, input_text: str | None) -> pr_ops.CmdResult:
            observed_cmds.append(cmd)
            if cmd[:3] == ["gh", "pr", "view"] and "--repo" not in cmd:
                return pr_ops.CmdResult(1, "", "no pull requests found for branch")
            if cmd[:4] == ["git", "remote", "get-url", "origin"]:
                return pr_ops.CmdResult(0, "https://github.com/fork-user/repo.git\n", "")
            if cmd[:3] == ["git", "branch", "--show-current"]:
                return pr_ops.CmdResult(0, "feat/shared-name\n", "")
            if cmd[:3] == ["gh", "pr", "view"] and "--repo" in cmd:
                if "number" == cmd[cmd.index("--json") + 1]:
                    return pr_ops.CmdResult(0, json.dumps({"number": 88}), "")
                return pr_ops.CmdResult(
                    0,
                    json.dumps(
                        {
                            "headRefOid": "1234567890abcdef1234567890abcdef12345678",
                            "body": "",
                            "comments": [],
                            "reviews": [],
                        }
                    ),
                    "",
                )
            if cmd[:3] == ["gh", "api", "graphql"]:
                payload = json.loads(input_text or "{}")
                q = payload.get("query") or ""
                if "reviewThreads" in q:
                    self.assertEqual(payload["variables"]["owner"], "fork-user")
                    self.assertEqual(payload["variables"]["number"], 88)
                    return pr_ops.CmdResult(
                        0,
                        json.dumps(
                            {
                                "data": {
                                    "repository": {
                                        "pullRequest": {
                                            "headRefOid": "1234567890abcdef1234567890abcdef12345678",
                                            "reviewThreads": {
                                                "pageInfo": {"hasNextPage": False, "endCursor": None},
                                                "nodes": [{"id": "PRRT_fork_1234"}],
                                            },
                                        }
                                    }
                                }
                            }
                        ),
                        "",
                    )
                if "resolveReviewThread" in q:
                    return pr_ops.CmdResult(0, json.dumps({"data": {"resolveReviewThread": {"thread": {"id": "PRRT_fork_1234", "isResolved": True}}}}), "")
            raise AssertionError(f"Unexpected command: {cmd}")

        with tempfile.TemporaryDirectory() as tmp:
            plan_path = Path(tmp) / "plan.json"
            plan_path.write_text(json.dumps({"resolve_only": ["PRRT_fork_1234"]}), encoding="utf-8")
            code, stdout, stderr = _run_cli_capture(
                ["apply-triage", "--cwd", tmp, "--plan", str(plan_path), "--no-verify"],
                runner=fake_runner,
            )
            self.assertEqual(code, 0, stderr)
            out = json.loads(stdout)
            self.assertEqual(out["repo"], "fork-user/repo")
            self.assertEqual(out["pr_number"], 88)
            self.assertIn(
                ["gh", "pr", "view", "feat/shared-name", "--repo", "fork-user/repo", "--json", "number"],
                observed_cmds,
            )


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

            # 指定外のファイルが事前ステージされている場合は停止し、既存インデックスを変更しない
            unrelated = work / "unrelated.txt"
            unrelated.write_text("unrelated\n", encoding="utf-8")
            (work / "fix.txt").write_text("fix\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(work), "add", "unrelated.txt"], check=True, capture_output=True)
            code, _, _ = _run_cli_capture(
                [
                    "commit-push",
                    "--cwd",
                    str(work),
                    "--files",
                    "fix.txt",
                    "--message-file",
                    str(msg_file),
                ]
            )
            self.assertEqual(code, 2)
            staged_after = subprocess.run(
                ["git", "-C", str(work), "diff", "--cached", "--name-only"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.splitlines()
            self.assertEqual(staged_after, ["unrelated.txt"])
            subprocess.run(["git", "-C", str(work), "reset", "HEAD", "unrelated.txt"], check=True, capture_output=True)

            # origin/HEAD が独自名の既定ブランチを指す場合は直接 push を拒否
            subprocess.run(["git", "-C", str(work), "checkout", "-b", "trunk-custom"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(work), "push", "-u", "origin", "trunk-custom"], check=True, capture_output=True)
            subprocess.run(
                ["git", "-C", str(work), "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/trunk-custom"],
                check=True,
                capture_output=True,
            )
            code, _, _ = _run_cli_capture(
                [
                    "commit-push",
                    "--cwd",
                    str(work),
                    "--files",
                    "fix.txt",
                    "--message-file",
                    str(msg_file),
                ]
            )
            self.assertEqual(code, 2)

            # 相対 --cwd 指定時でも --message-file が二重パス連結されず成功する
            subprocess.run(["git", "-C", str(work), "checkout", "feat/pr-ops-test"], check=True, capture_output=True)
            (work / "rel_msg.txt").write_text("feat: relative cwd test\n", encoding="utf-8", newline="\n")
            prev_cwd = os.getcwd()
            try:
                os.chdir(tmp_dir)
                code, stdout, stderr = _run_cli_capture(
                    [
                        "commit-push",
                        "--cwd",
                        "work",
                        "--files",
                        "fix.txt",
                        "--message-file",
                        "rel_msg.txt",
                        "--no-push",
                    ]
                )
            finally:
                os.chdir(prev_cwd)
            self.assertEqual(code, 0, stderr)
            self.assertTrue(json.loads(stdout)["ok"])

            # サブディレクトリから実行しても、同サブディレクトリ内でステージ済みファイルをコミットでき、リネーム旧パス漏れは拒否する
            (work / "app").mkdir()
            (work / "app" / "handler.py").write_text("h = 1\n", encoding="utf-8", newline="\n")
            (work / "app" / "msg.txt").write_text("feat: subdir commit\n", encoding="utf-8", newline="\n")
            subprocess.run(["git", "-C", str(work), "add", "app/handler.py"], check=True, capture_output=True)
            code, stdout, stderr = _run_cli_capture(
                [
                    "commit-push",
                    "--cwd",
                    str(work / "app"),
                    "--files",
                    "handler.py",
                    "--message-file",
                    "msg.txt",
                    "--no-push",
                ]
            )
            self.assertEqual(code, 0, stderr)
            self.assertTrue(json.loads(stdout)["ok"])

            # ステージ済みリネーム (old_name.txt -> new_name.txt) で新パスのみ指定すると旧パス欠落として拒否
            (work / "old_name.txt").write_text("rename test content line 1\nline 2\n", encoding="utf-8", newline="\n")
            subprocess.run(["git", "-C", str(work), "add", "old_name.txt"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(work), "commit", "-m", "add old_name"], check=True, capture_output=True)
            subprocess.run(["git", "-C", str(work), "mv", "old_name.txt", "new_name.txt"], check=True, capture_output=True)
            code, _, _ = _run_cli_capture(
                [
                    "commit-push",
                    "--cwd",
                    str(work),
                    "--files",
                    "new_name.txt",
                    "--message-file",
                    str(msg_file),
                    "--no-push",
                ]
            )
            self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
