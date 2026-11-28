#!/usr/bin/env python3
"""preflight_drift.py のオフライン単体テスト（PFD-01〜PFD-11）。"""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import errno
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

import preflight_drift as pfd  # noqa: E402
import screen_drift_decision1 as sdd  # noqa: E402


def _run_preflight(
    argv: list[str],
    *,
    stdin_text: str | None = None,
) -> tuple[int, str, str]:
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
        code = pfd.main(argv, stdin_text=stdin_text)
    return code, stdout_buf.getvalue(), stderr_buf.getvalue()


class PreflightScanTests(unittest.TestCase):
    def test_PFD_01_spec_id_bidirectional_matching_with_test_distinction(self) -> None:
        """PFD-01: scan が文書・コード間の仕様 ID 双方向照合をテスト除外/含む区分と file:line 付きで返す。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir()
            (root / "src").mkdir()
            (root / "tests").mkdir()

            (root / "docs" / "spec.md").write_text(
                "# Spec\n\n"
                "- REQ-01: active in prod\n"
                "- REQ-02: dead doc only\n"
                "- TST-01: only covered in test\n",
                encoding="utf-8",
            )
            (root / "src" / "app.py").write_text(
                "# REQ-01 implemented\n"
                "# REQ-03 undocumented prod id\n"
                "def ok():\n    return 1\n",
                encoding="utf-8",
            )
            (root / "tests" / "test_app.py").write_text(
                "# TST-01 verified\n"
                "# TST-02 test only id\n",
                encoding="utf-8",
            )
            (root / "src" / "ignored.py").write_text("# REQ-99 ignored\n", encoding="utf-8")

            code, out, err = _run_preflight(
                [
                    "scan",
                    "--repo",
                    str(root),
                    "--exclude-glob",
                    "src/ignored.py",
                    "--format",
                    "json",
                ]
            )
            self.assertEqual(code, 0, msg=err)
            report = json.loads(out)
            spec = report["spec_id_audit"]

            doc_only = {e["id"]: e["locations"] for e in spec["doc_only_ids"]}
            self.assertEqual(doc_only, {"REQ-02": ["docs/spec.md:4"]})

            doc_excl_tests = {e["id"]: e for e in spec["doc_only_excluding_tests"]}
            self.assertIn("REQ-02", doc_excl_tests)
            self.assertIn("TST-01", doc_excl_tests)
            self.assertEqual(doc_excl_tests["TST-01"]["test_locations"], ["tests/test_app.py:1"])

            code_excl = {e["id"]: e["non_test_locations"] for e in spec["code_only_excluding_tests"]}
            self.assertEqual(code_excl, {"REQ-03": ["src/app.py:2"]})
            self.assertNotIn("REQ-99", code_excl)

            code_incl = {e["id"]: e for e in spec["code_only_ids"]}
            self.assertIn("REQ-03", code_incl)
            self.assertIn("TST-02", code_incl)
            self.assertFalse(code_incl["REQ-03"]["is_test_only"])
            self.assertTrue(code_incl["TST-02"]["is_test_only"])

    def test_PFD_02_huge_source_files_sorted_desc_with_ast_def_count(self) -> None:
        """PFD-02: scan が閾値超えの巨大ソースファイルを降順で抽出し Python AST トップレベル定義数を数える。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "docs").mkdir()

            (root / "src" / "medium.py").write_text(
                "def f1():\n    pass\n\nasync def f2():\n    pass\n" + ("x = 1\n" * 15),
                encoding="utf-8",
            )
            (root / "src" / "large.py").write_text(
                "class A:\n    def m(self):\n        pass\n\ndef f():\n    pass\n" + ("y = 2\n" * 30),
                encoding="utf-8",
            )
            (root / "src" / "small.py").write_text("z = 1\n", encoding="utf-8")
            (root / "src" / "big.js").write_text("const a = 1;\n" * 25, encoding="utf-8")
            # Markdown 文書は巨大ソースファイル対象外
            (root / "docs" / "long.md").write_text("line\n" * 50, encoding="utf-8")

            code, out, err = _run_preflight(
                ["scan", "--repo", str(root), "--loc-threshold", "10", "--format", "json"]
            )
            self.assertEqual(code, 0, msg=err)
            huge = json.loads(out)["huge_files"]
            self.assertEqual(
                [h["file"] for h in huge],
                ["src/large.py", "src/big.js", "src/medium.py"],
            )
            self.assertEqual(huge[0]["top_level_defs"], 2)
            self.assertIsNone(huge[1]["top_level_defs"])
            self.assertEqual(huge[2]["top_level_defs"], 2)

    def test_PFD_03_sha256_duplicate_groups_ignore_empty_files(self) -> None:
        """PFD-03: scan が非空ファイルの SHA-256 重複グループのみを抽出し空ファイルを除外する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.txt").write_text("duplicate payload\n", encoding="utf-8")
            (root / "b.txt").write_text("duplicate payload\n", encoding="utf-8")
            (root / "unique.txt").write_text("unique payload\n", encoding="utf-8")
            (root / "empty1.txt").write_text("", encoding="utf-8")
            (root / "empty2.txt").write_text("", encoding="utf-8")

            code, out, err = _run_preflight(["scan", "--repo", str(root), "--format", "json"])
            self.assertEqual(code, 0, msg=err)
            groups = json.loads(out)["duplicate_groups"]
            self.assertEqual(len(groups), 1)
            self.assertEqual(groups[0]["files"], ["a.txt", "b.txt"])
            self.assertEqual(groups[0]["count"], 2)

    def test_PFD_04_missing_hints_and_binary_symlink_secret_skipped_cleanly(self) -> None:
        """PFD-04: scan が不在パス・不在フラグを集約し、バイナリ・symlink・.env をクラッシュせずスキップする。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "scripts").mkdir()
            (root / "scripts" / "cli.py").write_text(
                "import argparse\np = argparse.ArgumentParser()\np.add_argument('--repo')\n",
                encoding="utf-8",
            )
            (root / "README.md").write_text(
                "# Guide\n\n"
                "See `scripts/missing.py`.\n"
                "```bash\npython scripts/cli.py --repo . --ghost-flag\n```\n",
                encoding="utf-8",
            )
            (root / ".env").write_text("API_KEY=secret\n", encoding="utf-8")
            (root / "blob.bin").write_bytes(b"\x00\xff\xfe\x80binary")
            (root / "link.md").write_text("# symlink target\n", encoding="utf-8")

            orig_is_sym = pfd.drift_repo.is_reparse_or_symlink

            def fake_is_sym(path: Path) -> bool:
                if path.name == "link.md":
                    return True
                return orig_is_sym(path)

            # collect_repo_files が link.md を含める場合（例: Git 管理下の symlink）でも scan 側で安全にスキップする
            orig_collect = pfd.drift_repo.collect_repo_files

            def fake_collect(repo_root: Path, is_git: bool) -> list[str]:
                files = orig_collect(repo_root, is_git)
                if "link.md" not in files:
                    files = sorted([*files, "link.md"])
                return files

            with mock.patch.object(pfd.drift_repo, "is_reparse_or_symlink", side_effect=fake_is_sym), \
                 mock.patch.object(pfd.drift_repo, "collect_repo_files", side_effect=fake_collect):
                code, out, err = _run_preflight(["scan", "--repo", str(root), "--format", "json"])

            self.assertEqual(code, 0, msg=err)
            report = json.loads(out)
            self.assertEqual(report["summary"]["skipped"]["secret"], 1)
            self.assertEqual(report["summary"]["skipped"]["binary"], 1)
            self.assertEqual(report["summary"]["skipped"]["symlink"], 1)
            self.assertEqual(len(report["doc_hints"]), 1)
            self.assertEqual(report["doc_hints"][0]["file"], "README.md")
            self.assertEqual(report["doc_hints"][0]["missing_path_hints"], ["scripts/missing.py"])
            self.assertEqual(report["doc_hints"][0]["missing_flag_hints"], ["cli.py:--ghost-flag"])

            code_md, out_md, err_md = _run_preflight(
                ["scan", "--repo", str(root), "--format", "markdown"]
            )
            self.assertEqual(code_md, 0, msg=err_md)
            self.assertIn("scripts/missing.py", out_md)
            self.assertIn("cli.py:--ghost-flag", out_md)

    def test_PFD_05_candidates_json_piped_to_screen_drift_candidates(self) -> None:
        """PFD-05: scan --format candidates-json の出力を screen_drift_decision1.py candidates --stdin --dry-run へそのまま投入できる。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir()
            (root / "README.md").write_text("Broken `docs/absent.md`.\n", encoding="utf-8")
            (root / "a.txt").write_text("same\n", encoding="utf-8")
            (root / "b.txt").write_text("same\n", encoding="utf-8")

            code_scan, out_scan, err_scan = _run_preflight(
                ["scan", "--repo", str(root), "--format", "candidates-json"]
            )
            self.assertEqual(code_scan, 0, msg=err_scan)
            cands = json.loads(out_scan)
            self.assertIsInstance(cands, list)
            self.assertGreaterEqual(len(cands), 2)

            sdd_out = io.StringIO()
            sdd_err = io.StringIO()
            with redirect_stdout(sdd_out), redirect_stderr(sdd_err):
                code_sdd = sdd.main(
                    ["candidates", "--stdin", "--dry-run", "--format", "json"],
                    env={},
                    stdin_text=out_scan,
                )
            self.assertEqual(code_sdd, 0, msg=sdd_err.getvalue())
            dry_report = json.loads(sdd_out.getvalue())
            self.assertEqual(dry_report["status"], "dry_run")
            self.assertEqual(dry_report["batch_mode"], "chunk")
            self.assertEqual(dry_report["total"], len(cands))


class PlanTracksTests(unittest.TestCase):
    def test_PFD_06_plan_tracks_verdict_filtering_union_find_and_provisional_ids(self) -> None:
        """PFD-06: plan-tracks が confirmed のみを Union-Find で排他トラックへまとめ、衝突理由と仮採番衝突を報告する。"""
        plans = [
            {
                "id": "item-a",
                "verdict": "confirmed",
                "summary": "Fix A",
                "plan_path": "/tmp/a.md",
                "target_files": ["./src\\shared.py", "src/a_only.py"],
                "provisional_ids": ["P-100", "P-SHARED"],
            },
            {
                "id": "item-b",
                "verdict": "false_positive",
                "summary": "Not a bug",
                "plan_path": "/tmp/b.md",
                "target_files": ["src/shared.py"],
                "provisional_ids": ["P-IGNORED"],
            },
            {
                "id": "item-c",
                "verdict": "confirmed",
                "summary": "Fix C",
                "plan_path": "/tmp/c.md",
                "target_files": ["src/shared.py", "docs/c.md"],
                "provisional_ids": ["P-200", "P-SHARED"],
            },
            {
                "id": "item-d",
                "verdict": "already_resolved",
                "summary": "Done earlier",
                "plan_path": "/tmp/d.md",
                "target_files": [],
                "provisional_ids": [],
            },
            {
                "id": "item-e",
                "verdict": "confirmed",
                "summary": "Fix E",
                "plan_path": "/tmp/e.md",
                "target_files": ["scripts/independent.py"],
                "provisional_ids": ["P-300"],
            },
        ]

        code, out, err = _run_preflight(
            ["plan-tracks", "--stdin", "--format", "json"],
            stdin_text=json.dumps(plans),
        )
        self.assertEqual(code, 0, msg=err)
        report = json.loads(out)

        self.assertEqual(report["summary"]["confirmed"], 3)
        self.assertEqual(report["summary"]["false_positive"], 1)
        self.assertEqual(report["summary"]["already_resolved"], 1)
        self.assertEqual(report["summary"]["track_count"], 2)

        tracks = report["tracks"]
        self.assertEqual(tracks[0]["track_id"], "track_01")
        self.assertEqual(tracks[0]["item_ids"], ["item-a", "item-c"])
        self.assertEqual(
            tracks[0]["exclusive_files"],
            ["docs/c.md", "src/a_only.py", "src/shared.py"],
        )
        self.assertEqual(len(tracks[0]["conflict_reasons"]), 1)
        self.assertIn("src/shared.py", tracks[0]["conflict_reasons"][0])

        self.assertEqual(tracks[1]["track_id"], "track_02")
        self.assertEqual(tracks[1]["item_ids"], ["item-e"])
        self.assertEqual(tracks[1]["exclusive_files"], ["scripts/independent.py"])
        self.assertEqual(tracks[1]["conflict_reasons"], [])

        self.assertEqual([x["id"] for x in report["false_positive"]], ["item-b"])
        self.assertEqual([x["id"] for x in report["already_resolved"]], ["item-d"])

        collisions = report["provisional_ids"]["collisions"]
        self.assertEqual([c["id"] for c in collisions], ["P-SHARED"])
        self.assertEqual(collisions[0]["item_ids"], ["item-a", "item-c"])

        code_md, out_md, err_md = _run_preflight(
            ["plan-tracks", "--stdin", "--format", "markdown"],
            stdin_text=json.dumps(plans),
        )
        self.assertEqual(code_md, 0, msg=err_md)
        self.assertIn("track_01", out_md)
        self.assertIn("False Positive", out_md)
        self.assertIn("Already Resolved", out_md)
        self.assertIn("P-SHARED", out_md)

    def test_PFD_07_plan_tracks_rejects_env_symlink_and_secret_content(self) -> None:
        """PFD-07: plan-tracks が .env・シンボリックリンク・秘密情報含有 JSON を終了コード 2 で拒否する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env_file = root / ".env"
            env_file.write_text("[]", encoding="utf-8")
            code_env, _, err_env = _run_preflight(["plan-tracks", "--plans-json", str(env_file)])
            self.assertEqual(code_env, 2)
            self.assertIn("secret_env_file", err_env)

            plans_file = root / "plans.json"
            plans_file.write_text("[]", encoding="utf-8")
            with mock.patch.object(pfd.drift_repo, "is_reparse_or_symlink", return_value=True):
                code_sym, _, err_sym = _run_preflight(
                    ["plan-tracks", "--plans-json", str(plans_file)]
                )
            self.assertEqual(code_sym, 2)
            self.assertIn("unsafe_plans_file", err_sym)

            dummy_token = "ghp_" + ("Z" * 30)
            bad_plans = [
                {
                    "id": "x",
                    "verdict": "confirmed",
                    "summary": f"leaked {dummy_token}",
                    "target_files": ["a.py"],
                }
            ]
            code_sec, _, err_sec = _run_preflight(
                ["plan-tracks", "--stdin"],
                stdin_text=json.dumps(bad_plans),
            )
            self.assertEqual(code_sec, 2)
            self.assertIn("secret_detected", err_sec)
            self.assertNotIn(dummy_token, err_sec)

    def test_PFD_08_broken_pipe_exits_quietly_with_zero(self) -> None:
        """PFD-08: パイプ切断（BrokenPipeError / Windows EINVAL）時にエラー JSON を出さず終了コード 0 を返す。"""
        class _BrokenStream:
            def __init__(self, exc: BaseException) -> None:
                self._exc = exc

            def write(self, _text: str) -> int:
                raise self._exc

            def flush(self) -> None:
                pass

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "README.md").write_text("# Ok\n", encoding="utf-8")

            for exc in (BrokenPipeError(errno.EPIPE, "broken"), OSError(errno.EINVAL, "einval")):
                if type(exc) is OSError and os.name != "nt":
                    continue
                err_buf = io.StringIO()
                broken_stream = _BrokenStream(exc)
                with mock.patch.object(sys, "stdout", broken_stream), redirect_stderr(err_buf):
                    try:
                        code = pfd.main(["scan", "--repo", str(root), "--format", "json"])
                    finally:
                        if sys.stdout is not broken_stream and getattr(sys.stdout, "name", None) == os.devnull:
                            sys.stdout.close()
                self.assertEqual(code, 0)
                self.assertEqual(err_buf.getvalue(), "")

    def test_PFD_09_scan_masks_secret_tokens_in_hints_and_outputs(self) -> None:
        """PFD-09: scan が文書内の擬似シークレットを含む不在パス等をマスクして出力する。"""
        dummy_gh = "ghp_" + ("Z" * 30)
        dummy_ai = "AIza" + ("Y" * 28)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir()
            (root / "README.md").write_text(
                f"# Guide\n\nSee `docs/{dummy_gh}.md` and `docs/{dummy_ai}.py`.\n",
                encoding="utf-8",
            )
            for fmt in ("json", "markdown", "candidates-json"):
                code, out, err = _run_preflight(["scan", "--repo", str(root), "--format", fmt])
                self.assertEqual(code, 0, msg=err)
                self.assertNotIn(dummy_gh, out)
                self.assertNotIn(dummy_ai, out)
                self.assertIn("[REDACTED]", out)

    def test_PFD_10_test_file_classification_outside_test_dirs(self) -> None:
        """PFD-10: pkg/api_test.go や src/App.test.tsx のようなディレクトリ外テストファイルをテストとして分類する。"""
        self.assertTrue(pfd._is_test_file("pkg/api_test.go"))
        self.assertTrue(pfd._is_test_file("src/App.test.tsx"))
        self.assertTrue(pfd._is_test_file("src/auth.spec.ts"))
        self.assertFalse(pfd._is_test_file("src/app.py"))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pkg").mkdir()
            (root / "src").mkdir()
            (root / "pkg" / "api_test.go").write_text("// GO-10 test only\n", encoding="utf-8")
            (root / "src" / "App.test.tsx").write_text("// TSX-20 test only\n", encoding="utf-8")
            (root / "src" / "main.go").write_text("// GO-99 prod only\n", encoding="utf-8")

            code, out, err = _run_preflight(["scan", "--repo", str(root), "--format", "json"])
            self.assertEqual(code, 0, msg=err)
            spec = json.loads(out)["spec_id_audit"]
            by_id = {e["id"]: e for e in spec["code_only_ids"]}
            self.assertTrue(by_id["GO-10"]["is_test_only"])
            self.assertTrue(by_id["TSX-20"]["is_test_only"])
            self.assertFalse(by_id["GO-99"]["is_test_only"])

    def test_PFD_11_subprocess_broken_pipe_exits_zero(self) -> None:
        """PFD-11: 実子プロセスでパイプ読み端を早期クローズしたとき preflight_drift.py が終了コード 0 を返す。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "docs").mkdir()
            for i in range(40):
                (root / "docs" / f"doc_{i:02d}.md").write_text(
                    f"# Doc {i}\n\nSee `docs/missing_{i:02d}.md` and REQ-{i + 10:02d}.\n",
                    encoding="utf-8",
                )
            sub_env = os.environ.copy()
            sub_env["PYTHONUTF8"] = "1"
            sub_env["PYTHONIOENCODING"] = "utf-8"
            proc = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    str(_SCRIPT_DIR / "preflight_drift.py"),
                    "scan",
                    "--repo",
                    str(root),
                    "--format",
                    "markdown",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=sub_env,
            )
            assert proc.stdout is not None and proc.stderr is not None
            proc.stdout.read(1)
            proc.stdout.close()
            proc.stdout = None
            try:
                _, stderr_bytes = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                _, stderr_bytes = proc.communicate()
                raise
            self.assertEqual(proc.returncode, 0, msg=stderr_bytes.decode("utf-8", errors="replace"))
            self.assertEqual(stderr_bytes, b"")


if __name__ == "__main__":
    unittest.main()
