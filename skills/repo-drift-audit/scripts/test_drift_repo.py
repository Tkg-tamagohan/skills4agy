#!/usr/bin/env python3
"""drift_repo.py と drift_format.py のオフライン単体テスト（DRR-01〜DRR-09）。"""

from __future__ import annotations

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

import drift_format as df  # noqa: E402
import drift_repo as dr  # noqa: E402


def _init_git_repo(root: Path) -> None:
    subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=root, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Tester"], cwd=root, check=True, capture_output=True)


def _git_commit_at(root: Path, message: str, iso_date: str) -> None:
    env = os.environ.copy()
    env["GIT_AUTHOR_DATE"] = iso_date
    env["GIT_COMMITTER_DATE"] = iso_date
    subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True, env=env)
    subprocess.run(["git", "commit", "-m", message], cwd=root, check=True, capture_output=True, env=env)


class _FakePopenProc:
    def __init__(self, stdout_bytes: bytes, *, returncode: int = 0) -> None:
        self.stdout = io.BytesIO(stdout_bytes)
        self._returncode: int | None = None
        self._final_rc = returncode
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return self._returncode

    def terminate(self) -> None:
        self.terminated = True
        self._returncode = -15

    def kill(self) -> None:
        self.killed = True
        self._returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        if self._returncode is None:
            self._returncode = self._final_rc
        return self._returncode


class DriftRepoTests(unittest.TestCase):
    def test_DRR_01_staleness_bulk_matches_single_and_handles_non_git(self) -> None:
        """DRR-01: compute_staleness_days_bulk が実 Git 履歴の経過日数を単体版と一致させ、未追跡と非 Git を None にする。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "old.md").write_text("# old\n", encoding="utf-8")
            (root / "new.md").write_text("# new\n", encoding="utf-8")
            (root / "untracked.md").write_text("# untracked\n", encoding="utf-8")

            non_git_res = dr.compute_staleness_days_bulk(
                root, ["old.md", "new.md"], is_git=False, latest_commit_ts=None
            )
            self.assertEqual(non_git_res, {"old.md": None, "new.md": None})

            try:
                _init_git_repo(root)
                subprocess.run(["git", "add", "old.md"], cwd=root, check=True, capture_output=True)
                env1 = os.environ.copy()
                env1["GIT_AUTHOR_DATE"] = "2026-11-01T00:00:00Z"
                env1["GIT_COMMITTER_DATE"] = "2026-11-01T00:00:00Z"
                subprocess.run(["git", "commit", "-m", "add old"], cwd=root, check=True, capture_output=True, env=env1)

                subprocess.run(["git", "add", "new.md"], cwd=root, check=True, capture_output=True)
                env2 = os.environ.copy()
                env2["GIT_AUTHOR_DATE"] = "2026-11-11T00:00:00Z"
                env2["GIT_COMMITTER_DATE"] = "2026-11-11T00:00:00Z"
                subprocess.run(["git", "commit", "-m", "add new"], cwd=root, check=True, capture_output=True, env=env2)
            except (OSError, subprocess.CalledProcessError) as exc:
                self.skipTest(f"git unavailable for test: {exc}")

            ctx = dr.collect_repo_context(root, 5)
            bulk = dr.compute_staleness_days_bulk(
                root,
                ["old.md", "new.md", "untracked.md"],
                ctx.is_git,
                ctx.latest_commit_ts,
            )
            self.assertEqual(bulk["old.md"], 10)
            self.assertEqual(bulk["new.md"], 0)
            self.assertIsNone(bulk["untracked.md"])
            for rel in ("old.md", "new.md", "untracked.md"):
                self.assertEqual(
                    bulk[rel],
                    dr.compute_staleness_days(root, rel, ctx.is_git, ctx.latest_commit_ts),
                )

    def test_DRR_02_staleness_bulk_chunking_and_early_stop(self) -> None:
        """DRR-02: 200 件・16,000 文字上限でチャンク分割し、全対象が埋まった時点で git log を早期打ち切りする。"""
        # 205 件（200 超）と長パス（16,000 文字超）のチャンク分割を確認
        many_paths = [f"docs/doc_{i:03d}.md" for i in range(205)]
        chunks_by_count = dr._chunk_paths_for_git(many_paths)
        self.assertEqual([len(c) for c in chunks_by_count], [200, 5])

        long_paths = [f"dir_{i:02d}/" + ("x" * 190) + ".md" for i in range(100)]
        chunks_by_chars = dr._chunk_paths_for_git(long_paths)
        self.assertGreater(len(chunks_by_chars), 1)
        for ch in chunks_by_chars:
            self.assertLessEqual(len(ch), dr.BULK_STALENESS_MAX_PATHS)
            self.assertLessEqual(sum(len(p) + 1 for p in ch), dr.BULK_STALENESS_MAX_CHARS)

        # 早期打ち切り: 最初の 2 コミットで対象 2 ファイルが揃った後に続く巨大ストリーム末尾を読まず終了する
        latest_ts = 1_700_000_000 + 5 * 86400
        # 10 KB を超えるストリームを組み、8192 バイト境界後方の残りを読む前に terminate されるか確認
        padding_commits = b"".join(
            b"\x1e1690000000\x00\n" + (b"other/file.md\x00" * 50)
            for _ in range(20)
        )
        stream_bytes = (
            f"\x1e{latest_ts - 86400}\x00\ndocs/a.md\x00"
            f"\x1e{latest_ts - 3 * 86400}\x00\ndocs/b.md\x00"
        ).encode("utf-8") + padding_commits

        fake_procs: list[_FakePopenProc] = []
        recorded_cmds: list[list[str]] = []

        def fake_popen(cmd: list[str], **kwargs: object) -> _FakePopenProc:
            self.assertFalse(kwargs.get("shell"))
            recorded_cmds.append(cmd)
            proc = _FakePopenProc(stream_bytes)
            fake_procs.append(proc)
            return proc

        with mock.patch.object(dr.subprocess, "Popen", side_effect=fake_popen):
            res = dr.compute_staleness_days_bulk(
                Path("."),
                ["docs/a.md", "docs/b.md"],
                is_git=True,
                latest_commit_ts=latest_ts,
            )

        self.assertEqual(res, {"docs/a.md": 1, "docs/b.md": 3})
        self.assertEqual(len(fake_procs), 1)
        self.assertTrue(fake_procs[0].terminated)
        self.assertIn("-c", recorded_cmds[0])
        self.assertIn("core.quotePath=false", recorded_cmds[0])
        self.assertIn("--", recorded_cmds[0])

    def test_DRR_03_snapshot_round_robin_sampling_over_800_files(self) -> None:
        """DRR-03: 800 件超のファイル群でトップレベルディレクトリ別ラウンドロビン抽出と省略サマリを出力する。"""
        files: list[str] = []
        files.extend(f"root_{i:03d}.md" for i in range(300))
        files.extend(f"alpha/a_{i:03d}.py" for i in range(500))
        files.extend(f"beta/b_{i:03d}.py" for i in range(400))
        files.extend(f"gamma/g_{i:03d}.md" for i in range(50))
        files.sort()

        ctx = dr.RepoContext(
            repo_root=Path("/tmp/big-repo"),
            is_git=True,
            repo_files=files,
            repo_files_set=frozenset(files),
            top_level_dirs=frozenset({"alpha", "beta", "gamma"}),
            git_log="",
            latest_commit_ts=1_700_000_000,
        )
        snap = dr.build_repo_snapshot_text(ctx, [])
        self.assertIn("Repository Files (1250 total, showing 800 via round-robin sampling):", snap)
        self.assertIn("gamma/g_049.md", snap)
        self.assertIn("alpha/a_249.py", snap)
        self.assertNotIn("alpha/a_250.py", snap)
        self.assertIn("beta/b_249.py", snap)
        self.assertNotIn("beta/b_250.py", snap)
        self.assertIn("root_249.md", snap)
        self.assertNotIn("root_250.md", snap)
        self.assertNotIn("Omitted Files Summary: gamma/", snap)
        self.assertIn("Omitted Files Summary: ./: 50 omitted (250/300 shown)", snap)
        self.assertIn("Omitted Files Summary: alpha/: 250 omitted (250/500 shown)", snap)
        self.assertIn("Omitted Files Summary: beta/: 150 omitted (250/400 shown)", snap)

    def test_DRR_04_missing_path_hints_line_suffix_stripping(self) -> None:
        """DRR-04: パス末尾の行番号サフィックスを剥がして実在照合し、URL やドライブ文字を除外する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "src").mkdir()
            (root / "src" / "main.py").write_text("x = 1\n", encoding="utf-8")
            (root / "docs").mkdir()
            doc = root / "docs" / "ref.md"
            doc.write_text(
                "Valid [m](src/main.py:L10) and `src/main.py:10-20`.\n"
                "Missing [g](src/gone.py:L10-L20) and `src/absent.py:42`.\n"
                "Ignore `https://example.com:8443/a.py:10` and `C:\\temp\\win.py:10`.\n",
                encoding="utf-8",
            )
            ctx = dr.collect_repo_context(root, 0)
            hints = dr.extract_missing_path_hints(doc.read_text(encoding="utf-8"), "docs/ref.md", ctx)
            self.assertEqual(hints, ["src/absent.py", "src/gone.py"])

    def test_DRR_05_missing_path_hints_standalone_filenames_and_exclusions(self) -> None:
        """DRR-05: / なし単体ファイル名の実在照合とプレースホルダ・ダミー名除外を検証する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "skills" / "demo" / "scripts").mkdir(parents=True)
            (root / "skills" / "demo" / "scripts" / "real_tool.py").write_text("pass\n", encoding="utf-8")
            (root / "docs").mkdir()
            (root / "docs" / "sibling.md").write_text("# sib\n", encoding="utf-8")
            (root / "root_cfg.json").write_text("{}\n", encoding="utf-8")

            doc_text = (
                "Existing: `real_tool.py`, `sibling.md`, `root_cfg.json`.\n"
                "Missing: `ghost_worker.py`, `lost_notes.md`, `missing_cfg.yml`, `deploy.ps1`.\n"
                "Dummy/Ignore: `example.py`, `sample.md`, `foo.json`, `bar.yaml`, `test.sh`, `candidates.json`, "
                "`<name>.py`, `*.md`, `file?.py`, `unknown.xyz`.\n"
            )
            ctx = dr.collect_repo_context(root, 0)
            hints = dr.extract_missing_path_hints(doc_text, "docs/guide.md", ctx)
            self.assertEqual(
                hints,
                ["deploy.ps1", "ghost_worker.py", "lost_notes.md", "missing_cfg.yml"],
            )

    def test_DRR_06_missing_path_hints_fenced_script_lines(self) -> None:
        """DRR-06: フェンスコードブロック内のスクリプト実行行と $HOME/.../skills/ 形式を検出し、-m/-c や地の文例示は除外する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "skills" / "alpha" / "scripts").mkdir(parents=True)
            (root / "skills" / "alpha" / "scripts" / "ok.py").write_text("pass\n", encoding="utf-8")
            (root / "scripts").mkdir()
            (root / "scripts" / "helper.sh").write_text("echo ok\n", encoding="utf-8")

            doc_text = (
                "```bash\n"
                "python -B skills/alpha/scripts/ok.py --dry-run\n"
                'python "$HOME/.gemini/config/plugins/shared-skills/skills/alpha/scripts/ok.py"\n'
                'python3 "$HOME/.gemini/config/plugins/shared-skills/skills/alpha/scripts/missing_home.py" --flag\n'
                "py scripts/missing_py.py\n"
                "bash scripts/helper.sh\n"
                "sh scripts/missing_sh.sh\n"
                "pwsh scripts/missing_ps.ps1\n"
                "python -m unittest discover\n"
                'python -c "print(\'ignored.py\')"\n'
                "```\n"
                "```\n"
                "See `src/in_prose_fence.py` and [x](docs/nope.md)\n"
                "```\n"
            )
            ctx = dr.collect_repo_context(root, 0)
            hints = dr.extract_missing_path_hints(doc_text, "README.md", ctx)
            self.assertEqual(
                hints,
                [
                    "scripts/missing_ps.ps1",
                    "scripts/missing_py.py",
                    "scripts/missing_sh.sh",
                    "skills/alpha/scripts/missing_home.py",
                ],
            )

    def test_DRR_07_extract_missing_flag_hints_and_load_doc_entries_and_secret_block(self) -> None:
        """DRR-07: load_doc_entries が不在パス・不在フラグを格納し、.env と秘密情報を遮断する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "skills" / "demo" / "scripts").mkdir(parents=True)
            (root / "skills" / "demo" / "scripts" / "run.py").write_text(
                "import argparse\np = argparse.ArgumentParser()\np.add_argument('--repo')\n",
                encoding="utf-8",
            )
            skill_md = root / "skills" / "demo" / "SKILL.md"
            skill_md.write_text(
                "# Demo\n\n"
                "```bash\n"
                "python skills/demo/scripts/run.py --repo . --help --bogus-flag\n"
                "```\n"
                "See `skills/demo/scripts/gone.py`.\n",
                encoding="utf-8",
            )
            ctx = dr.collect_repo_context(root, 0)
            entries = dr.load_doc_entries(ctx, ["skills/demo/SKILL.md"])
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0].missing_path_hints, ["skills/demo/scripts/gone.py"])
            self.assertEqual(entries[0].missing_flag_hints, ["run.py:--bogus-flag"])
            self.assertIsNone(entries[0].staleness_days)

            # 秘密トークンは実行時に組み立ててリテラル直書きを回避する
            dummy_gh_token = "ghp_" + ("Z" * 28)
            secret_md = root / "skills" / "demo" / "leak.md"
            secret_md.write_text(f"token={dummy_gh_token}\n", encoding="utf-8")
            with self.assertRaises(dr.DriftScreenError) as cm:
                dr.load_doc_entries(ctx, ["skills/demo/leak.md"])
            self.assertEqual(cm.exception.code, "secret_detected")
            self.assertNotIn(dummy_gh_token, cm.exception.message)

    def test_DRR_08_symlink_reparse_guards(self) -> None:
        """DRR-08: load_doc_entries と load_facts_blocks がシンボリックリンク/リパースポイントを拒否する。"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            doc = root / "README.md"
            doc.write_text("# Hello\n", encoding="utf-8")
            facts = root / "facts.txt"
            facts.write_text("fact\n", encoding="utf-8")
            ctx = dr.collect_repo_context(root, 0)

            with mock.patch.object(dr, "is_reparse_or_symlink", return_value=True):
                with self.assertRaises(dr.DriftScreenError) as cm_doc:
                    dr.load_doc_entries(ctx, ["README.md"])
                self.assertEqual(cm_doc.exception.code, "unsafe_doc_file")

                with self.assertRaises(dr.DriftScreenError) as cm_facts:
                    dr.load_facts_blocks([str(facts)])
                self.assertEqual(cm_facts.exception.code, "unsafe_facts_file")

    def test_DRR_09_drift_format_chunks_section_flags_and_broken_pipe(self) -> None:
        """DRR-09: drift_format が chunk dry-run・backlog section・missing_flag_hints 表整形とパイプ切断処理を行う。"""
        chunk_docs_report = {
            "status": "dry_run",
            "subcommand": "docs",
            "batch_mode": "chunk",
            "total": 2,
            "chunk_count": 1,
            "chunks": [
                {
                    "chunk_index": 0,
                    "files": ["README.md", "docs/broken.md"],
                    "missing_flag_hints": ["run.py:--bad"],
                    "payload": {
                        "input": [{"type": "text", "text": "hello"}],
                        "questions": {"q1": {}, "q2": {}},
                    },
                }
            ],
        }
        docs_tbl = df.format_report_table(chunk_docs_report)
        self.assertIn("docs/broken.md", docs_tbl)
        self.assertIn("run.py:--bad", docs_tbl)
        self.assertIn("Summary: dry_run subcommand=docs total=2, batch_mode=chunk, chunk_count=1", docs_tbl)

        chunk_cand_report = {
            "status": "dry_run",
            "subcommand": "candidates",
            "batch_mode": "chunk",
            "total": 2,
            "chunk_count": 1,
            "chunks": [
                {
                    "chunk_index": 0,
                    "ids": ["C-1", "C-2"],
                    "payload": {"input": [{"type": "text", "text": "abc"}], "questions": {"q1": {}}},
                }
            ],
        }
        cand_tbl = df.format_report_table(chunk_cand_report)
        self.assertIn("C-1, C-2", cand_tbl)
        self.assertIn("batch_mode=chunk, chunk_count=1", cand_tbl)

        backlog_report = {
            "status": "completed",
            "subcommand": "backlog",
            "total": 1,
            "summary": {"needs_verification": 0, "still_open": 1},
            "results": [
                {
                    "id": "item_0001",
                    "file": "PLAN.md",
                    "line": 12,
                    "section": "Track 2 > drift_repo",
                    "status_choice": "still_open",
                    "confidence": 0.9,
                    "needs_verification": False,
                    "text": "Extract helper",
                }
            ],
        }
        bl_tbl = df.format_report_table(backlog_report)
        self.assertIn("| section |", bl_tbl)
        self.assertIn("Track 2 > drift_repo", bl_tbl)

        docs_completed = {
            "status": "completed",
            "subcommand": "docs",
            "total": 1,
            "summary": {"prioritize_for_audit": 1, "mechanization_candidate": 0, "low_priority_clean": 0},
            "results": [
                {
                    "file": "skills/demo/SKILL.md",
                    "bucket": "prioritize_for_audit",
                    "recommended_action": "plan_worker_deep_check",
                    "action_confidence": 0.91,
                    "stale_status_or_facts": 0.2,
                    "broken_or_obsolete_refs": 0.8,
                    "mechanizable_workflow": 0.1,
                    "drift_severity": 2.0,
                    "missing_path_hints": ["gone.py"],
                    "missing_flag_hints": ["run.py:--ghost"],
                }
            ],
        }
        docs_done_tbl = df.format_report_table(docs_completed)
        self.assertIn("| flag_hints |", docs_done_tbl)
        self.assertIn("run.py:--ghost", docs_done_tbl)

        class _BrokenPipeStream:
            def write(self, _text: str) -> int:
                raise BrokenPipeError(errno.EPIPE, "broken pipe")

            def flush(self) -> None:
                pass

        self.assertFalse(df.emit_report(docs_completed, "json", stream=_BrokenPipeStream()))

        dummy_api_key = "AIza" + ("X" * 28)
        err_buf = io.StringIO()
        df.emit_error(
            "api_error",
            f"failed with {dummy_api_key}",
            1,
            "json",
            dummy_api_key,
            stream=err_buf,
        )
        self.assertNotIn(dummy_api_key, err_buf.getvalue())
        self.assertIn("[REDACTED]", err_buf.getvalue())


if __name__ == "__main__":
    unittest.main()
