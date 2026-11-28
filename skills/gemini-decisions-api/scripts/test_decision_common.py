#!/usr/bin/env python3
"""decision_common.py の単体テスト（テスト ID: DC-01–DC-08）。

数値判定・抽出、usage 集計、Markdown 表セル整形、エラー出力マスク、POSIX glob 一致、およびパイプ切断時の安全な標準出力書き込みを検証する。
"""

from __future__ import annotations

import contextlib
import errno
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import decision_common as dc  # noqa: E402


class TestDecisionCommon(unittest.TestCase):
    def test_dc01_is_real_number_and_extract_number(self) -> None:
        """DC-01: is_real_number と extract_number が int/float を受理し、bool/None/非数値/非辞書を除外する。"""
        self.assertTrue(dc.is_real_number(0))
        self.assertTrue(dc.is_real_number(0.75))
        self.assertFalse(dc.is_real_number(True))
        self.assertFalse(dc.is_real_number(False))
        self.assertFalse(dc.is_real_number(None))
        self.assertFalse(dc.is_real_number("1.0"))

        self.assertEqual(dc.extract_number({"score": 2}, "score"), 2.0)
        self.assertEqual(dc.extract_number({"score": 0.5}, "score"), 0.5)
        self.assertIsNone(dc.extract_number({"score": True}, "score"))
        self.assertIsNone(dc.extract_number({"score": "0.5"}, "score"))
        self.assertIsNone(dc.extract_number({"other": 1}, "score"))
        self.assertIsNone(dc.extract_number(["not-a-dict"], "score"))

    def test_dc02_aggregate_usage_and_bool_exclusion(self) -> None:
        """DC-02: aggregate_usage が複数行のトークン数を合算し、usage 不在時は None、bool 混入時は無視する。"""
        self.assertIsNone(dc.aggregate_usage([{"id": "a"}, {"usage": None}]))

        rows = [
            {"usage": {"total_input_tokens": 100, "total_output_tokens": 20}},
            {"usage": {"total_input_tokens": True, "total_output_tokens": 5}},
            {"usage": {"total_input_tokens": 50, "total_output_tokens": False}},
        ]
        self.assertEqual(
            dc.aggregate_usage(rows),
            {
                "total_input_tokens": 150,
                "total_output_tokens": 25,
                "total_tokens": 175,
            },
        )

    def test_dc03_escape_md_cell_newlines_pipes_and_options(self) -> None:
        """DC-03: escape_md_cell が改行とパイプを整形し、empty と strip オプション通りに動作する。"""
        self.assertEqual(dc.escape_md_cell(None), "-")
        self.assertEqual(dc.escape_md_cell("   "), "-")
        self.assertEqual(dc.escape_md_cell("  a|b\r\nc\nd\re  "), "a\\|b c d e")
        self.assertEqual(dc.escape_md_cell(None, empty="", strip=False), "")
        self.assertEqual(dc.escape_md_cell("  a|b\nc  ", empty="", strip=False), "  a\\|b c  ")

    def test_dc04_emit_cli_error_masks_secrets_in_json_and_table(self) -> None:
        """DC-04: emit_cli_error が json と table の両形式で API キーとトークン実値を [REDACTED] にマスクする。"""
        api_key = "test-api-key-12345"
        dummy_cog = "cog_" + "AbCdEf0123456789_-XyZ"
        msg = f"failed key={api_key} token={dummy_cog}"

        json_buf = io.StringIO()
        dc.emit_cli_error("secret_detected", msg, 2, "json", api_key, stream=json_buf)
        parsed = json.loads(json_buf.getvalue())
        self.assertEqual(parsed["status"], "error")
        self.assertEqual(parsed["exit_code"], 2)
        self.assertEqual(parsed["code"], "secret_detected")
        self.assertNotIn(api_key, parsed["error"])
        self.assertNotIn(dummy_cog, parsed["error"])
        self.assertIn("[REDACTED]", parsed["error"])

        text_buf = io.StringIO()
        dc.emit_cli_error("secret_detected", msg, 2, "table", api_key, stream=text_buf)
        text_out = text_buf.getvalue()
        self.assertTrue(text_out.startswith("ERROR [secret_detected]: "))
        self.assertNotIn(api_key, text_out)
        self.assertNotIn(dummy_cog, text_out)
        self.assertIn("[REDACTED]", text_out)

    def test_dc05_normalize_and_glob_match(self) -> None:
        """DC-05: normalize_posix_rel_path、glob_to_regex、glob_match が **・*・? と区切りを正しく判定する。"""
        self.assertEqual(dc.normalize_posix_rel_path(r"  .\src\a\b.py  "), "src/a/b.py")
        self.assertEqual(dc.normalize_posix_rel_path("././foo.md"), "foo.md")

        self.assertTrue(dc.glob_match("b.py", "**/*.py"))
        self.assertTrue(dc.glob_match(r".\src\a\b.py", "src/**/*.py"))
        self.assertTrue(dc.glob_match("src/b.py", "src/**/*.py"))
        self.assertFalse(dc.glob_match("/b.py", "**/*.py"))
        self.assertFalse(dc.glob_match("src//b.py", "src/**/*.py"))

        self.assertTrue(dc.glob_match("src/ab.py", "src/a?.py"))
        self.assertFalse(dc.glob_match("src/abc.py", "src/a?.py"))
        self.assertFalse(dc.glob_match("src/a/b.py", "src/*.py"))

    def test_dc06_is_broken_pipe_error(self) -> None:
        """DC-06: is_broken_pipe_error が BrokenPipeError、EPIPE、Windows EINVAL を判定し EACCES を除外する。"""
        self.assertTrue(dc.is_broken_pipe_error(BrokenPipeError("broken pipe")))
        self.assertTrue(dc.is_broken_pipe_error(OSError(errno.EPIPE, "epipe")))
        self.assertFalse(dc.is_broken_pipe_error(OSError(errno.EACCES, "eacces")))
        self.assertFalse(dc.is_broken_pipe_error(ValueError("not os error")))

        win_einval = OSError(errno.EINVAL, "invalid argument")
        with mock.patch.object(dc.os, "name", "nt"):
            self.assertTrue(dc.is_broken_pipe_error(win_einval))
            self.assertFalse(dc.is_broken_pipe_error(PermissionError(errno.EINVAL, "subclass")))
            self.assertFalse(dc.is_broken_pipe_error(OSError(errno.EACCES, "eacces")))

        with mock.patch.object(dc.os, "name", "posix"):
            self.assertFalse(dc.is_broken_pipe_error(win_einval))
            self.assertTrue(dc.is_broken_pipe_error(OSError(errno.EPIPE, "epipe")))

    def test_dc07_safe_write_stdout_normal_and_errors(self) -> None:
        """DC-07: safe_write_stdout が通常書き込み・改行補完・flush とパイプ切断抑止・EACCES 再送出を正しく行う。"""
        class _RecordingStream:
            def __init__(self, *, write_exc: BaseException | None = None, flush_exc: BaseException | None = None):
                self.chunks: list[str] = []
                self.flushed = 0
                self._write_exc = write_exc
                self._flush_exc = flush_exc

            def write(self, data: str) -> int:
                if self._write_exc is not None:
                    raise self._write_exc
                self.chunks.append(data)
                return len(data)

            def flush(self) -> None:
                if self._flush_exc is not None:
                    raise self._flush_exc
                self.flushed += 1

        ok_stream = _RecordingStream()
        self.assertTrue(dc.safe_write_stdout("hello", stream=ok_stream))
        self.assertEqual(ok_stream.chunks, ["hello\n"])
        self.assertEqual(ok_stream.flushed, 1)

        self.assertTrue(dc.safe_write_stdout("already\n", stream=ok_stream))
        self.assertTrue(dc.safe_write_stdout("no_nl", stream=ok_stream, ensure_newline=False))
        self.assertEqual(ok_stream.chunks, ["hello\n", "already\n", "no_nl"])
        self.assertEqual(ok_stream.flushed, 3)

        stdout_buf = _RecordingStream()
        with contextlib.redirect_stdout(stdout_buf):  # type: ignore[arg-type]
            self.assertTrue(dc.safe_write_stdout("via_stdout"))
        self.assertEqual(stdout_buf.chunks, ["via_stdout\n"])
        self.assertEqual(stdout_buf.flushed, 1)

        self.assertFalse(dc.safe_write_stdout("x", stream=_RecordingStream(write_exc=BrokenPipeError())))
        self.assertFalse(
            dc.safe_write_stdout("x", stream=_RecordingStream(flush_exc=OSError(errno.EPIPE, "epipe")))
        )
        with mock.patch.object(dc.os, "name", "nt"):
            self.assertFalse(
                dc.safe_write_stdout("x", stream=_RecordingStream(flush_exc=OSError(errno.EINVAL, "einval")))
            )

        with self.assertRaises(OSError) as ctx:
            dc.safe_write_stdout("x", stream=_RecordingStream(write_exc=OSError(errno.EACCES, "denied")))
        self.assertEqual(ctx.exception.errno, errno.EACCES)

    def test_dc08_glob_rejects_trailing_newline(self) -> None:
        """DC-08: glob_to_regex が \\Z 終端を使い、末尾改行付きパスを拒否して通常パスを許容する。"""
        self.assertIsNone(dc.glob_to_regex("*.md").match("guide.md\n"))
        self.assertFalse(dc.glob_match("docs/guide.md\n", "docs/**/*.md"))
        self.assertTrue(dc.glob_match("docs/guide.md", "docs/**/*.md"))


if __name__ == "__main__":
    unittest.main()
