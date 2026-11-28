#!/usr/bin/env python3
"""Decision 1 系 CLI 群で共有する数値判定、usage 集計、Markdown 整形、エラー出力、glob 補助モジュール。

外部依存を持たず Python 標準ライブラリのみで動作する。
"""

from __future__ import annotations

from collections.abc import Iterable
import errno
import json
import os
import re
import sys
from typing import Any

import decision_hygiene


def is_real_number(val: Any) -> bool:
    """bool を除外して int または float かどうかを判定する。"""
    return isinstance(val, (int, float)) and not isinstance(val, bool)


def extract_number(mapping: Any, key: str) -> float | None:
    """辞書から指定キーの数値を float として取り出し、非数値や bool なら None を返す。"""
    if not isinstance(mapping, dict):
        return None
    val = mapping.get(key)
    if is_real_number(val):
        return float(val)
    return None


def aggregate_usage(rows: Iterable[dict[str, Any]]) -> dict[str, int] | None:
    """結果行群の usage 辞書を合算し、1 件も usage がなければ None を返す。"""
    has_usage = False
    in_total = 0
    out_total = 0
    for row in rows:
        usage = row.get("usage")
        if isinstance(usage, dict):
            has_usage = True
            if is_real_number(usage.get("total_input_tokens")):
                in_total += int(usage["total_input_tokens"])
            if is_real_number(usage.get("total_output_tokens")):
                out_total += int(usage["total_output_tokens"])
    if not has_usage:
        return None
    return {
        "total_input_tokens": in_total,
        "total_output_tokens": out_total,
        "total_tokens": in_total + out_total,
    }


def escape_md_cell(value: Any, *, empty: str = "-", strip: bool = True) -> str:
    """Markdown 表セル向けに改行の空白化とパイプ記号のエスケープを行う。"""
    if value is None:
        return empty
    text = str(value).replace("\r\n", " ").replace("\r", " ").replace("\n", " ").replace("|", "\\|")
    if strip:
        text = text.strip()
    return text if text else empty


def emit_cli_error(
    code: str,
    message: str,
    exit_code: int,
    output_format: str,
    api_key: str,
    *,
    stream: Any = None,
) -> None:
    """秘密情報をマスクした上で JSON またはプレーンテキスト形式のエラーを出力する。"""
    target = sys.stderr if stream is None else stream
    safe_msg = decision_hygiene.mask_secret(message, api_key)
    if output_format == "json":
        err_obj = {
            "status": "error",
            "exit_code": exit_code,
            "code": code,
            "error": safe_msg,
        }
        print(json.dumps(err_obj, ensure_ascii=False, indent=2), file=target)
    else:
        print(f"ERROR [{code}]: {safe_msg}", file=target)


def normalize_posix_rel_path(path_str: str) -> str:
    """バックスラッシュをスラッシュへ揃え、先頭の ./ を除いた相対パス文字列を返す。"""
    norm = path_str.replace("\\", "/").strip(" ")
    while norm.startswith("./"):
        norm = norm[2:]
    return norm


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """POSIX 形式の glob パターン（** 対応）を正規表現へ変換する。"""
    pat = normalize_posix_rel_path(pattern)
    parts: list[str] = ["^"]
    i = 0
    n = len(pat)
    while i < n:
        if pat[i : i + 3] == "**/":
            parts.append("(?:.+/)?")
            i += 3
        elif pat[i : i + 2] == "**":
            parts.append(".*")
            i += 2
        elif pat[i] == "*":
            parts.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            parts.append("[^/]")
            i += 1
        else:
            parts.append(re.escape(pat[i]))
            i += 1
    parts.append(r"\Z")
    return re.compile("".join(parts))


def glob_match(path_str: str, pattern: str) -> bool:
    """正規化済み POSIX 相対パスに対して ** を含む glob 一致判定を行う。"""
    return bool(glob_to_regex(pattern).match(normalize_posix_rel_path(path_str)))


def is_broken_pipe_error(exc: BaseException) -> bool:
    """パイプ切断（BrokenPipeError / EPIPE / Windows の EINVAL）を示す例外か判定する。"""
    return (
        isinstance(exc, BrokenPipeError)
        or (isinstance(exc, OSError) and exc.errno == errno.EPIPE)
        or (os.name == "nt" and type(exc) is OSError and exc.errno == errno.EINVAL)
    )


def safe_write_stdout(
    text: str,
    *,
    stream: Any = None,
    ensure_newline: bool = True,
) -> bool:
    """標準出力（または指定ストリーム）へ書き込み、パイプ切断時のみ False を返す。"""
    target = sys.stdout if stream is None else stream
    if target is None:
        return False
    output = text if (not ensure_newline or text.endswith("\n")) else f"{text}\n"
    try:
        target.write(output)
        target.flush()
    except OSError as exc:
        if is_broken_pipe_error(exc):
            return False
        raise
    return True
