#!/usr/bin/env python3
"""argparse 定義と Markdown 文書記載の CLI ロングフラグ突合ヘルパ。

`repo-drift-audit` と `plugin-authoring/scripts/audit_skills_weekly.py` の双方から
共有される決定論的チェックを提供する。Python 標準ライブラリのみで動作する。
"""

from __future__ import annotations

import ast
from collections import defaultdict
from collections.abc import Iterable
import os
from pathlib import Path
import re
import stat

FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})")
LONG_FLAG_RE = re.compile(r"(?<![A-Za-z0-9_-])(--[a-z][a-z0-9-]{1,})")
BACKTICK_PATH_RE = re.compile(r"`([^`\n]+)`")


def _is_reparse_or_symlink(path: Path) -> bool:
    """シンボリックリンクまたは Windows リパースポイントかどうかを判定する。"""
    if os.path.islink(path):
        return True
    try:
        st = os.lstat(path)
    except OSError:
        return True
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attrs & reparse_flag)


def extract_argparse_flags(py_path: Path) -> set[str]:
    """Python スクリプトの AST から add_argument で定義された --flag を抽出する。"""
    if _is_reparse_or_symlink(py_path):
        return set()
    try:
        source = py_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(py_path))
    except (OSError, SyntaxError):
        return set()

    flags: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            attr_name = (
                func.attr
                if isinstance(func, ast.Attribute)
                else (func.id if isinstance(func, ast.Name) else "")
            )
            if attr_name != "add_argument":
                continue
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if arg.value.startswith("--") and len(arg.value) > 2:
                        flags.add(arg.value)
    return flags


def strip_quoted_arg_values(text: str) -> str:
    """フラグ値（例: --command "git push --force"）内部の誤検出を防ぐためクォート内を除去する。"""
    cleaned = re.sub(r'"[^"\n]*"', '""', text)
    cleaned = re.sub(r"'[^'\n]*'", "''", cleaned)
    return cleaned


def extract_doc_flags_from_lines(
    lines: Iterable[str],
    script_names: set[str],
    flags_by_script: dict[str, set[str]] | None = None,
) -> dict[str, set[str]]:
    """Markdown 行列からスクリプト呼び出しに紐づく --flag 記載をスクリプト単位で抽出する。"""
    target_map: dict[str, set[str]] = (
        flags_by_script if flags_by_script is not None else defaultdict(set)
    )
    if not script_names:
        return dict(target_map)

    ordered_names = sorted(script_names, key=lambda s: (-len(s), s))
    name_patterns: list[tuple[str, re.Pattern[str]]] = [
        (
            sn,
            re.compile(r"(?<![A-Za-z0-9_.-])" + re.escape(sn) + r"(?![A-Za-z0-9_.-])"),
        )
        for sn in ordered_names
    ]

    def detect_scripts(text: str) -> list[str]:
        return [sn for sn, rx in name_patterns if rx.search(text)]

    in_fence = False
    fence_char = ""
    fence_len = 0
    block_buf: list[str] = []

    for line in lines:
        fence_match = FENCE_RE.match(line)
        if fence_match:
            marker = fence_match.group(1)
            if not in_fence:
                in_fence = True
                fence_char = marker[0]
                fence_len = len(marker)
                continue
            if marker[0] == fence_char and len(marker) >= fence_len:
                block_text = "\n".join(block_buf)
                if detect_scripts(block_text):
                    active_script: str | None = None
                    for b_line in block_buf:
                        stripped = b_line.strip()
                        if not stripped or stripped.startswith("#"):
                            active_script = None
                            continue
                        matched = detect_scripts(b_line)
                        if len(matched) == 1:
                            active_script = matched[0]
                        elif len(matched) > 1:
                            # 1 行に複数スクリプトが混在する場合は誤帰属を避けてリセット
                            active_script = None
                        if active_script is not None and (
                            matched or stripped.startswith("--")
                        ):
                            target_map.setdefault(active_script, set()).update(
                                LONG_FLAG_RE.findall(strip_quoted_arg_values(b_line))
                            )
                        if not stripped.endswith(("`", "\\")):
                            active_script = None
                block_buf = []
                in_fence = False
                fence_char = ""
                fence_len = 0
                continue
        if in_fence:
            block_buf.append(line)
        else:
            # 地の文では単一スクリプト名を含むインラインコード片のみから抽出する
            for seg in BACKTICK_PATH_RE.findall(line):
                matched = detect_scripts(seg)
                if len(matched) == 1:
                    target_map.setdefault(matched[0], set()).update(
                        LONG_FLAG_RE.findall(strip_quoted_arg_values(seg))
                    )
    return dict(target_map)


def extract_doc_flags_by_script(
    md_paths: Iterable[Path],
    script_names: set[str],
) -> dict[str, set[str]]:
    """指定された Markdown ファイル群からスクリプト単位の --flag 記載を抽出する。"""
    if not script_names:
        return {}
    flags_by_script: dict[str, set[str]] = defaultdict(set)
    seen_paths: set[Path] = set()
    for md_path in md_paths:
        if md_path in seen_paths or _is_reparse_or_symlink(md_path):
            continue
        seen_paths.add(md_path)
        try:
            lines = md_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        extract_doc_flags_from_lines(lines, script_names, flags_by_script)
    return dict(flags_by_script)


def _diff_doc_only_flags(
    doc_flags_by_script: dict[str, set[str]],
    script_paths: Iterable[Path],
) -> list[str]:
    impl_flags_by_script: dict[str, set[str]] = {}
    for sp in script_paths:
        impl_flags_by_script.setdefault(sp.name, set()).update(extract_argparse_flags(sp))

    doc_only: list[str] = []
    for sname, dflags in sorted(doc_flags_by_script.items()):
        # argparse の既定ヘルプフラグは文書記載を許容する
        allowed = impl_flags_by_script.get(sname, set()) | {"--help"}
        for fl in sorted(dflags):
            if fl not in allowed:
                doc_only.append(f"{sname}:{fl}")
    return sorted(doc_only)


def find_doc_only_flags(
    md_paths: Iterable[Path],
    script_paths: Iterable[Path],
) -> list[str]:
    """文書にのみ存在し対象スクリプトの AST にないフラグを script.py:--flag 昇順で返す。"""
    scripts = list(script_paths)
    if not scripts:
        return []
    script_names = {sp.name for sp in scripts}
    doc_flags = extract_doc_flags_by_script(md_paths, script_names)
    return _diff_doc_only_flags(doc_flags, scripts)


def find_doc_only_flags_in_text(
    doc_text: str,
    script_paths: Iterable[Path],
) -> list[str]:
    """メモリ上の Markdown 文字列に対して不在フラグ一覧（script.py:--flag）を返す。"""
    scripts = list(script_paths)
    if not scripts:
        return []
    script_names = {sp.name for sp in scripts}
    doc_flags = extract_doc_flags_from_lines(doc_text.splitlines(), script_names)
    return _diff_doc_only_flags(doc_flags, scripts)
