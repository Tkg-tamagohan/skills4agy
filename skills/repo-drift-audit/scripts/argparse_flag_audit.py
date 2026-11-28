#!/usr/bin/env python3
"""argparse 定義と Markdown 文書記載の CLI ロングフラグ突合ヘルパ。

`repo-drift-audit` が利用する決定論的チェックを提供する。なお、
`plugin-authoring/scripts/audit_skills_weekly.py` の本共有ヘルパへの移行は
後続トラック（Track 4）で行う設計であり、現時点の共有先移行は未実施。
Python 標準ライブラリのみで動作する。
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
CMD_STOP_TOKENS: frozenset[str] = frozenset({"&&", "||", ";", "|"})


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


def _is_add_parser_call(call: ast.Call) -> str | None:
    func = call.func
    if not (isinstance(func, ast.Attribute) and func.attr == "add_parser"):
        return None
    if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
        return call.args[0].value
    for kw in call.keywords:
        if kw.arg == "name" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
            return kw.value.value
    return None


def _is_argument_parser_init(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Name) and func.id == "ArgumentParser":
        return True
    if isinstance(func, ast.Attribute) and func.attr == "ArgumentParser":
        return True
    return False


def _extract_long_flags_from_call(call: ast.Call) -> set[str]:
    flags: set[str] = set()
    for arg in call.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            if arg.value.startswith("--") and len(arg.value) > 2:
                flags.add(arg.value)
    return flags


def extract_argparse_flag_spec(py_path: Path) -> tuple[set[str], dict[str, set[str]]]:
    """Python スクリプトの AST から (root_flags, subcommand_flags) を抽出する。"""
    if _is_reparse_or_symlink(py_path):
        return set(), {}
    try:
        source = py_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(py_path))
    except (OSError, SyntaxError):
        return set(), {}

    funcs_by_name: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs_by_name[node.name] = node

    flags_by_tag: dict[str, set[str]] = defaultdict(set)
    subcommand_names: set[str] = set()
    subparser_roots: set[str] = set()
    parent_edges: dict[str, set[str]] = defaultdict(set)
    parser_counter = 0
    visited_calls: set[tuple[str, tuple[tuple[str, str], ...]]] = set()

    def new_parser_tag() -> str:
        nonlocal parser_counter
        parser_counter += 1
        return f"parser:{parser_counter}"

    def _record_parents(target_tag: str, call: ast.Call, env: dict[str, str]) -> None:
        for kw in call.keywords:
            if kw.arg == "parents" and isinstance(kw.value, (ast.List, ast.Tuple)):
                for elem in kw.value.elts:
                    ptag = eval_expr(elem, env)
                    if ptag is not None:
                        parent_edges[target_tag].add(ptag)

    def eval_expr(expr: ast.AST | None, env: dict[str, str]) -> str | None:
        if expr is None:
            return None
        if isinstance(expr, ast.Name):
            return env.get(expr.id)
        if not isinstance(expr, ast.Call):
            return None

        if _is_argument_parser_init(expr):
            tag = new_parser_tag()
            _record_parents(tag, expr, env)
            return tag

        func = expr.func
        if isinstance(func, ast.Attribute):
            owner_tag = eval_expr(func.value, env)
            attr = func.attr
            if attr == "add_subparsers":
                if owner_tag is not None:
                    subparser_roots.add(owner_tag)
                return f"subparsers:{owner_tag or 'unknown'}"
            if attr == "add_parser":
                sub_name = _is_add_parser_call(expr)
                if sub_name:
                    subcommand_names.add(sub_name)
                    tag = f"sub:{sub_name}"
                    _record_parents(tag, expr, env)
                    return tag
                return None
            if attr in ("add_argument_group", "add_mutually_exclusive_group"):
                return owner_tag
            if attr == "add_argument":
                target = owner_tag if owner_tag is not None else "unknown:root"
                flags_by_tag[target].update(_extract_long_flags_from_call(expr))
                return None

        if isinstance(func, ast.Name):
            if func.id == "add_argument":
                flags_by_tag["unknown:root"].update(_extract_long_flags_from_call(expr))
                return None
            callee = funcs_by_name.get(func.id)
            if callee is not None:
                bound: dict[str, str] = {}
                pos_names = [a.arg for a in callee.args.posonlyargs] + [a.arg for a in callee.args.args]
                for idx, arg_node in enumerate(expr.args):
                    if idx < len(pos_names):
                        arg_tag = eval_expr(arg_node, env)
                        if arg_tag is not None:
                            bound[pos_names[idx]] = arg_tag
                for kw in expr.keywords:
                    if kw.arg is not None:
                        arg_tag = eval_expr(kw.value, env)
                        if arg_tag is not None:
                            bound[kw.arg] = arg_tag
                return run_function(callee, bound)
            for arg_node in expr.args:
                eval_expr(arg_node, env)
            for kw in expr.keywords:
                eval_expr(kw.value, env)
            return None

        for arg_node in expr.args:
            eval_expr(arg_node, env)
        for kw in expr.keywords:
            eval_expr(kw.value, env)
        return None

    def walk_stmts(stmts: list[ast.stmt], env: dict[str, str]) -> str | None:
        ret_tag: str | None = None
        for stmt in stmts:
            if isinstance(stmt, ast.Assign):
                val_tag = eval_expr(stmt.value, env)
                if val_tag is not None:
                    for tgt in stmt.targets:
                        if isinstance(tgt, ast.Name):
                            env[tgt.id] = val_tag
            elif isinstance(stmt, ast.AnnAssign):
                val_tag = eval_expr(stmt.value, env)
                if val_tag is not None and isinstance(stmt.target, ast.Name):
                    env[stmt.target.id] = val_tag
            elif isinstance(stmt, ast.Expr):
                eval_expr(stmt.value, env)
            elif isinstance(stmt, ast.Return):
                rtag = eval_expr(stmt.value, env)
                if rtag is not None and ret_tag is None:
                    ret_tag = rtag
            elif isinstance(stmt, ast.If):
                for sub_body in (stmt.body, stmt.orelse):
                    rtag = walk_stmts(sub_body, env)
                    if rtag is not None and ret_tag is None:
                        ret_tag = rtag
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                for sub_body in (stmt.body, stmt.orelse):
                    rtag = walk_stmts(sub_body, env)
                    if rtag is not None and ret_tag is None:
                        ret_tag = rtag
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                rtag = walk_stmts(stmt.body, env)
                if rtag is not None and ret_tag is None:
                    ret_tag = rtag
            elif isinstance(stmt, ast.Try):
                for sub_body in (stmt.body, stmt.orelse, stmt.finalbody):
                    rtag = walk_stmts(sub_body, env)
                    if rtag is not None and ret_tag is None:
                        ret_tag = rtag
                for h in stmt.handlers:
                    rtag = walk_stmts(h.body, env)
                    if rtag is not None and ret_tag is None:
                        ret_tag = rtag
        return ret_tag

    def run_function(
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
        bound: dict[str, str],
    ) -> str | None:
        key = (fn.name, tuple(sorted(bound.items())))
        if key in visited_calls:
            return None
        visited_calls.add(key)
        local_env: dict[str, str] = {}
        all_params = (
            [a.arg for a in fn.args.posonlyargs]
            + [a.arg for a in fn.args.args]
            + [a.arg for a in fn.args.kwonlyargs]
        )
        for p in all_params:
            if p in bound:
                local_env[p] = bound[p]
            else:
                local_env[p] = f"param:{fn.name}:{p}"
        return walk_stmts(fn.body, local_env)

    top_env: dict[str, str] = {}
    top_stmts = [n for n in tree.body if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    walk_stmts(top_stmts, top_env)
    for fn in funcs_by_name.values():
        run_function(fn, {})

    def collect_inherited(tag: str, seen: set[str] | None = None) -> set[str]:
        visited = set() if seen is None else seen
        if tag in visited:
            return set()
        visited.add(tag)
        collected = set(flags_by_tag.get(tag, set()))
        for ptag in parent_edges.get(tag, set()):
            collected.update(collect_inherited(ptag, visited))
        return collected

    subcommand_flags: dict[str, set[str]] = {}
    for sub_name in sorted(subcommand_names):
        subcommand_flags[sub_name] = collect_inherited(f"sub:{sub_name}")

    root_flags: set[str] = set(flags_by_tag.get("unknown:root", set()))
    if subcommand_names:
        for rtag in subparser_roots:
            root_flags.update(collect_inherited(rtag))
        if not subparser_roots:
            for tag, fls in flags_by_tag.items():
                if tag.startswith("parser:"):
                    root_flags.update(fls)
    else:
        for tag, fls in flags_by_tag.items():
            if not tag.startswith("sub:"):
                root_flags.update(fls)

    return root_flags, subcommand_flags


def extract_argparse_flags(py_path: Path) -> set[str]:
    """Python スクリプトの AST から add_argument で定義された --flag を抽出する。"""
    root_flags, subcommand_flags = extract_argparse_flag_spec(py_path)
    all_flags = set(root_flags)
    for sub_flags in subcommand_flags.values():
        all_flags.update(sub_flags)
    return all_flags


def strip_quoted_arg_values(text: str) -> str:
    """フラグ値（例: --command "git push --force"）内部の誤検出を防ぐためクォート内を除去する。"""
    cleaned = re.sub(r'"[^"\n]*"', '""', text)
    cleaned = re.sub(r"'[^'\n]*'", "''", cleaned)
    return cleaned


def _detect_subcommand_after_script(
    text: str,
    script_rx: re.Pattern[str],
    subcmds: set[str],
) -> str | None:
    if not subcmds:
        return None
    m = script_rx.search(text)
    if not m:
        return None
    tail = text[m.end() :].lstrip("\"'")
    cleaned_tail = strip_quoted_arg_values(tail)
    for tok in cleaned_tail.split():
        if tok in CMD_STOP_TOKENS:
            break
        if tok.startswith("-"):
            return None
        return tok if tok in subcmds else None
    return None


def _scan_doc_flags_from_lines(
    lines: Iterable[str],
    script_names: set[str],
    *,
    known_subcommands: dict[str, set[str]] | None = None,
) -> dict[str, dict[str | None, set[str]]]:
    """Markdown 行列から (スクリプト名 -> {サブコマンドまたは None -> フラグ集合}) を抽出する。"""
    result: dict[str, dict[str | None, set[str]]] = defaultdict(lambda: defaultdict(set))
    if not script_names:
        return {}

    ordered_names = sorted(script_names, key=lambda s: (-len(s), s))
    name_patterns: list[tuple[str, re.Pattern[str]]] = [
        (
            sn,
            re.compile(r"(?<![A-Za-z0-9_.-])" + re.escape(sn) + r"(?![A-Za-z0-9_.-])"),
        )
        for sn in ordered_names
    ]
    pattern_by_name = dict(name_patterns)

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
                    active_subcmd: str | None = None
                    for b_line in block_buf:
                        stripped = b_line.strip()
                        if not stripped or stripped.startswith("#"):
                            active_script = None
                            active_subcmd = None
                            continue
                        matched = detect_scripts(b_line)
                        if len(matched) == 1:
                            active_script = matched[0]
                            sub_set = (
                                known_subcommands.get(active_script, set())
                                if known_subcommands
                                else set()
                            )
                            active_subcmd = _detect_subcommand_after_script(
                                b_line, pattern_by_name[active_script], sub_set
                            )
                        elif len(matched) > 1:
                            # 1 行に複数スクリプトが混在する場合は誤帰属を避けてリセット
                            active_script = None
                            active_subcmd = None
                        if active_script is not None and (
                            matched or stripped.startswith("--")
                        ):
                            result[active_script][active_subcmd].update(
                                LONG_FLAG_RE.findall(strip_quoted_arg_values(b_line))
                            )
                        if not stripped.endswith(("`", "\\")):
                            active_script = None
                            active_subcmd = None
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
                    sname = matched[0]
                    sub_set = (
                        known_subcommands.get(sname, set())
                        if known_subcommands
                        else set()
                    )
                    subcmd = _detect_subcommand_after_script(
                        seg, pattern_by_name[sname], sub_set
                    )
                    result[sname][subcmd].update(
                        LONG_FLAG_RE.findall(strip_quoted_arg_values(seg))
                    )
    return {sn: dict(sub_map) for sn, sub_map in result.items()}


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

    scanned = _scan_doc_flags_from_lines(lines, script_names)
    for sname, sub_map in scanned.items():
        bucket = target_map.setdefault(sname, set())
        for flags in sub_map.values():
            bucket.update(flags)
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


def _build_impl_specs(
    script_paths: Iterable[Path],
) -> tuple[dict[str, set[str]], dict[str, dict[str, set[str]]]]:
    root_by_script: dict[str, set[str]] = {}
    subs_by_script: dict[str, dict[str, set[str]]] = {}
    for sp in script_paths:
        rflags, sub_map = extract_argparse_flag_spec(sp)
        root_by_script.setdefault(sp.name, set()).update(rflags)
        target_subs = subs_by_script.setdefault(sp.name, {})
        for sub_name, sflags in sub_map.items():
            target_subs.setdefault(sub_name, set()).update(sflags)
    return root_by_script, subs_by_script


def _diff_doc_only_flags_with_subcommands(
    doc_flags_by_script_sub: dict[str, dict[str | None, set[str]]],
    root_by_script: dict[str, set[str]],
    subs_by_script: dict[str, dict[str, set[str]]],
) -> list[str]:
    doc_only: set[str] = set()
    for sname, sub_map in sorted(doc_flags_by_script_sub.items()):
        root_flags = root_by_script.get(sname, set())
        impl_subs = subs_by_script.get(sname, {})
        union_all = set(root_flags)
        for sflags in impl_subs.values():
            union_all.update(sflags)

        for subcmd, dflags in sub_map.items():
            if subcmd is not None and subcmd in impl_subs:
                allowed = root_flags | impl_subs[subcmd] | {"--help"}
            else:
                allowed = union_all | {"--help"}
            for fl in dflags:
                if fl not in allowed:
                    doc_only.add(f"{sname}:{fl}")
    return sorted(doc_only)


def find_doc_only_flags(
    md_paths: Iterable[Path],
    script_paths: Iterable[Path],
) -> list[str]:
    """文書にのみ存在し対象スクリプトの AST にないフラグを script.py:--flag 昇順で返す。"""
    scripts = list(script_paths)
    if not scripts:
        return []
    root_by_script, subs_by_script = _build_impl_specs(scripts)
    script_names = {sp.name for sp in scripts}
    known_subcommands = {sn: set(smap.keys()) for sn, smap in subs_by_script.items()}

    merged: dict[str, dict[str | None, set[str]]] = defaultdict(lambda: defaultdict(set))
    seen_paths: set[Path] = set()
    for md_path in md_paths:
        if md_path in seen_paths or _is_reparse_or_symlink(md_path):
            continue
        seen_paths.add(md_path)
        try:
            lines = md_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        scanned = _scan_doc_flags_from_lines(
            lines,
            script_names,
            known_subcommands=known_subcommands,
        )
        for sname, smap in scanned.items():
            for subcmd, fls in smap.items():
                merged[sname][subcmd].update(fls)

    return _diff_doc_only_flags_with_subcommands(merged, root_by_script, subs_by_script)


def find_doc_only_flags_in_text(
    doc_text: str,
    script_paths: Iterable[Path],
) -> list[str]:
    """メモリ上の Markdown 文字列に対して不在フラグ一覧（script.py:--flag）を返す。"""
    scripts = list(script_paths)
    if not scripts:
        return []
    root_by_script, subs_by_script = _build_impl_specs(scripts)
    script_names = {sp.name for sp in scripts}
    known_subcommands = {sn: set(smap.keys()) for sn, smap in subs_by_script.items()}
    scanned = _scan_doc_flags_from_lines(
        doc_text.splitlines(),
        script_names,
        known_subcommands=known_subcommands,
    )
    return _diff_doc_only_flags_with_subcommands(scanned, root_by_script, subs_by_script)
