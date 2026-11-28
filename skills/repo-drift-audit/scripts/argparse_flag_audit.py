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


def _parse_python_ast(py_path: Path) -> ast.Module | None:
    if _is_reparse_or_symlink(py_path):
        return None
    try:
        source = py_path.read_text(encoding="utf-8", errors="replace")
        return ast.parse(source, filename=str(py_path))
    except (OSError, SyntaxError):
        return None


def _is_add_argument_call(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr == "add_argument"
    if isinstance(func, ast.Name):
        return func.id == "add_argument"
    return False


def _extract_long_flags_from_call(call: ast.Call) -> set[str]:
    flags: set[str] = set()
    for arg in call.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            if arg.value.startswith("--") and len(arg.value) > 2:
                flags.add(arg.value)
    return flags


def _collect_all_add_argument_calls(tree: ast.AST) -> tuple[set[str], set[int]]:
    flat_flags: set[str] = set()
    add_arg_ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_add_argument_call(node):
            flags = _extract_long_flags_from_call(node)
            if flags:
                flat_flags.update(flags)
                add_arg_ids.add(id(node))
    return flat_flags, add_arg_ids


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


def _is_main_guard(stmt: ast.If) -> bool:
    test = stmt.test
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or len(test.comparators) != 1:
        return False
    if not isinstance(test.ops[0], ast.Eq):
        return False
    left, right = test.left, test.comparators[0]
    if isinstance(left, ast.Name) and left.id == "__name__":
        return isinstance(right, ast.Constant) and right.value == "__main__"
    if isinstance(right, ast.Name) and right.id == "__name__":
        return isinstance(left, ast.Constant) and left.value == "__main__"
    return False


def _has_argparse_construct(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            if _is_argument_parser_init(sub) or _is_add_argument_call(sub):
                return True
            if isinstance(sub.func, ast.Attribute) and sub.func.attr in (
                "add_subparsers",
                "add_parser",
            ):
                return True
    return False


def _fn_creates_argument_parser(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        isinstance(sub, ast.Call) and _is_argument_parser_init(sub)
        for sub in ast.walk(fn)
    )


def extract_argparse_flags(py_path: Path) -> set[str]:
    """Python スクリプトの AST から add_argument で定義された --flag を抽出する。"""
    tree = _parse_python_ast(py_path)
    if tree is None:
        return set()
    flat_flags, _ = _collect_all_add_argument_calls(tree)
    return flat_flags


def extract_argparse_flag_spec(py_path: Path) -> tuple[set[str], dict[str, set[str]]]:
    """Python スクリプトの AST から (root_flags, subcommand_flags) を抽出する。

    単純な静的構造のすべてで 100% 帰属確定できる場合のみサブコマンド単位へ分離し、
    動的・複雑構文や未帰属フラグが残る場合は安全側フォールバック (flat_flags, {}) を返す。
    """
    tree = _parse_python_ast(py_path)
    if tree is None:
        return set(), {}

    flat_flags, all_add_arg_ids = _collect_all_add_argument_calls(tree)
    if not all_add_arg_ids:
        return flat_flags, {}

    has_literal_subparser = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "add_parser":
                if _is_add_parser_call(node) is None:
                    return flat_flags, {}
                has_literal_subparser = True
    if not has_literal_subparser:
        return flat_flags, {}

    top_funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if stmt.name in top_funcs:
                return flat_flags, {}
            top_funcs[stmt.name] = stmt

    flags_by_tag: dict[str, set[str]] = defaultdict(set)
    subcommand_names: set[str] = set()
    subparser_roots: set[str] = set()
    parent_edges: dict[str, set[str]] = defaultdict(set)
    parent_sources: set[str] = set()
    attributed_add_arg_ids: set[int] = set()
    called_top_funcs: set[str] = set()
    parser_counter = 0
    ambiguous = False
    call_stack: set[str] = set()

    def new_parser_tag() -> str:
        nonlocal parser_counter
        parser_counter += 1
        return f"parser:{parser_counter}"

    def bind_var(env: dict[str, str], name: str, tag: str) -> None:
        nonlocal ambiguous
        if name in env and env[name] != tag:
            ambiguous = True
            return
        env[name] = tag

    def record_parents(target_tag: str, call: ast.Call, env: dict[str, str]) -> None:
        nonlocal ambiguous
        for kw in call.keywords:
            if kw.arg == "parents":
                if not isinstance(kw.value, (ast.List, ast.Tuple)):
                    ambiguous = True
                    return
                for elem in kw.value.elts:
                    ptag = eval_expr(elem, env)
                    if ptag is None or not ptag.startswith(("parser:", "sub:")):
                        ambiguous = True
                        return
                    parent_edges[target_tag].add(ptag)
                    parent_sources.add(ptag)

    def eval_expr(expr: ast.AST | None, env: dict[str, str]) -> str | None:
        nonlocal ambiguous
        if expr is None or ambiguous:
            return None
        if isinstance(expr, ast.Name):
            return env.get(expr.id)
        if not isinstance(expr, ast.Call):
            return None

        if _is_argument_parser_init(expr):
            tag = new_parser_tag()
            record_parents(tag, expr, env)
            return tag

        func = expr.func
        if isinstance(func, ast.Attribute):
            owner_tag = eval_expr(func.value, env)
            attr = func.attr
            if attr == "add_subparsers":
                if owner_tag is None or not owner_tag.startswith("parser:"):
                    ambiguous = True
                    return None
                subparser_roots.add(owner_tag)
                return f"subparsers:{owner_tag}"
            if attr == "add_parser":
                sub_name = _is_add_parser_call(expr)
                if not sub_name or owner_tag is None or not owner_tag.startswith("subparsers:"):
                    ambiguous = True
                    return None
                subcommand_names.add(sub_name)
                tag = f"sub:{sub_name}"
                record_parents(tag, expr, env)
                return tag
            if attr in ("add_argument_group", "add_mutually_exclusive_group"):
                if owner_tag is None or not owner_tag.startswith(("parser:", "sub:")):
                    ambiguous = True
                    return None
                return owner_tag
            if attr == "add_argument":
                fls = _extract_long_flags_from_call(expr)
                if not fls:
                    return None
                if owner_tag is None or not owner_tag.startswith(("parser:", "sub:")):
                    ambiguous = True
                    return None
                flags_by_tag[owner_tag].update(fls)
                attributed_add_arg_ids.add(id(expr))
                return None

        if isinstance(func, ast.Name):
            if func.id == "add_argument":
                if _extract_long_flags_from_call(expr):
                    ambiguous = True
                return None
            callee = top_funcs.get(func.id)
            if callee is not None:
                if callee.name in call_stack:
                    ambiguous = True
                    return None
                bound: dict[str, str] = {}
                pos_names = [a.arg for a in callee.args.posonlyargs] + [
                    a.arg for a in callee.args.args
                ]
                for idx, arg_node in enumerate(expr.args):
                    arg_tag = eval_expr(arg_node, env)
                    if idx < len(pos_names) and arg_tag is not None:
                        bound[pos_names[idx]] = arg_tag
                for kw in expr.keywords:
                    kw_tag = eval_expr(kw.value, env)
                    if kw.arg is not None and kw_tag is not None:
                        bound[kw.arg] = kw_tag
                return run_top_func(callee, bound)

        for arg_node in expr.args:
            eval_expr(arg_node, env)
        for kw in expr.keywords:
            eval_expr(kw.value, env)
        return None

    def walk_linear(stmts: list[ast.stmt], env: dict[str, str], *, allow_main_if: bool) -> str | None:
        nonlocal ambiguous
        ret_tag: str | None = None
        for stmt in stmts:
            if ambiguous:
                return None
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if not allow_main_if:
                    if _has_argparse_construct(stmt):
                        ambiguous = True
                        return None
                continue
            if isinstance(stmt, ast.Assign):
                val_tag = eval_expr(stmt.value, env)
                if val_tag is not None:
                    for tgt in stmt.targets:
                        if isinstance(tgt, ast.Name):
                            bind_var(env, tgt.id, val_tag)
            elif isinstance(stmt, ast.AnnAssign):
                val_tag = eval_expr(stmt.value, env)
                if val_tag is not None and isinstance(stmt.target, ast.Name):
                    bind_var(env, stmt.target.id, val_tag)
            elif isinstance(stmt, ast.Expr):
                eval_expr(stmt.value, env)
            elif isinstance(stmt, ast.Raise):
                eval_expr(stmt.exc, env)
                eval_expr(stmt.cause, env)
            elif isinstance(stmt, ast.Return):
                rtag = eval_expr(stmt.value, env)
                if rtag is not None:
                    if ret_tag is not None and ret_tag != rtag:
                        ambiguous = True
                        return None
                    ret_tag = rtag
            elif isinstance(stmt, ast.If) and allow_main_if and _is_main_guard(stmt):
                if stmt.orelse and _has_argparse_construct(ast.Module(body=stmt.orelse, type_ignores=[])):
                    ambiguous = True
                    return None
                walk_linear(stmt.body, env, allow_main_if=False)
            elif isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith)):
                if _has_argparse_construct(stmt):
                    ambiguous = True
                    return None
        return ret_tag

    def run_top_func(
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
        bound: dict[str, str],
    ) -> str | None:
        called_top_funcs.add(fn.name)
        call_stack.add(fn.name)
        try:
            return walk_linear(fn.body, dict(bound), allow_main_if=False)
        finally:
            call_stack.discard(fn.name)

    module_env: dict[str, str] = {}
    walk_linear(tree.body, module_env, allow_main_if=True)

    if not ambiguous and attributed_add_arg_ids != all_add_arg_ids:
        callee_names = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        for only_roots in (True, False):
            for fn_name, fn in top_funcs.items():
                if ambiguous or attributed_add_arg_ids == all_add_arg_ids:
                    break
                if only_roots and fn_name in callee_names:
                    continue
                if fn_name not in called_top_funcs and _fn_creates_argument_parser(fn):
                    run_top_func(fn, {})

    if ambiguous or attributed_add_arg_ids != all_add_arg_ids or not subcommand_names:
        return flat_flags, {}

    def collect_inherited(tag: str, seen: set[str] | None = None) -> set[str]:
        visited = set() if seen is None else seen
        if tag in visited:
            return set()
        visited.add(tag)
        collected = set(flags_by_tag.get(tag, set()))
        for ptag in parent_edges.get(tag, set()):
            collected.update(collect_inherited(ptag, visited))
        return collected

    subcommand_flags: dict[str, set[str]] = {
        sub_name: collect_inherited(f"sub:{sub_name}")
        for sub_name in sorted(subcommand_names)
    }
    root_flags: set[str] = set()
    for rtag in subparser_roots:
        root_flags.update(collect_inherited(rtag))
    for tag in flags_by_tag:
        if tag.startswith("parser:") and tag not in parent_sources and tag not in subparser_roots:
            root_flags.update(collect_inherited(tag))

    return root_flags, subcommand_flags


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


def _split_shell_segments(text: str) -> list[str]:
    """引用符外のバックスラッシュエスケープとシェル演算子（&&, ||, ;, |）を考慮して分割する。"""
    segments: list[str] = []
    buf: list[str] = []
    in_quote: str | None = None
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and in_quote != "'":
            buf.append(ch)
            if i + 1 < n:
                i += 1
                buf.append(text[i])
            i += 1
            continue
        if in_quote is not None:
            buf.append(ch)
            if ch == in_quote:
                in_quote = None
            i += 1
            continue
        if ch in ('"', "'"):
            in_quote = ch
            buf.append(ch)
            i += 1
            continue
        if text[i : i + 2] in ("&&", "||"):
            segments.append("".join(buf))
            buf = []
            i += 2
            continue
        if ch in (";", "|"):
            segments.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    segments.append("".join(buf))
    return [seg for seg in segments if seg.strip()]


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
                        for seg_idx, seg in enumerate(_split_shell_segments(b_line)):
                            seg_stripped = seg.strip()
                            matched = detect_scripts(seg)
                            if len(matched) == 1:
                                active_script = matched[0]
                                sub_set = (
                                    known_subcommands.get(active_script, set())
                                    if known_subcommands
                                    else set()
                                )
                                active_subcmd = _detect_subcommand_after_script(
                                    seg, pattern_by_name[active_script], sub_set
                                )
                            elif len(matched) > 1 or seg_idx > 0:
                                active_script = None
                                active_subcmd = None
                            if active_script is not None and (
                                matched or seg_stripped.startswith("--")
                            ):
                                result[active_script][active_subcmd].update(
                                    LONG_FLAG_RE.findall(strip_quoted_arg_values(seg))
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
            for inline_seg in BACKTICK_PATH_RE.findall(line):
                for sub_seg in _split_shell_segments(inline_seg):
                    matched = detect_scripts(sub_seg)
                    if len(matched) == 1:
                        sname = matched[0]
                        sub_set = (
                            known_subcommands.get(sname, set())
                            if known_subcommands
                            else set()
                        )
                        subcmd = _detect_subcommand_after_script(
                            sub_seg, pattern_by_name[sname], sub_set
                        )
                        result[sname][subcmd].update(
                            LONG_FLAG_RE.findall(strip_quoted_arg_values(sub_seg))
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


def _iter_safe_md_lines(md_paths: Iterable[Path]) -> Iterable[list[str]]:
    seen_paths: set[Path] = set()
    for md_path in md_paths:
        if md_path in seen_paths or _is_reparse_or_symlink(md_path):
            continue
        seen_paths.add(md_path)
        try:
            yield md_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue


def extract_doc_flags_by_script(
    md_paths: Iterable[Path],
    script_names: set[str],
) -> dict[str, set[str]]:
    """指定された Markdown ファイル群からスクリプト単位の --flag 記載を抽出する。"""
    if not script_names:
        return {}
    flags_by_script: dict[str, set[str]] = defaultdict(set)
    for lines in _iter_safe_md_lines(md_paths):
        extract_doc_flags_from_lines(lines, script_names, flags_by_script)
    return dict(flags_by_script)


def _find_doc_only_flags_from_line_batches(
    line_batches: Iterable[Iterable[str]],
    script_paths: Iterable[Path],
) -> list[str]:
    scripts = list(script_paths)
    if not scripts:
        return []
    root_by_script: dict[str, set[str]] = {}
    subs_by_script: dict[str, dict[str, set[str]]] = {}
    for sp in scripts:
        rflags, sub_map = extract_argparse_flag_spec(sp)
        root_by_script.setdefault(sp.name, set()).update(rflags)
        target_subs = subs_by_script.setdefault(sp.name, {})
        for sub_name, sflags in sub_map.items():
            target_subs.setdefault(sub_name, set()).update(sflags)

    script_names = {sp.name for sp in scripts}
    known_subcommands = {sn: set(smap.keys()) for sn, smap in subs_by_script.items()}

    merged: dict[str, dict[str | None, set[str]]] = defaultdict(lambda: defaultdict(set))
    for lines in line_batches:
        scanned = _scan_doc_flags_from_lines(
            lines,
            script_names,
            known_subcommands=known_subcommands,
        )
        for sname, smap in scanned.items():
            for subcmd, fls in smap.items():
                merged[sname][subcmd].update(fls)

    doc_only: set[str] = set()
    for sname, sub_map in sorted(merged.items()):
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
    return _find_doc_only_flags_from_line_batches(_iter_safe_md_lines(md_paths), script_paths)


def find_doc_only_flags_in_text(
    doc_text: str,
    script_paths: Iterable[Path],
) -> list[str]:
    """メモリ上の Markdown 文字列に対して不在フラグ一覧（script.py:--flag）を返す。"""
    return _find_doc_only_flags_from_line_batches([doc_text.splitlines()], script_paths)
