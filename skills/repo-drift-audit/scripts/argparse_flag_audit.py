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
from typing import Any

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


def _merge_tags(*seqs: Iterable[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    out: list[str] = []
    for seq in seqs:
        for item in seq:
            if item and item not in seen:
                seen.add(item)
                out.append(item)
    return tuple(out)


def _dedup_func_nodes(
    items: Iterable[ast.FunctionDef | ast.AsyncFunctionDef],
) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    seen: set[int] = set()
    out: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for item in items:
        fid = id(item)
        if fid not in seen:
            seen.add(fid)
            out.append(item)
    return out


def _dedup_lexical_entries(
    items: Iterable[tuple[ast.FunctionDef | ast.AsyncFunctionDef, dict[str, tuple[str, ...]]]],
) -> list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, dict[str, tuple[str, ...]]]]:
    seen: set[int] = set()
    out: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, dict[str, tuple[str, ...]]]] = []
    for fn_node, c_env in items:
        fid = id(fn_node)
        if fid not in seen:
            seen.add(fid)
            out.append((fn_node, c_env))
    return out


def _merge_if_maps(
    pre_map: dict[str, list[Any]],
    then_map: dict[str, list[Any]],
    else_map: dict[str, list[Any]] | None,
    dedup_fn: Any,
) -> dict[str, list[Any]]:
    merged: dict[str, list[Any]] = {k: list(v) for k, v in pre_map.items()}
    if else_map is None:
        for k, then_val in then_map.items():
            if then_val != pre_map.get(k):
                merged[k] = dedup_fn([*pre_map.get(k, []), *then_val])
        return merged

    all_keys = set(pre_map.keys()) | set(then_map.keys()) | set(else_map.keys())
    for k in all_keys:
        pre_val = pre_map.get(k)
        then_val = then_map.get(k)
        else_val = else_map.get(k)
        redef_then = then_val is not None and then_val != pre_val
        redef_else = else_val is not None and else_val != pre_val
        if redef_then and redef_else:
            merged[k] = dedup_fn([*(then_val or []), *(else_val or [])])
        elif redef_then:
            merged[k] = dedup_fn([*(pre_val or []), *(then_val or [])])
        elif redef_else:
            merged[k] = dedup_fn([*(pre_val or []), *(else_val or [])])
    return merged


def _merge_env_branches(
    pre_env: dict[str, tuple[str, ...]],
    then_env: dict[str, tuple[str, ...]],
    else_env: dict[str, tuple[str, ...]] | None,
) -> dict[str, tuple[str, ...]]:
    merged: dict[str, tuple[str, ...]] = dict(pre_env)
    if else_env is None:
        for k, then_val in then_env.items():
            if then_val != pre_env.get(k):
                merged[k] = _merge_tags(pre_env.get(k, ()), then_val)
        return merged

    for k in set(pre_env.keys()) | set(then_env.keys()) | set(else_env.keys()):
        pre_val = pre_env.get(k)
        then_val = then_env.get(k)
        else_val = else_env.get(k)
        redef_then = then_val is not None and then_val != pre_val
        redef_else = else_val is not None and else_val != pre_val
        if redef_then and redef_else:
            merged[k] = _merge_tags(then_val or (), else_val or ())
        elif redef_then:
            merged[k] = _merge_tags(pre_val or (), then_val or ())
        elif redef_else:
            merged[k] = _merge_tags(pre_val or (), else_val or ())
    return merged


def extract_argparse_flag_spec(py_path: Path) -> tuple[set[str], dict[str, set[str]]]:
    """Python スクリプトの AST から (root_flags, subcommand_flags) を抽出する。"""
    if _is_reparse_or_symlink(py_path):
        return set(), {}
    try:
        source = py_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(py_path))
    except (OSError, SyntaxError):
        return set(), {}

    module_funcs: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
    class_methods: dict[str, dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]]] = defaultdict(
        dict
    )
    all_nested_funcs: list[ast.FunctionDef | ast.AsyncFunctionDef] = []

    def _collect_nested_only(stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                all_nested_funcs.append(stmt)
                _collect_nested_only(stmt.body)
            elif isinstance(stmt, ast.ClassDef):
                _collect_nested_only(stmt.body)
            elif isinstance(stmt, ast.If):
                _collect_nested_only(stmt.body)
                _collect_nested_only(stmt.orelse)
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                _collect_nested_only(stmt.body)
                _collect_nested_only(stmt.orelse)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                _collect_nested_only(stmt.body)
            elif isinstance(stmt, ast.Try):
                _collect_nested_only(stmt.body)
                _collect_nested_only(stmt.orelse)
                _collect_nested_only(stmt.finalbody)
                for handler in stmt.handlers:
                    _collect_nested_only(handler.body)

    def _collect_defs_in_block(
        stmts: list[ast.stmt],
        defs_map: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]],
        *,
        is_module_scope: bool,
    ) -> None:
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defs_map[stmt.name] = [stmt]
                _collect_nested_only(stmt.body)
            elif isinstance(stmt, ast.ClassDef):
                if is_module_scope:
                    cls_map: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
                    _collect_defs_in_block(stmt.body, cls_map, is_module_scope=False)
                    class_methods[stmt.name] = cls_map
                else:
                    _collect_nested_only(stmt.body)
            elif isinstance(stmt, ast.If):
                pre = {k: list(v) for k, v in defs_map.items()}
                then_map = {k: list(v) for k, v in pre.items()}
                _collect_defs_in_block(stmt.body, then_map, is_module_scope=is_module_scope)
                else_map: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] | None = None
                if stmt.orelse:
                    else_map = {k: list(v) for k, v in pre.items()}
                    _collect_defs_in_block(stmt.orelse, else_map, is_module_scope=is_module_scope)
                merged = _merge_if_maps(pre, then_map, else_map, _dedup_func_nodes)
                defs_map.clear()
                defs_map.update(merged)
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                pre = {k: list(v) for k, v in defs_map.items()}
                body_map = {k: list(v) for k, v in pre.items()}
                _collect_defs_in_block(stmt.body, body_map, is_module_scope=is_module_scope)
                else_map = {k: list(v) for k, v in pre.items()}
                if stmt.orelse:
                    _collect_defs_in_block(stmt.orelse, else_map, is_module_scope=is_module_scope)
                for k in set(body_map.keys()) | set(else_map.keys()):
                    if body_map.get(k) != pre.get(k) or else_map.get(k) != pre.get(k):
                        defs_map[k] = _dedup_func_nodes(
                            [*pre.get(k, []), *body_map.get(k, []), *else_map.get(k, [])]
                        )
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                _collect_defs_in_block(stmt.body, defs_map, is_module_scope=is_module_scope)
            elif isinstance(stmt, ast.Try):
                pre = {k: list(v) for k, v in defs_map.items()}
                try_map = {k: list(v) for k, v in pre.items()}
                _collect_defs_in_block(stmt.body, try_map, is_module_scope=is_module_scope)
                if stmt.orelse:
                    _collect_defs_in_block(stmt.orelse, try_map, is_module_scope=is_module_scope)
                merged_try = {k: list(v) for k, v in try_map.items()}
                for handler in stmt.handlers:
                    h_map = {k: list(v) for k, v in pre.items()}
                    _collect_defs_in_block(handler.body, h_map, is_module_scope=is_module_scope)
                    for k, h_val in h_map.items():
                        if h_val != pre.get(k):
                            merged_try[k] = _dedup_func_nodes(
                                [*merged_try.get(k, []), *h_val]
                            )
                defs_map.clear()
                defs_map.update(merged_try)
                if stmt.finalbody:
                    _collect_defs_in_block(stmt.finalbody, defs_map, is_module_scope=is_module_scope)

    _collect_defs_in_block(tree.body, module_funcs, is_module_scope=True)
    all_nested_funcs = _dedup_func_nodes(all_nested_funcs)

    flags_by_tag: dict[str, set[str]] = defaultdict(set)
    subcommand_names: set[str] = set()
    subparser_roots: set[str] = set()
    parent_edges: dict[str, set[str]] = defaultdict(set)
    parent_sources: set[str] = set()
    directly_called_func_ids: set[int] = set()
    parser_counter = 0
    active_calls: set[
        tuple[
            int,
            tuple[tuple[str, tuple[str, ...]], ...],
            tuple[tuple[str, tuple[str, ...]], ...],
            bool,
        ]
    ] = set()
    completed_returns: dict[
        tuple[
            int,
            tuple[tuple[str, tuple[str, ...]], ...],
            tuple[tuple[str, tuple[str, ...]], ...],
            bool,
        ],
        tuple[str, ...],
    ] = {}

    def new_parser_tag() -> str:
        nonlocal parser_counter
        parser_counter += 1
        return f"parser:{parser_counter}"

    def _record_parents(
        target_tags: tuple[str, ...],
        call: ast.Call,
        env: dict[str, tuple[str, ...]],
        lexical_funcs: dict[
            str,
            list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, dict[str, tuple[str, ...]]]],
        ],
    ) -> None:
        for kw in call.keywords:
            if kw.arg == "parents" and isinstance(kw.value, (ast.List, ast.Tuple)):
                for elem in kw.value.elts:
                    ptags = eval_expr(elem, env, lexical_funcs)
                    for ptag in ptags:
                        parent_sources.add(ptag)
                        for ttag in target_tags:
                            parent_edges[ttag].add(ptag)

    def _bind_and_call(
        callee: ast.FunctionDef | ast.AsyncFunctionDef,
        expr: ast.Call,
        env: dict[str, tuple[str, ...]],
        lexical_funcs: dict[
            str,
            list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, dict[str, tuple[str, ...]]]],
        ],
        *,
        closure_env: dict[str, tuple[str, ...]] | None = None,
        skip_self_cls: bool = False,
        self_instance_tags: tuple[str, ...] = (),
    ) -> tuple[str, ...]:
        bound: dict[str, tuple[str, ...]] = {}
        pos_names = [a.arg for a in callee.args.posonlyargs] + [a.arg for a in callee.args.args]
        if skip_self_cls and pos_names and pos_names[0] in ("self", "cls"):
            if self_instance_tags:
                bound[pos_names[0]] = self_instance_tags
            pos_names = pos_names[1:]
        for idx, arg_node in enumerate(expr.args):
            if idx < len(pos_names):
                arg_tags = eval_expr(arg_node, env, lexical_funcs)
                if arg_tags:
                    bound[pos_names[idx]] = arg_tags
        for kw in expr.keywords:
            if kw.arg is not None:
                arg_tags = eval_expr(kw.value, env, lexical_funcs)
                if arg_tags:
                    bound[kw.arg] = arg_tags
        closure_snap = dict(closure_env) if closure_env else {}
        directly_called_func_ids.add(id(callee))
        return run_function(callee, bound, closure_snap, lexical_funcs, is_uncalled_sweep=False)

    def eval_expr(
        expr: ast.AST | None,
        env: dict[str, tuple[str, ...]],
        lexical_funcs: dict[
            str,
            list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, dict[str, tuple[str, ...]]]],
        ],
    ) -> tuple[str, ...]:
        if expr is None:
            return ()
        if isinstance(expr, ast.Name):
            return env.get(expr.id, ())
        if isinstance(expr, ast.IfExp):
            return _merge_tags(
                eval_expr(expr.body, env, lexical_funcs),
                eval_expr(expr.orelse, env, lexical_funcs),
            )
        if not isinstance(expr, ast.Call):
            return ()

        if _is_argument_parser_init(expr):
            tag = new_parser_tag()
            _record_parents((tag,), expr, env, lexical_funcs)
            return (tag,)

        func = expr.func
        if isinstance(func, ast.Attribute):
            owner_tags = eval_expr(func.value, env, lexical_funcs)
            attr = func.attr
            if attr == "add_subparsers":
                if owner_tags:
                    for ot in owner_tags:
                        subparser_roots.add(ot)
                    return tuple(f"subparsers:{ot}" for ot in owner_tags)
                return ("subparsers:unknown",)
            if attr == "add_parser":
                sub_name = _is_add_parser_call(expr)
                if sub_name:
                    subcommand_names.add(sub_name)
                    tag = f"sub:{sub_name}"
                    _record_parents((tag,), expr, env, lexical_funcs)
                    return (tag,)
                return ()
            if attr in ("add_argument_group", "add_mutually_exclusive_group"):
                return owner_tags
            if attr == "add_argument":
                targets = owner_tags if owner_tags else ("unknown:root",)
                fls = _extract_long_flags_from_call(expr)
                for target in targets:
                    flags_by_tag[target].update(fls)
                return ()

            cls_names: list[str] = []
            if isinstance(func.value, ast.Name) and func.value.id in class_methods:
                cls_names.append(func.value.id)
            for ot in owner_tags:
                if ot.startswith("instance:"):
                    cn = ot[len("instance:") :]
                    if cn in class_methods and cn not in cls_names:
                        cls_names.append(cn)

            all_method_rets: list[str] = []
            matched_any = False
            for cls_name in cls_names:
                method_cands = class_methods.get(cls_name, {}).get(attr, [])
                if method_cands:
                    matched_any = True
                    for m_fn in method_cands:
                        rets = _bind_and_call(
                            m_fn,
                            expr,
                            env,
                            lexical_funcs,
                            skip_self_cls=True,
                            self_instance_tags=(f"instance:{cls_name}",),
                        )
                        all_method_rets.extend(rets)
            if matched_any:
                return _merge_tags(all_method_rets)

            for arg_node in expr.args:
                eval_expr(arg_node, env, lexical_funcs)
            for kw in expr.keywords:
                eval_expr(kw.value, env, lexical_funcs)
            return ()

        if isinstance(func, ast.Name):
            if func.id == "add_argument":
                flags_by_tag["unknown:root"].update(_extract_long_flags_from_call(expr))
                return ()
            if func.id in lexical_funcs:
                all_rets: list[str] = []
                for callee, closure_env_ref in list(lexical_funcs[func.id]):
                    rets = _bind_and_call(
                        callee,
                        expr,
                        env,
                        lexical_funcs,
                        closure_env=closure_env_ref,
                        skip_self_cls=False,
                    )
                    all_rets.extend(rets)
                return _merge_tags(all_rets)
            if func.id in module_funcs:
                all_rets = []
                for callee in module_funcs[func.id]:
                    rets = _bind_and_call(
                        callee,
                        expr,
                        env,
                        lexical_funcs,
                        skip_self_cls=False,
                    )
                    all_rets.extend(rets)
                return _merge_tags(all_rets)
            if func.id in class_methods:
                for arg_node in expr.args:
                    eval_expr(arg_node, env, lexical_funcs)
                for kw in expr.keywords:
                    eval_expr(kw.value, env, lexical_funcs)
                return (f"instance:{func.id}",)
            for arg_node in expr.args:
                eval_expr(arg_node, env, lexical_funcs)
            for kw in expr.keywords:
                eval_expr(kw.value, env, lexical_funcs)
            return ()

        for arg_node in expr.args:
            eval_expr(arg_node, env, lexical_funcs)
        for kw in expr.keywords:
            eval_expr(kw.value, env, lexical_funcs)
        return ()

    def walk_stmts(
        stmts: list[ast.stmt],
        env: dict[str, tuple[str, ...]],
        lexical_funcs: dict[
            str,
            list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, dict[str, tuple[str, ...]]]],
        ],
    ) -> tuple[str, ...]:
        ret_tags: list[str] = []
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # 同一スコープの再定義および内側シャドウイングは外側候補を置換する
                lexical_funcs[stmt.name] = [(stmt, env)]
            elif isinstance(stmt, ast.Assign):
                val_tags = eval_expr(stmt.value, env, lexical_funcs)
                if val_tags:
                    for tgt in stmt.targets:
                        if isinstance(tgt, ast.Name):
                            env[tgt.id] = val_tags
            elif isinstance(stmt, ast.AnnAssign):
                val_tags = eval_expr(stmt.value, env, lexical_funcs)
                if val_tags and isinstance(stmt.target, ast.Name):
                    env[stmt.target.id] = val_tags
            elif isinstance(stmt, ast.Expr):
                eval_expr(stmt.value, env, lexical_funcs)
            elif isinstance(stmt, ast.Raise):
                eval_expr(stmt.exc, env, lexical_funcs)
                eval_expr(stmt.cause, env, lexical_funcs)
            elif isinstance(stmt, ast.Return):
                ret_tags.extend(eval_expr(stmt.value, env, lexical_funcs))
            elif isinstance(stmt, ast.If):
                pre_env = dict(env)
                pre_lex = {k: list(v) for k, v in lexical_funcs.items()}

                then_env = dict(pre_env)
                then_lex = {k: list(v) for k, v in pre_lex.items()}
                ret_tags.extend(walk_stmts(stmt.body, then_env, then_lex))

                else_env: dict[str, tuple[str, ...]] | None = None
                else_lex: (
                    dict[
                        str,
                        list[
                            tuple[
                                ast.FunctionDef | ast.AsyncFunctionDef,
                                dict[str, tuple[str, ...]],
                            ]
                        ],
                    ]
                    | None
                ) = None
                if stmt.orelse:
                    else_env = dict(pre_env)
                    else_lex = {k: list(v) for k, v in pre_lex.items()}
                    ret_tags.extend(walk_stmts(stmt.orelse, else_env, else_lex))

                merged_env = _merge_env_branches(pre_env, then_env, else_env)
                env.clear()
                env.update(merged_env)

                merged_lex = _merge_if_maps(pre_lex, then_lex, else_lex, _dedup_lexical_entries)
                lexical_funcs.clear()
                lexical_funcs.update(merged_lex)
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                pre_env = dict(env)
                pre_lex = {k: list(v) for k, v in lexical_funcs.items()}
                body_env = dict(pre_env)
                body_lex = {k: list(v) for k, v in pre_lex.items()}
                ret_tags.extend(walk_stmts(stmt.body, body_env, body_lex))
                else_env = dict(pre_env)
                else_lex = {k: list(v) for k, v in pre_lex.items()}
                if stmt.orelse:
                    ret_tags.extend(walk_stmts(stmt.orelse, else_env, else_lex))
                for k in set(body_env.keys()) | set(else_env.keys()):
                    if body_env.get(k) != pre_env.get(k) or else_env.get(k) != pre_env.get(k):
                        env[k] = _merge_tags(
                            pre_env.get(k, ()), body_env.get(k, ()), else_env.get(k, ())
                        )
                for k in set(body_lex.keys()) | set(else_lex.keys()):
                    if body_lex.get(k) != pre_lex.get(k) or else_lex.get(k) != pre_lex.get(k):
                        lexical_funcs[k] = _dedup_lexical_entries(
                            [*pre_lex.get(k, []), *body_lex.get(k, []), *else_lex.get(k, [])]
                        )
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                ret_tags.extend(walk_stmts(stmt.body, env, lexical_funcs))
            elif isinstance(stmt, ast.Try):
                pre_env = dict(env)
                pre_lex = {k: list(v) for k, v in lexical_funcs.items()}
                try_env = dict(pre_env)
                try_lex = {k: list(v) for k, v in pre_lex.items()}
                ret_tags.extend(walk_stmts(stmt.body, try_env, try_lex))
                if stmt.orelse:
                    ret_tags.extend(walk_stmts(stmt.orelse, try_env, try_lex))
                merged_try_env = dict(try_env)
                merged_try_lex = {k: list(v) for k, v in try_lex.items()}
                for handler in stmt.handlers:
                    h_env = dict(pre_env)
                    h_lex = {k: list(v) for k, v in pre_lex.items()}
                    ret_tags.extend(walk_stmts(handler.body, h_env, h_lex))
                    for k, h_val in h_env.items():
                        if h_val != pre_env.get(k):
                            merged_try_env[k] = _merge_tags(merged_try_env.get(k, ()), h_val)
                    for k, h_fval in h_lex.items():
                        if h_fval != pre_lex.get(k):
                            merged_try_lex[k] = _dedup_lexical_entries(
                                [*merged_try_lex.get(k, []), *h_fval]
                            )
                env.clear()
                env.update(merged_try_env)
                lexical_funcs.clear()
                lexical_funcs.update(merged_try_lex)
                if stmt.finalbody:
                    ret_tags.extend(walk_stmts(stmt.finalbody, env, lexical_funcs))
        return _merge_tags(ret_tags)

    def run_function(
        fn: ast.FunctionDef | ast.AsyncFunctionDef,
        bound: dict[str, tuple[str, ...]],
        closure_env: dict[str, tuple[str, ...]],
        parent_lexical: dict[
            str,
            list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, dict[str, tuple[str, ...]]]],
        ],
        *,
        is_uncalled_sweep: bool = False,
    ) -> tuple[str, ...]:
        key = (
            id(fn),
            tuple(sorted(bound.items())),
            tuple(sorted(closure_env.items())),
            is_uncalled_sweep,
        )
        if key in completed_returns:
            return completed_returns[key]
        if key in active_calls:
            return ()
        active_calls.add(key)
        try:
            local_env: dict[str, tuple[str, ...]] = dict(closure_env)
            local_lexical: dict[
                str,
                list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, dict[str, tuple[str, ...]]]],
            ] = {k: list(v) for k, v in parent_lexical.items()}
            all_params = (
                [a.arg for a in fn.args.posonlyargs]
                + [a.arg for a in fn.args.args]
                + [a.arg for a in fn.args.kwonlyargs]
            )
            param_prefix = "sweep_param" if is_uncalled_sweep else "param"
            for p in all_params:
                if p in bound:
                    local_env[p] = bound[p]
                elif p not in local_env:
                    local_env[p] = (f"{param_prefix}:{id(fn)}:{p}",)
            ret = walk_stmts(fn.body, local_env, local_lexical)
        finally:
            active_calls.discard(key)
        completed_returns[key] = ret
        return ret

    static_callee_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                static_callee_names.add(node.func.id)
            elif isinstance(node.func, ast.Attribute):
                static_callee_names.add(node.func.attr)

    top_env: dict[str, tuple[str, ...]] = {}
    top_lexical: dict[
        str,
        list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, dict[str, tuple[str, ...]]]],
    ] = {}
    top_stmts = [n for n in tree.body if not isinstance(n, ast.ClassDef)]
    walk_stmts(top_stmts, top_env, top_lexical)

    def _run_uncalled_sweep(only_entry_roots: bool) -> None:
        for fn_name, fn_list in module_funcs.items():
            if only_entry_roots and fn_name in static_callee_names:
                continue
            for fn in fn_list:
                if id(fn) not in directly_called_func_ids:
                    run_function(fn, {}, top_env, top_lexical, is_uncalled_sweep=True)

        for cls_name, methods in class_methods.items():
            for m_name, m_list in methods.items():
                if only_entry_roots and m_name in static_callee_names:
                    continue
                for m_fn in m_list:
                    if id(m_fn) not in directly_called_func_ids:
                        pos_names = [a.arg for a in m_fn.args.posonlyargs] + [
                            a.arg for a in m_fn.args.args
                        ]
                        m_bound: dict[str, tuple[str, ...]] = {}
                        if pos_names and pos_names[0] in ("self", "cls"):
                            m_bound[pos_names[0]] = (f"instance:{cls_name}",)
                        run_function(m_fn, m_bound, top_env, top_lexical, is_uncalled_sweep=True)

    _run_uncalled_sweep(only_entry_roots=True)
    _run_uncalled_sweep(only_entry_roots=False)

    for n_fn in all_nested_funcs:
        if id(n_fn) not in directly_called_func_ids:
            run_function(n_fn, {}, {}, {}, is_uncalled_sweep=True)

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
    for tag, fls in flags_by_tag.items():
        if tag.startswith("param:"):
            root_flags.update(fls)
        elif tag.startswith("sweep_param:"):
            parts = tag.split(":", 2)
            if len(parts) >= 2 and parts[1].isdigit():
                if int(parts[1]) not in directly_called_func_ids:
                    root_flags.update(fls)

    if subcommand_names:
        for rtag in subparser_roots:
            root_flags.update(collect_inherited(rtag))
        for tag, fls in flags_by_tag.items():
            if tag.startswith("parser:") and tag not in parent_sources and tag not in subparser_roots:
                root_flags.update(fls)
    else:
        for tag, fls in flags_by_tag.items():
            if not tag.startswith(("sub:", "param:", "sweep_param:")):
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
                        segs = _split_shell_segments(b_line)
                        for seg_idx, seg in enumerate(segs):
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
                                # 1 セグメントに複数スクリプト混在、または別コマンド連結時は誤帰属を避けてリセット
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
            # 地の文では単一スクリプト名を含むインラインコード片のみから抽出する
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
