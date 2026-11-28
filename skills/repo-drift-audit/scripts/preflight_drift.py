#!/usr/bin/env python3
"""repo-drift-audit 向け API キー不要の決定論的プリフライト＆トラック分割 CLI。

`scan`（仕様 ID 双方向照合、巨大ファイル抽出、SHA-256 重複検出、不在パス・不在 CLI フラグ集約）と
`plan-tracks`（verdict == 'confirmed' 抽出、Union-Find 排他トラック算出、仮採番衝突検出）を提供する。
"""

from __future__ import annotations

import argparse
import ast
from collections import defaultdict
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import sys
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

_DECISIONS_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "gemini-decisions-api" / "scripts"
if str(_DECISIONS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_DECISIONS_SCRIPTS_DIR))

import decision_common  # noqa: E402
import drift_format  # noqa: E402
import drift_repo  # noqa: E402

DEFAULT_LOC_THRESHOLD = 800
DEFAULT_SPEC_ID_PATTERNS: tuple[str, ...] = (r"[A-Z]{2,6}-\d{2,4}",)

DOC_EXTS: frozenset[str] = frozenset({".md", ".mdx", ".rst"})
SOURCE_CODE_EXTS: frozenset[str] = frozenset(
    {
        ".py",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".jsx",
        ".sh",
        ".bash",
        ".ps1",
        ".psm1",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".rb",
        ".php",
        ".c",
        ".cpp",
        ".cc",
        ".h",
        ".hpp",
        ".cs",
        ".swift",
        ".sql",
        ".css",
        ".scss",
        ".html",
    }
)

SECRET_BASENAMES: frozenset[str] = frozenset(
    {
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "credentials.json",
        "secrets.json",
        "service-account.json",
    }
)
SECRET_SUFFIXES: frozenset[str] = frozenset({".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"})
TEST_DIR_NAMES: frozenset[str] = frozenset({"test", "tests", "__tests__"})
TEST_FILENAME_RE = re.compile(
    r"(?:^test_.*|_test\.[^.]+|\.test\.[^.]+|\.spec\.[^.]+)$",
    re.IGNORECASE,
)
VALID_VERDICTS: frozenset[str] = frozenset({"confirmed", "false_positive", "already_resolved"})


@dataclass
class _UnionFind:
    parent: list[int]

    @classmethod
    def create(cls, n: int) -> "_UnionFind":
        return cls(parent=list(range(n)))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra = self.find(a)
        rb = self.find(b)
        if ra == rb:
            return
        if ra < rb:
            self.parent[rb] = ra
        else:
            self.parent[ra] = rb


def _is_secret_file(path: Path | str) -> bool:
    if drift_repo.is_blocked_env_path(path):
        return True
    name = str(path).replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name in SECRET_BASENAMES:
        return True
    return Path(name).suffix.lower() in SECRET_SUFFIXES


def _is_test_file(rel_posix: str) -> bool:
    parts = rel_posix.split("/")
    if any(seg.lower() in TEST_DIR_NAMES for seg in parts[:-1]):
        return True
    return bool(TEST_FILENAME_RE.match(parts[-1]))


def _compile_spec_patterns(raw_patterns: list[str]) -> tuple[list[str], list[re.Pattern[str]]]:
    patterns = raw_patterns if raw_patterns else list(DEFAULT_SPEC_ID_PATTERNS)
    compiled: list[re.Pattern[str]] = []
    for pat in patterns:
        if not pat:
            raise drift_repo.DriftScreenError(
                "invalid_spec_id_pattern",
                "--spec-id-pattern に空文字列は指定できません。",
                exit_code=2,
            )
        try:
            compiled.append(re.compile(pat))
        except re.error as exc:
            raise drift_repo.DriftScreenError(
                "invalid_spec_id_pattern",
                f"--spec-id-pattern の正規表現が不正です ({pat}): {exc}",
                exit_code=2,
            ) from exc
    return patterns, compiled


def _extract_spec_ids_from_text(
    text: str,
    rel_posix: str,
    patterns: list[re.Pattern[str]],
    dest: dict[str, list[str]],
) -> None:
    for line_no, line in enumerate(text.splitlines(), start=1):
        seen_in_line: set[str] = set()
        for rx in patterns:
            for match in rx.finditer(line):
                token = match.group(0)
                if token and token not in seen_in_line:
                    seen_in_line.add(token)
                    dest[token].append(f"{rel_posix}:{line_no}")


def _count_python_top_level_defs(text: str, rel_posix: str) -> int | None:
    try:
        tree = ast.parse(text, filename=rel_posix)
    except SyntaxError:
        return None
    return sum(
        1
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )


def _read_safe_text_and_bytes(
    repo_root: Path,
    rel_posix: str,
) -> tuple[bytes, str] | tuple[None, str]:
    """シークレット・シンボリックリンク・バイナリを安全に除外してバイト列と UTF-8 本文を返す。"""
    full = repo_root / rel_posix
    if _is_secret_file(full):
        return None, "secret"
    if not os.path.lexists(full) or drift_repo.is_reparse_or_symlink(full):
        return None, "symlink"
    try:
        full.resolve().relative_to(repo_root)
    except ValueError:
        return None, "symlink"
    if not full.is_file():
        return None, "missing"
    try:
        raw_bytes = full.read_bytes()
    except OSError:
        return None, "unreadable"
    if b"\x00" in raw_bytes:
        return None, "binary"
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None, "binary"
    return raw_bytes, text


def run_scan(
    repo_path: Path,
    *,
    loc_threshold: int = DEFAULT_LOC_THRESHOLD,
    spec_id_patterns: list[str] | None = None,
    exclude_globs: list[str] | None = None,
) -> dict[str, Any]:
    """決定論的プリフライトの 4 検査を実行し、構造化レポート辞書を返す。"""
    if isinstance(loc_threshold, bool) or loc_threshold < 1:
        raise drift_repo.DriftScreenError(
            "invalid_loc_threshold",
            "--loc-threshold は 1 以上の整数を指定してください。",
            exit_code=2,
        )

    pattern_strs, compiled_patterns = _compile_spec_patterns(spec_id_patterns or [])
    exclude_regexes = [decision_common.glob_to_regex(pat) for pat in (exclude_globs or [])]
    default_doc_excludes = [
        decision_common.glob_to_regex(pat) for pat in drift_repo.DEFAULT_EXCLUDED_DOC_GLOBS
    ]

    ctx = drift_repo.collect_repo_context(repo_path, git_log_limit=0)

    doc_locs: dict[str, list[str]] = defaultdict(list)
    code_non_test_locs: dict[str, list[str]] = defaultdict(list)
    code_test_locs: dict[str, list[str]] = defaultdict(list)
    code_all_locs: dict[str, list[str]] = defaultdict(list)
    huge_files: list[dict[str, Any]] = []
    hash_groups: dict[tuple[str, int], list[str]] = defaultdict(list)
    doc_hints: list[dict[str, Any]] = []

    skipped = {"excluded": 0, "secret": 0, "symlink": 0, "binary": 0, "other": 0}
    scanned_files = 0
    docs_scanned = 0
    source_files_scanned = 0

    for rel in ctx.repo_files:
        if any(rx.match(rel) for rx in exclude_regexes):
            skipped["excluded"] += 1
            continue

        raw_bytes, text_or_reason = _read_safe_text_and_bytes(ctx.repo_root, rel)
        if raw_bytes is None:
            key = text_or_reason if text_or_reason in skipped else "other"
            skipped[key] += 1
            continue

        scanned_files += 1
        text = text_or_reason
        suffix = Path(rel).suffix.lower()
        is_excluded_doc = any(rx.match(rel) for rx in default_doc_excludes)

        if raw_bytes:
            digest = hashlib.sha256(raw_bytes).hexdigest()
            hash_groups[(digest, len(raw_bytes))].append(rel)

        if suffix in DOC_EXTS and not is_excluded_doc:
            docs_scanned += 1
            _extract_spec_ids_from_text(text, rel, compiled_patterns, doc_locs)
            if suffix == ".md":
                missing_paths = drift_repo.extract_missing_path_hints(text, rel, ctx)
                missing_flags = drift_repo.extract_missing_flag_hints(text, rel, ctx)
                if missing_paths or missing_flags:
                    doc_hints.append(
                        {
                            "file": rel,
                            "missing_path_hints": missing_paths,
                            "missing_flag_hints": missing_flags,
                        }
                    )

        if suffix in SOURCE_CODE_EXTS:
            source_files_scanned += 1
            is_test = _is_test_file(rel)
            _extract_spec_ids_from_text(text, rel, compiled_patterns, code_all_locs)
            if is_test:
                _extract_spec_ids_from_text(text, rel, compiled_patterns, code_test_locs)
            else:
                _extract_spec_ids_from_text(text, rel, compiled_patterns, code_non_test_locs)

            loc = len(text.splitlines())
            if loc > loc_threshold:
                top_defs = _count_python_top_level_defs(text, rel) if suffix == ".py" else None
                huge_files.append(
                    {
                        "file": rel,
                        "loc": loc,
                        "top_level_defs": top_defs,
                    }
                )

    huge_files.sort(key=lambda item: (-item["loc"], item["file"]))

    duplicate_groups = [
        {
            "sha256": digest,
            "size_bytes": size_bytes,
            "count": len(files),
            "files": sorted(files),
        }
        for (digest, size_bytes), files in hash_groups.items()
        if len(files) >= 2
    ]
    duplicate_groups.sort(key=lambda g: (-g["count"], -g["size_bytes"], g["files"][0]))

    doc_only_ids = [
        {"id": spec_id, "locations": doc_locs[spec_id]}
        for spec_id in sorted(doc_locs)
        if spec_id not in code_all_locs
    ]
    doc_only_excluding_tests = [
        {
            "id": spec_id,
            "locations": doc_locs[spec_id],
            "test_locations": code_test_locs.get(spec_id, []),
        }
        for spec_id in sorted(doc_locs)
        if spec_id not in code_non_test_locs
    ]
    code_only_ids = [
        {
            "id": spec_id,
            "locations": code_all_locs[spec_id],
            "non_test_locations": code_non_test_locs.get(spec_id, []),
            "test_locations": code_test_locs.get(spec_id, []),
            "is_test_only": spec_id not in code_non_test_locs,
        }
        for spec_id in sorted(code_all_locs)
        if spec_id not in doc_locs
    ]
    code_only_excluding_tests = [entry for entry in code_only_ids if not entry["is_test_only"]]

    return {
        "status": "completed",
        "subcommand": "scan",
        "repo": ctx.repo_root.name,
        "is_git": ctx.is_git,
        "loc_threshold": loc_threshold,
        "summary": {
            "total_repo_files": len(ctx.repo_files),
            "scanned_files": scanned_files,
            "docs_scanned": docs_scanned,
            "source_files_scanned": source_files_scanned,
            "doc_only_id_count": len(doc_only_ids),
            "doc_only_excluding_tests_count": len(doc_only_excluding_tests),
            "code_only_id_count": len(code_only_ids),
            "code_only_excluding_tests_count": len(code_only_excluding_tests),
            "huge_file_count": len(huge_files),
            "duplicate_group_count": len(duplicate_groups),
            "doc_hint_file_count": len(doc_hints),
            "skipped": skipped,
        },
        "spec_id_audit": {
            "patterns": pattern_strs,
            "doc_id_count": len(doc_locs),
            "code_id_count_excluding_tests": len(code_non_test_locs),
            "code_id_count_including_tests": len(code_all_locs),
            "doc_only_ids": doc_only_ids,
            "doc_only_excluding_tests": doc_only_excluding_tests,
            "code_only_ids": code_only_ids,
            "code_only_excluding_tests": code_only_excluding_tests,
        },
        "huge_files": huge_files,
        "duplicate_groups": duplicate_groups,
        "doc_hints": doc_hints,
    }


def _safe_candidate_text(text: str) -> str:
    return drift_repo.mask_secret(text)


def build_candidates_from_scan(scan_report: dict[str, Any]) -> list[dict[str, Any]]:
    """`scan` 結果から `screen_drift_decision1.py candidates --stdin` 互換配列を構築する。"""
    candidates: list[dict[str, Any]] = []
    seq = 0

    def _next_id(prefix: str) -> str:
        nonlocal seq
        seq += 1
        return f"PFD-{prefix}-{seq:04d}"

    for entry in scan_report.get("doc_hints") or []:
        rel = entry["file"]
        missing_paths = entry.get("missing_path_hints") or []
        missing_flags = entry.get("missing_flag_hints") or []
        ev_parts: list[str] = []
        if missing_paths:
            ev_parts.append(f"missing_path_hints: {', '.join(missing_paths)}")
        if missing_flags:
            ev_parts.append(f"missing_flag_hints: {', '.join(missing_flags)}")
        candidates.append(
            {
                "id": _next_id("DOC"),
                "category": "doc_drift",
                "title": f"Broken path or CLI flag references in {rel}",
                "files": [rel],
                "evidence": _safe_candidate_text("; ".join(ev_parts)),
                "symptom": "Documentation references missing file paths or undefined CLI flags.",
                "estimated_scope": "single_track",
            }
        )

    loc_threshold = scan_report.get("loc_threshold", DEFAULT_LOC_THRESHOLD)
    for hf in scan_report.get("huge_files") or []:
        rel = hf["file"]
        top_defs = hf.get("top_level_defs")
        def_note = f", top_level_defs={top_defs}" if top_defs is not None else ""
        candidates.append(
            {
                "id": _next_id("HUGE"),
                "category": "structure",
                "title": f"Oversized source file {rel} ({hf['loc']} LOC)",
                "files": [rel],
                "evidence": _safe_candidate_text(
                    f"{rel}: {hf['loc']} lines (threshold={loc_threshold}{def_note})"
                ),
                "symptom": "Source file exceeds LOC threshold and should be checked for modular split.",
                "estimated_scope": "single_track",
            }
        )

    for grp in scan_report.get("duplicate_groups") or []:
        files = list(grp.get("files") or [])
        candidates.append(
            {
                "id": _next_id("DUP"),
                "category": "duplication",
                "title": f"Duplicate file group ({len(files)} identical files)",
                "files": files,
                "evidence": _safe_candidate_text(
                    f"sha256={grp['sha256'][:16]}... size={grp['size_bytes']}B files={', '.join(files)}"
                ),
                "symptom": "Non-empty files have identical SHA-256 content.",
                "estimated_scope": "single_track",
            }
        )

    spec_audit = scan_report.get("spec_id_audit") or {}
    doc_only_by_file: dict[str, list[str]] = defaultdict(list)
    for item in spec_audit.get("doc_only_ids") or []:
        spec_id = item["id"]
        for loc in item.get("locations") or []:
            fpath = loc.rsplit(":", 1)[0]
            doc_only_by_file[fpath].append(f"{spec_id} ({loc})")

    for fpath in sorted(doc_only_by_file):
        items = doc_only_by_file[fpath]
        preview = ", ".join(items[:20])
        if len(items) > 20:
            preview += f" ... (+{len(items) - 20} more)"
        candidates.append(
            {
                "id": _next_id("SPEC"),
                "category": "spec_id_drift",
                "title": f"Doc-only spec IDs in {fpath} ({len(items)})",
                "files": [fpath],
                "evidence": _safe_candidate_text(preview),
                "symptom": "Specification IDs in document have no matching code occurrences.",
                "estimated_scope": "single_track",
            }
        )

    code_only_by_file: dict[str, list[str]] = defaultdict(list)
    for item in spec_audit.get("code_only_excluding_tests") or []:
        spec_id = item["id"]
        for loc in item.get("non_test_locations") or []:
            fpath = loc.rsplit(":", 1)[0]
            code_only_by_file[fpath].append(f"{spec_id} ({loc})")

    for fpath in sorted(code_only_by_file):
        items = code_only_by_file[fpath]
        preview = ", ".join(items[:20])
        if len(items) > 20:
            preview += f" ... (+{len(items) - 20} more)"
        candidates.append(
            {
                "id": _next_id("SPEC"),
                "category": "spec_id_drift",
                "title": f"Code-only spec IDs in {fpath} ({len(items)})",
                "files": [fpath],
                "evidence": _safe_candidate_text(preview),
                "symptom": "Specification IDs in non-test code have no matching doc occurrences.",
                "estimated_scope": "single_track",
            }
        )

    return candidates


def format_scan_markdown(report: dict[str, Any]) -> str:
    """`scan` 結果を人間可読な Markdown レポートへ整形する。"""
    s = report["summary"]
    spec = report["spec_id_audit"]
    lines = [
        f"# Preflight Drift Scan ({report['repo']})",
        "",
        f"- Scanned files: {s['scanned_files']} / {s['total_repo_files']} (docs={s['docs_scanned']}, code={s['source_files_scanned']})",
        f"- Spec IDs: doc_only={s['doc_only_id_count']} (excluding_tests={s['doc_only_excluding_tests_count']}), "
        f"code_only={s['code_only_id_count']} (excluding_tests={s['code_only_excluding_tests_count']})",
        f"- Huge source files (>{report['loc_threshold']} LOC): {s['huge_file_count']}",
        f"- Duplicate SHA-256 groups: {s['duplicate_group_count']}",
        f"- Docs with missing path/flag hints: {s['doc_hint_file_count']}",
        "",
        "## 1. Spec ID Bidirectional Audit",
        "",
        "### Doc-only IDs",
        "",
    ]
    if spec["doc_only_ids"]:
        lines.extend(["| id | locations |", "| --- | --- |"])
        for entry in spec["doc_only_ids"]:
            locs = ", ".join(entry["locations"])
            lines.append(
                f"| {decision_common.escape_md_cell(entry['id'])} | {decision_common.escape_md_cell(locs)} |"
            )
    else:
        lines.append("(none)")

    lines.extend(["", "### Code-only IDs (excluding tests)", ""])
    if spec["code_only_excluding_tests"]:
        lines.extend(["| id | locations |", "| --- | --- |"])
        for entry in spec["code_only_excluding_tests"]:
            locs = ", ".join(entry["non_test_locations"])
            lines.append(
                f"| {decision_common.escape_md_cell(entry['id'])} | {decision_common.escape_md_cell(locs)} |"
            )
    else:
        lines.append("(none)")

    lines.extend(["", f"## 2. Huge Source Files (>{report['loc_threshold']} LOC)", ""])
    if report["huge_files"]:
        lines.extend(["| file | loc | top_level_defs |", "| --- | ---: | ---: |"])
        for hf in report["huge_files"]:
            defs_val = hf["top_level_defs"]
            defs_str = str(defs_val) if defs_val is not None else "-"
            lines.append(
                f"| {decision_common.escape_md_cell(hf['file'])} | {hf['loc']} | {defs_str} |"
            )
    else:
        lines.append("(none)")

    lines.extend(["", "## 3. SHA-256 Duplicate Groups", ""])
    if report["duplicate_groups"]:
        lines.extend(["| sha256 | size_bytes | count | files |", "| --- | ---: | ---: | --- |"])
        for grp in report["duplicate_groups"]:
            lines.append(
                f"| `{grp['sha256'][:12]}` | {grp['size_bytes']} | {grp['count']} | "
                f"{decision_common.escape_md_cell(', '.join(grp['files']))} |"
            )
    else:
        lines.append("(none)")

    lines.extend(["", "## 4. Missing Path and CLI Flag Hints", ""])
    if report["doc_hints"]:
        lines.extend(["| file | missing_path_hints | missing_flag_hints |", "| --- | --- | --- |"])
        for dh in report["doc_hints"]:
            mp = ", ".join(dh["missing_path_hints"]) if dh["missing_path_hints"] else "-"
            mf = ", ".join(dh["missing_flag_hints"]) if dh["missing_flag_hints"] else "-"
            lines.append(
                f"| {decision_common.escape_md_cell(dh['file'])} | "
                f"{decision_common.escape_md_cell(mp)} | {decision_common.escape_md_cell(mf)} |"
            )
    else:
        lines.append("(none)")

    return "\n".join(lines)


def _load_plans_json(
    plans_path: str | None,
    use_stdin: bool,
    stdin_text: str | None,
) -> Any:
    if bool(plans_path) == bool(use_stdin):
        raise drift_repo.DriftScreenError(
            "invalid_input_source",
            "--plans-json <path> または --stdin のどちらか一方だけを指定してください。",
            exit_code=2,
        )

    if plans_path:
        path = Path(plans_path)
        drift_repo.assert_safe_file_path(path, "--plans-json")
        if os.path.lexists(path) and drift_repo.is_reparse_or_symlink(path):
            raise drift_repo.DriftScreenError(
                "unsafe_plans_file",
                f"--plans-json にシンボリックリンクまたはリパースポイントは指定できません: {plans_path}",
                exit_code=2,
            )
        if not path.is_file():
            raise drift_repo.DriftScreenError(
                "plans_file_not_found",
                f"--plans-json ファイルが見つかりません: {plans_path}",
                exit_code=2,
            )
        try:
            raw_text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise drift_repo.DriftScreenError(
                "plans_file_read_error",
                f"--plans-json を読み込めません ({plans_path}): {exc}",
                exit_code=2,
            ) from exc
        drift_repo.assert_text_has_no_secrets(raw_text, f"--plans-json ({path.name})")
    else:
        raw_text = stdin_text if stdin_text is not None else sys.stdin.read()
        drift_repo.assert_text_has_no_secrets(raw_text, "--stdin")

    try:
        return json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise drift_repo.DriftScreenError(
            "invalid_json",
            f"計画出力 JSON の構文が不正です: {exc}",
            exit_code=2,
        ) from exc


def _normalize_target_file(raw_path: str, idx: int, f_idx: int) -> str:
    cleaned = decision_common.normalize_posix_rel_path(raw_path)
    if not cleaned:
        raise drift_repo.DriftScreenError(
            "invalid_input_schema",
            f"plans[{idx}].target_files[{f_idx}] が空です。",
            exit_code=2,
        )
    norm = posixpath.normpath(cleaned)
    if norm in (".", "..") or norm.startswith("../") or norm.startswith("/"):
        raise drift_repo.DriftScreenError(
            "invalid_input_schema",
            f"plans[{idx}].target_files[{f_idx}] が不正な相対パスです: {raw_path}",
            exit_code=2,
        )
    drift_repo.assert_safe_file_path(norm, f"plans[{idx}].target_files[{f_idx}]")
    return norm


def run_plan_tracks(raw_data: Any) -> dict[str, Any]:
    """計画ワーカー出力配列から排他トラック・非実装仕分け・仮採番衝突レポートを算出する。"""
    if not isinstance(raw_data, list):
        raise drift_repo.DriftScreenError(
            "invalid_input_schema",
            "plan-tracks 入力 JSON のトップレベルは配列である必要があります。",
            exit_code=2,
        )

    confirmed_items: list[dict[str, Any]] = []
    false_positive_items: list[dict[str, Any]] = []
    already_resolved_items: list[dict[str, Any]] = []
    used_ids: set[str] = set()

    for idx, row in enumerate(raw_data):
        if not isinstance(row, dict):
            raise drift_repo.DriftScreenError(
                "invalid_input_schema",
                f"plans[{idx}] は JSON オブジェクトである必要があります。",
                exit_code=2,
            )
        for field_name, val in drift_repo._iter_string_fields(row, f"plans[{idx}]"):
            drift_repo.assert_text_has_no_secrets(val, field_name)

        verdict = row.get("verdict")
        if not isinstance(verdict, str) or verdict not in VALID_VERDICTS:
            raise drift_repo.DriftScreenError(
                "invalid_input_schema",
                f"plans[{idx}].verdict は {sorted(VALID_VERDICTS)} のいずれかである必要があります。",
                exit_code=2,
            )

        raw_id = None
        for key in ("id", "item_id", "slug"):
            cand = row.get(key)
            if isinstance(cand, str) and cand.strip():
                raw_id = cand.strip()
                break
        if raw_id is None:
            plan_path_val = row.get("plan_path")
            if isinstance(plan_path_val, str) and plan_path_val.strip():
                raw_id = Path(plan_path_val.strip()).stem or None
        if raw_id is None:
            raw_id = f"plan_{idx + 1:04d}"

        item_id = raw_id
        if item_id in used_ids:
            suffix = 2
            while f"{raw_id}_{suffix}" in used_ids:
                suffix += 1
            item_id = f"{raw_id}_{suffix}"
        used_ids.add(item_id)

        raw_targets = row.get("target_files")
        norm_targets: list[str] = []
        if raw_targets is None:
            norm_targets = []
        elif isinstance(raw_targets, list):
            seen_targets: set[str] = set()
            for f_idx, f_val in enumerate(raw_targets):
                if not isinstance(f_val, str):
                    raise drift_repo.DriftScreenError(
                        "invalid_input_schema",
                        f"plans[{idx}].target_files[{f_idx}] は文字列である必要があります。",
                        exit_code=2,
                    )
                norm = _normalize_target_file(f_val, idx, f_idx)
                if norm not in seen_targets:
                    seen_targets.add(norm)
                    norm_targets.append(norm)
            norm_targets.sort()
        else:
            raise drift_repo.DriftScreenError(
                "invalid_input_schema",
                f"plans[{idx}].target_files は文字列配列である必要があります。",
                exit_code=2,
            )

        raw_prov = row.get("provisional_ids")
        prov_ids: list[str] = []
        if raw_prov is None:
            prov_ids = []
        elif isinstance(raw_prov, list):
            for p_idx, p_val in enumerate(raw_prov):
                if not isinstance(p_val, str) or not p_val.strip():
                    raise drift_repo.DriftScreenError(
                        "invalid_input_schema",
                        f"plans[{idx}].provisional_ids[{p_idx}] は空でない文字列である必要があります。",
                        exit_code=2,
                    )
                prov_ids.append(p_val.strip())
        else:
            raise drift_repo.DriftScreenError(
                "invalid_input_schema",
                f"plans[{idx}].provisional_ids は文字列配列である必要があります。",
                exit_code=2,
            )

        summary_val = row.get("summary") if isinstance(row.get("summary"), str) else ""
        plan_path_str = row.get("plan_path") if isinstance(row.get("plan_path"), str) else None

        entry = {
            "id": item_id,
            "verdict": verdict,
            "summary": summary_val,
            "plan_path": plan_path_str,
            "target_files": norm_targets,
            "provisional_ids": sorted(set(prov_ids)),
        }
        if verdict == "confirmed":
            confirmed_items.append(entry)
        elif verdict == "false_positive":
            false_positive_items.append(
                {"id": item_id, "summary": summary_val, "plan_path": plan_path_str}
            )
        else:
            already_resolved_items.append(
                {"id": item_id, "summary": summary_val, "plan_path": plan_path_str}
            )

    uf = _UnionFind.create(len(confirmed_items))
    file_to_indices: dict[str, list[int]] = defaultdict(list)
    for idx, item in enumerate(confirmed_items):
        for fpath in item["target_files"]:
            file_to_indices[fpath].append(idx)

    for indices in file_to_indices.values():
        first = indices[0]
        for other in indices[1:]:
            uf.union(first, other)

    components: dict[int, list[int]] = defaultdict(list)
    for idx in range(len(confirmed_items)):
        components[uf.find(idx)].append(idx)

    ordered_components = sorted(components.values(), key=lambda grp: min(grp))
    tracks: list[dict[str, Any]] = []
    pid_claims: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: {"item_ids": set(), "track_ids": set()}
    )

    for track_num, member_indices in enumerate(ordered_components, start=1):
        track_id = f"track_{track_num:02d}"
        item_ids = [confirmed_items[i]["id"] for i in member_indices]
        exclusive_files = sorted(
            {f for i in member_indices for f in confirmed_items[i]["target_files"]}
        )
        conflict_reasons: list[str] = []
        for fpath in exclusive_files:
            touching = [
                confirmed_items[i]["id"]
                for i in member_indices
                if fpath in confirmed_items[i]["target_files"]
            ]
            if len(touching) >= 2:
                conflict_reasons.append(
                    f"共有ファイル {fpath} を複数項目（{', '.join(touching)}）が変更するため統合"
                )
        track_prov_ids = sorted(
            {pid for i in member_indices for pid in confirmed_items[i]["provisional_ids"]}
        )
        for i in member_indices:
            for pid in confirmed_items[i]["provisional_ids"]:
                pid_claims[pid]["item_ids"].add(confirmed_items[i]["id"])
                pid_claims[pid]["track_ids"].add(track_id)

        tracks.append(
            {
                "track_id": track_id,
                "item_ids": item_ids,
                "exclusive_files": exclusive_files,
                "conflict_reasons": conflict_reasons,
                "provisional_ids": track_prov_ids,
            }
        )

    all_provisional = [
        {
            "id": pid,
            "item_ids": sorted(claims["item_ids"]),
            "track_ids": sorted(claims["track_ids"]),
        }
        for pid, claims in sorted(pid_claims.items())
    ]
    collisions = [entry for entry in all_provisional if len(entry["item_ids"]) >= 2]

    return {
        "status": "completed",
        "subcommand": "plan-tracks",
        "summary": {
            "total_plans": len(raw_data),
            "confirmed": len(confirmed_items),
            "false_positive": len(false_positive_items),
            "already_resolved": len(already_resolved_items),
            "track_count": len(tracks),
            "provisional_id_count": len(all_provisional),
            "provisional_id_collisions": len(collisions),
        },
        "tracks": tracks,
        "false_positive": false_positive_items,
        "already_resolved": already_resolved_items,
        "provisional_ids": {
            "all": all_provisional,
            "collisions": collisions,
        },
    }


def format_plan_tracks_markdown(report: dict[str, Any]) -> str:
    """`plan-tracks` 結果を人間可読な Markdown レポートへ整形する。"""
    s = report["summary"]
    lines = [
        "# Implementation Track Plan",
        "",
        f"- Total plans: {s['total_plans']} (confirmed={s['confirmed']}, "
        f"false_positive={s['false_positive']}, already_resolved={s['already_resolved']})",
        f"- Exclusive tracks: {s['track_count']}",
        f"- Provisional IDs: {s['provisional_id_count']} (collisions={s['provisional_id_collisions']})",
        "",
        "## Confirmed Implementation Tracks",
        "",
    ]
    if report["tracks"]:
        lines.extend(
            [
                "| track_id | item_ids | exclusive_files | conflict_reasons | provisional_ids |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for tr in report["tracks"]:
            items_s = ", ".join(tr["item_ids"])
            files_s = ", ".join(tr["exclusive_files"]) if tr["exclusive_files"] else "-"
            conf_s = "; ".join(tr["conflict_reasons"]) if tr["conflict_reasons"] else "-"
            prov_s = ", ".join(tr["provisional_ids"]) if tr["provisional_ids"] else "-"
            lines.append(
                f"| {tr['track_id']} | {decision_common.escape_md_cell(items_s)} | "
                f"{decision_common.escape_md_cell(files_s)} | "
                f"{decision_common.escape_md_cell(conf_s)} | "
                f"{decision_common.escape_md_cell(prov_s)} |"
            )
    else:
        lines.append("(none)")

    lines.extend(["", "## False Positive", ""])
    if report["false_positive"]:
        for item in report["false_positive"]:
            lines.append(f"- `{item['id']}`: {item['summary'] or '-'}")
    else:
        lines.append("(none)")

    lines.extend(["", "## Already Resolved", ""])
    if report["already_resolved"]:
        for item in report["already_resolved"]:
            lines.append(f"- `{item['id']}`: {item['summary'] or '-'}")
    else:
        lines.append("(none)")

    lines.extend(["", "## Provisional IDs", ""])
    prov = report["provisional_ids"]
    if prov["collisions"]:
        lines.append("### Collisions")
        for col in prov["collisions"]:
            lines.append(
                f"- `{col['id']}`: items={', '.join(col['item_ids'])} tracks={', '.join(col['track_ids'])}"
            )
        lines.append("")
    if prov["all"]:
        lines.append("### All Provisional IDs")
        for entry in prov["all"]:
            lines.append(
                f"- `{entry['id']}`: items={', '.join(entry['item_ids'])} tracks={', '.join(entry['track_ids'])}"
            )
    else:
        lines.append("(none)")

    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="repo-drift-audit 向け API キー不要の決定論的プリフライト CLI"
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="仕様 ID 双方向照合、巨大ファイル抽出、SHA-256 重複、不在パス・不在フラグを実行する",
    )
    scan_parser.add_argument("--repo", default=".", help="対象リポジトリルート（既定: .）")
    scan_parser.add_argument(
        "--loc-threshold",
        type=int,
        default=DEFAULT_LOC_THRESHOLD,
        help="巨大ファイル判定の行数閾値（既定: 800）",
    )
    scan_parser.add_argument(
        "--spec-id-pattern",
        action="append",
        default=[],
        help="仕様 ID 抽出用の正規表現（複数指定可、省略時は [A-Z]{2,6}-\\d{2,4}）",
    )
    scan_parser.add_argument(
        "--exclude-glob",
        action="append",
        default=[],
        help="走査から除外する POSIX glob パターン（複数指定可）",
    )
    scan_parser.add_argument(
        "--format",
        choices=("json", "markdown", "candidates-json"),
        default="json",
        help="出力形式（既定: json）",
    )

    tracks_parser = subparsers.add_parser(
        "plan-tracks",
        help="計画ワーカー出力配列から排他トラック境界と仮採番衝突を算出する",
    )
    tracks_parser.add_argument(
        "--plans-json",
        default=None,
        help="計画ワーカー finish 出力配列の JSON ファイルパス",
    )
    tracks_parser.add_argument(
        "--stdin",
        action="store_true",
        help="標準入力から計画ワーカー finish 出力配列 JSON を読み込む",
    )
    tracks_parser.add_argument(
        "--format",
        choices=("json", "markdown"),
        default="json",
        help="出力形式（既定: json）",
    )

    return parser


def _write_output(text: str) -> bool:
    return decision_common.safe_write_stdout(text)


def main(
    argv: list[str] | None = None,
    *,
    stdin_text: str | None = None,
) -> int:
    """CLI 引数を解釈して scan または plan-tracks を実行し、終了コードを返す。"""
    drift_repo.configure_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    err_fmt = "json" if args.format in ("json", "candidates-json") else "text"

    try:
        if args.subcommand == "scan":
            report = run_scan(
                Path(args.repo),
                loc_threshold=args.loc_threshold,
                spec_id_patterns=args.spec_id_pattern,
                exclude_globs=args.exclude_glob,
            )
            if args.format == "candidates-json":
                text = json.dumps(
                    build_candidates_from_scan(report),
                    ensure_ascii=False,
                    indent=2,
                )
            elif args.format == "markdown":
                text = format_scan_markdown(report)
            else:
                text = json.dumps(report, ensure_ascii=False, indent=2)
            _write_output(text)
            return 0

        if args.subcommand == "plan-tracks":
            raw_data = _load_plans_json(args.plans_json, args.stdin, stdin_text)
            report = run_plan_tracks(raw_data)
            if args.format == "markdown":
                text = format_plan_tracks_markdown(report)
            else:
                text = json.dumps(report, ensure_ascii=False, indent=2)
            _write_output(text)
            return 0

        raise drift_repo.DriftScreenError(
            "unknown_subcommand",
            f"不明なサブコマンドです: {args.subcommand}",
            exit_code=2,
        )
    except OSError as exc:
        if decision_common.is_broken_pipe_error(exc):
            return 0
        drift_format.emit_error("unexpected_error", str(exc), 2, err_fmt, "")
        return 2
    except drift_repo.DriftScreenError as exc:
        drift_format.emit_error(exc.code, exc.message, exc.exit_code, err_fmt, "")
        return exc.exit_code
    except Exception as exc:  # noqa: BLE001
        if decision_common.is_broken_pipe_error(exc):
            return 0
        drift_format.emit_error("unexpected_error", str(exc), 2, err_fmt, "")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
