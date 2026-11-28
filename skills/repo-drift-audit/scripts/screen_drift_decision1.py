#!/usr/bin/env python3
"""repo-drift-audit 向け Gemini Decision 1 一次スクリーニング CLI（ファサード）。

`drift_repo.py` と `drift_format.py` の公開シンボルを再エクスポートしつつ、
docs（チャンク/単一）、backlog（見出しパンくず・Markdown 表対応）、
candidates（任意スナップショット・チャンク/単一）、SDK/REST 切替（--backend）を提供する。
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

_DECISIONS_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "gemini-decisions-api" / "scripts"
if str(_DECISIONS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_DECISIONS_SCRIPTS_DIR))

import decision_common  # noqa: E402
import drift_format  # noqa: E402
import drift_repo  # noqa: E402
import run_decisions  # noqa: E402

# --- drift_repo / drift_format 公開シンボルのファサード再エクスポート ---
DEFAULT_MODEL = drift_repo.DEFAULT_MODEL
DEFAULT_ENDPOINT = drift_repo.DEFAULT_ENDPOINT
DEFAULT_TIMEOUT = drift_repo.DEFAULT_TIMEOUT
DEFAULT_MAX_WORKERS = drift_repo.DEFAULT_MAX_WORKERS
DEFAULT_DOCS_MAX_CHARS = drift_repo.DEFAULT_DOCS_MAX_CHARS
DEFAULT_BACKLOG_MAX_CHARS = drift_repo.DEFAULT_BACKLOG_MAX_CHARS
DEFAULT_CANDIDATES_MAX_CHARS = drift_repo.DEFAULT_CANDIDATES_MAX_CHARS
MAX_QUESTIONS = drift_repo.MAX_QUESTIONS

DEFAULT_MIN_CONFIDENCE = drift_repo.DEFAULT_MIN_CONFIDENCE
DEFAULT_DISCUSSION_THRESHOLD = drift_repo.DEFAULT_DISCUSSION_THRESHOLD
DEFAULT_NOUL_CLEAN_CEILING = drift_repo.DEFAULT_NOUL_CLEAN_CEILING
DEFAULT_MECHANIZABLE_THRESHOLD = drift_repo.DEFAULT_MECHANIZABLE_THRESHOLD
DEFAULT_DOCS_GIT_LOG_LIMIT = drift_repo.DEFAULT_DOCS_GIT_LOG_LIMIT
DEFAULT_BACKLOG_GIT_LOG_LIMIT = drift_repo.DEFAULT_BACKLOG_GIT_LOG_LIMIT
MAX_REPO_FILES_IN_SNAPSHOT = drift_repo.MAX_REPO_FILES_IN_SNAPSHOT
BULK_STALENESS_MAX_PATHS = drift_repo.BULK_STALENESS_MAX_PATHS
BULK_STALENESS_MAX_CHARS = drift_repo.BULK_STALENESS_MAX_CHARS

DEFAULT_DOC_GLOBS = drift_repo.DEFAULT_DOC_GLOBS
DEFAULT_EXCLUDED_DOC_GLOBS = drift_repo.DEFAULT_EXCLUDED_DOC_GLOBS
DEFAULT_EXCLUDED_DIRS = drift_repo.DEFAULT_EXCLUDED_DIRS
SAFE_ENV_BASENAMES = drift_repo.SAFE_ENV_BASENAMES
SAFE_ENV_SUFFIXES = drift_repo.SAFE_ENV_SUFFIXES
PRIVATE_KEY_BLOCK_RE = drift_repo.PRIVATE_KEY_BLOCK_RE
PRIVATE_KEY_HEADER_RE = drift_repo.PRIVATE_KEY_HEADER_RE
SECRET_PATTERNS = drift_repo.SECRET_PATTERNS

FENCE_RE = drift_repo.FENCE_RE
MARKDOWN_LINK_RE = drift_repo.MARKDOWN_LINK_RE
INLINE_CODE_RE = drift_repo.INLINE_CODE_RE
UNCHECKED_TASK_RE = drift_repo.UNCHECKED_TASK_RE
QUESTION_KEY_SAFE_RE = drift_repo.QUESTION_KEY_SAFE_RE

DOCS_RECOMMENDED_ACTIONS = drift_repo.DOCS_RECOMMENDED_ACTIONS
DRIFT_SEVERITY_CRITERIA = drift_repo.DRIFT_SEVERITY_CRITERIA
BACKLOG_STATUS_CRITERIA = drift_repo.BACKLOG_STATUS_CRITERIA
CANDIDATES_IMPACT_CRITERIA = drift_repo.CANDIDATES_IMPACT_CRITERIA
CANDIDATES_DISPATCH_ROUTES = drift_repo.CANDIDATES_DISPATCH_ROUTES
VALID_BACKLOG_CHOICES = drift_repo.VALID_BACKLOG_CHOICES
VALID_DISPATCH_ROUTES = drift_repo.VALID_DISPATCH_ROUTES
LOW_PRIORITY_CLEAN_NOTE = drift_repo.LOW_PRIORITY_CLEAN_NOTE

DriftScreenError = drift_repo.DriftScreenError
RepoContext = drift_repo.RepoContext
DocEntry = drift_repo.DocEntry
BacklogItem = drift_repo.BacklogItem
AuditCandidate = drift_repo.AuditCandidate

configure_utf8_stdio = drift_repo.configure_utf8_stdio
mask_secret = drift_repo.mask_secret
scan_text_for_secrets = drift_repo.scan_text_for_secrets
is_blocked_env_path = drift_repo.is_blocked_env_path
is_reparse_or_symlink = drift_repo.is_reparse_or_symlink
_is_reparse_or_symlink = drift_repo._is_reparse_or_symlink
assert_safe_file_path = drift_repo.assert_safe_file_path
assert_text_has_no_secrets = drift_repo.assert_text_has_no_secrets
_iter_string_fields = drift_repo._iter_string_fields
_is_real_number = drift_repo._is_real_number
_extract_number = drift_repo._extract_number
_glob_to_regex = drift_repo._glob_to_regex

is_git_repo = drift_repo.is_git_repo
collect_repo_files = drift_repo.collect_repo_files
collect_git_log = drift_repo.collect_git_log
compute_staleness_days = drift_repo.compute_staleness_days
compute_staleness_days_bulk = drift_repo.compute_staleness_days_bulk
collect_repo_context = drift_repo.collect_repo_context
load_facts_blocks = drift_repo.load_facts_blocks
build_repo_snapshot_text = drift_repo.build_repo_snapshot_text
extract_missing_path_hints = drift_repo.extract_missing_path_hints
extract_missing_flag_hints = drift_repo.extract_missing_flag_hints
select_doc_files = drift_repo.select_doc_files
load_doc_entries = drift_repo.load_doc_entries

_aggregate_usage = drift_format._aggregate_usage
_escape_md_cell = drift_format._escape_md_cell
discard_broken_stdout = drift_format.discard_broken_stdout
format_report_table = drift_format.format_report_table
emit_report = drift_format.emit_report
emit_error = drift_format.emit_error

DEFAULT_CHUNK_MAX_DOCS = 15
MAX_CHUNK_MAX_DOCS = 166
DEFAULT_CHUNK_MAX_ITEMS = 50
MAX_CHUNK_MAX_ITEMS = 200
DEFAULT_CANDIDATES_GIT_LOG_LIMIT = 30

HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.+?)\s*$")
LIST_ITEM_START_RE = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
TABLE_SEP_RE = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(?:\|\s*:?-{2,}:?\s*)+\|?\s*$")
STATUS_HEADER_NAMES: frozenset[str] = frozenset({"状態", "ステータス", "status", "state"})
COMPLETED_TABLE_MARKERS: frozenset[str] = frozenset(
    {
        "完了",
        "済",
        "済み",
        "対応済",
        "対応済み",
        "終了",
        "クローズ",
        "見送り",
        "不要",
        "done",
        "closed",
        "resolved",
        "fixed",
        "wontfix",
        "won't fix",
        "completed",
        "complete",
        "cancelled",
        "canceled",
        "skipped",
        "n/a",
        "x",
        "[x]",
    }
)
INCOMPLETE_TABLE_MARKERS: frozenset[str] = frozenset(
    {
        "未着手",
        "未完了",
        "未対応",
        "進行中",
        "対応中",
        "作業中",
        "保留",
        "要確認",
        "オープン",
        "open",
        "todo",
        "to do",
        "to-do",
        "pending",
        "wip",
        "in progress",
        "in_progress",
        "in-progress",
        "blocked",
        "reopened",
        "new",
        "draft",
        "[ ]",
    }
)
INCOMPLETE_ASCII_WORD_RE = re.compile(
    r"\b(?:open|todo|to-do|pending|wip|in[\s_-]+progress|blocked|reopened)\b",
    re.IGNORECASE,
)
COMPLETED_ASCII_WORD_RE = re.compile(
    r"\b(?:done|closed|resolved|fixed|wontfix|completed?|cancell?ed|skipped)\b",
    re.IGNORECASE,
)
NEGATED_DONE_RE = re.compile(r"\b(?:not\s+done|undone|incomplete)\b", re.IGNORECASE)


def build_docs_questions() -> dict[str, dict[str, Any]]:
    """docs モード用の 6 問マップを構築する。"""
    return {
        "stale_status_or_facts": {
            "type": "noul",
            "instructions": (
                "Do the status statements, architecture descriptions, or operational "
                "instructions in this document conflict with the current repository files "
                "or recent commits?"
            ),
            "criteria": {
                "true_description": (
                    "The document states file paths, statuses, structures, or procedures "
                    "that conflict with or lag behind the current repository state."
                ),
                "false_description": (
                    "The document aligns with the current repository files and recent commit "
                    "history, or shows no verifiable discrepancy."
                ),
            },
        },
        "broken_or_obsolete_refs": {
            "type": "noul",
            "instructions": (
                "Does this document reference missing, renamed, or obsolete files, "
                "commands, symbols, or section numbers?"
            ),
            "criteria": {
                "true_description": (
                    "The document cites paths, commands, identifiers, or section references "
                    "that appear absent, renamed, or superseded in the repository snapshot."
                ),
                "false_description": (
                    "All referenced paths, commands, and identifiers appear valid against "
                    "the repository snapshot."
                ),
            },
        },
        "mechanizable_workflow": {
            "type": "noul",
            "instructions": (
                "Does this document describe deterministic workflow steps whose outputs are "
                "uniquely determined by inputs and rules rather than judgment?"
            ),
            "criteria": {
                "true_description": (
                    "The document contains repeatable procedural steps such as file placement, "
                    "ledger bookkeeping, numbering, or schema checks that could be scripted."
                ),
                "false_description": (
                    "The document mainly contains conceptual guidance, design trade-offs, "
                    "or tasks requiring human or model judgment."
                ),
            },
        },
        "needs_discussion": {
            "type": "noul",
            "instructions": (
                "Would resolving any apparent discrepancy or revising the procedures in "
                "this document require specification or policy decisions from the user?"
            ),
            "criteria": {
                "true_description": (
                    "Addressing the discrepancy or procedural change involves policy choices, "
                    "scope trade-offs, or specification decisions."
                ),
                "false_description": (
                    "Any needed updates are straightforward factual corrections or mechanical "
                    "cleanups."
                ),
            },
        },
        "drift_severity": {
            "type": "score",
            "instructions": (
                "How severe is the apparent drift between this document and the current "
                "repository state?"
            ),
            "criteria": list(DRIFT_SEVERITY_CRITERIA),
        },
        "recommended_action": {
            "type": "choice",
            "instructions": "Which audit action should be taken next for this document?",
            "criteria": dict(DOCS_RECOMMENDED_ACTIONS),
        },
    }


def _format_doc_block(entry: DocEntry, *, doc_ns: str | None = None) -> str:
    staleness_label = (
        f"{entry.staleness_days} days"
        if entry.staleness_days is not None
        else "unknown (non-git or untracked)"
    )
    hints_label = ", ".join(entry.missing_path_hints) if entry.missing_path_hints else "(none)"
    flags_label = ", ".join(entry.missing_flag_hints) if entry.missing_flag_hints else "(none)"
    header = (
        f"Document Path [{doc_ns}]: {entry.rel_path}"
        if doc_ns
        else f"Document Path: {entry.rel_path}"
    )
    return "\n".join(
        [
            header,
            f"Staleness Days (vs latest commit): {staleness_label}",
            f"Deterministic Missing Path Hints: {hints_label}",
            f"Deterministic Missing Flag Hints: {flags_label}",
            f"Document Content:\n```\n{entry.content}\n```\n",
        ]
    )


def build_doc_payload(
    entry: DocEntry,
    snapshot_text: str,
    *,
    model: str = DEFAULT_MODEL,
    max_chars: int = DEFAULT_DOCS_MAX_CHARS,
) -> dict[str, Any]:
    """docs モード 1 文書分の Decisions API ペイロードを構築・検証する。"""
    doc_block = _format_doc_block(entry)
    input_blocks = [
        {"type": "text", "text": snapshot_text + "\n\n"},
        {"type": "text", "text": doc_block},
    ]
    total_chars = sum(len(b["text"]) for b in input_blocks)
    if total_chars > max_chars:
        raise DriftScreenError(
            "input_size_limit_exceeded",
            (
                f"文書 {entry.rel_path} の入力文字数（{total_chars:,} 文字）が上限 "
                f"{max_chars:,} 文字を超えています。--paths や --git-log-limit を絞って分割してください。"
            ),
            exit_code=2,
        )

    payload: dict[str, Any] = {
        "model": model,
        "input": input_blocks,
        "questions": build_docs_questions(),
    }
    errors = run_decisions.validate_payload(payload)
    if errors:
        raise DriftScreenError(
            "payload_validation_failed",
            f"文書 {entry.rel_path} のペイロード検証に失敗しました: " + "; ".join(errors),
            exit_code=2,
        )
    return payload


def build_doc_chunks(
    entries: list[DocEntry],
    snapshot_text: str,
    *,
    model: str = DEFAULT_MODEL,
    max_chars: int = DEFAULT_DOCS_MAX_CHARS,
    chunk_max_docs: int = DEFAULT_CHUNK_MAX_DOCS,
) -> list[dict[str, Any]]:
    """docs モードの文書群をスナップショット 1 回共有チャンク群へパッキングする。"""
    if isinstance(chunk_max_docs, bool) or chunk_max_docs < 1 or chunk_max_docs > MAX_CHUNK_MAX_DOCS:
        raise DriftScreenError(
            "invalid_chunk_max_docs",
            f"--chunk-max-docs は 1 から {MAX_CHUNK_MAX_DOCS} の整数を指定してください。",
            exit_code=2,
        )
    if not entries:
        return []

    base_questions = build_docs_questions()
    q_per_doc = len(base_questions)
    snapshot_prefix = snapshot_text + "\n\n"
    snapshot_chars = len(snapshot_prefix)

    packed_groups: list[list[tuple[str, DocEntry, str]]] = []
    cur_group: list[tuple[str, DocEntry, str]] = []
    cur_chars = snapshot_chars

    for idx, entry in enumerate(entries, start=1):
        doc_ns = f"doc_{idx:04d}"
        doc_block = _format_doc_block(entry, doc_ns=doc_ns)
        single_total = snapshot_chars + len(doc_block)
        if single_total > max_chars:
            raise DriftScreenError(
                "input_size_limit_exceeded",
                (
                    f"文書 {entry.rel_path} の入力文字数（{single_total:,} 文字）が上限 "
                    f"{max_chars:,} 文字を超えています。--paths や --git-log-limit を絞って分割してください。"
                ),
                exit_code=2,
            )

        next_count = len(cur_group) + 1
        if cur_group and (
            next_count > chunk_max_docs
            or next_count * q_per_doc > MAX_QUESTIONS
            or cur_chars + len(doc_block) > max_chars
        ):
            packed_groups.append(cur_group)
            cur_group = []
            cur_chars = snapshot_chars

        cur_group.append((doc_ns, entry, doc_block))
        cur_chars += len(doc_block)

    if cur_group:
        packed_groups.append(cur_group)

    chunks: list[dict[str, Any]] = []
    for chunk_index, group in enumerate(packed_groups):
        input_blocks = [{"type": "text", "text": snapshot_prefix}]
        questions: dict[str, dict[str, Any]] = {}
        chunk_entries: list[DocEntry] = []
        namespaces: list[str] = []
        chunk_flag_hints: list[str] = []

        for doc_ns, entry, doc_block in group:
            input_blocks.append({"type": "text", "text": doc_block})
            chunk_entries.append(entry)
            namespaces.append(doc_ns)
            chunk_flag_hints.extend(entry.missing_flag_hints)
            for base_key, base_q in base_questions.items():
                q_copy = dict(base_q)
                q_copy["instructions"] = (
                    f"Target document [{doc_ns}]: {entry.rel_path}\n{base_q['instructions']}"
                )
                questions[f"{doc_ns}__{base_key}"] = q_copy

        payload: dict[str, Any] = {
            "model": model,
            "input": input_blocks,
            "questions": questions,
        }
        errors = run_decisions.validate_payload(payload)
        if errors:
            raise DriftScreenError(
                "payload_validation_failed",
                f"docs チャンク {chunk_index} のペイロード検証に失敗しました: " + "; ".join(errors),
                exit_code=2,
            )

        chunks.append(
            {
                "chunk_index": chunk_index,
                "namespaces": namespaces,
                "entries": chunk_entries,
                "files": [e.rel_path for e in chunk_entries],
                "missing_flag_hints": chunk_flag_hints,
                "payload": payload,
            }
        )
    return chunks


def classify_doc_answers(
    entry: DocEntry,
    enriched: dict[str, Any],
    *,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
) -> dict[str, Any]:
    """Decisions API 応答と決定論的ヒントから docs モードの安全側分類を返す。"""
    answers = enriched.get("answers")
    if not isinstance(answers, dict):
        answers = {}

    stale = _extract_number(answers.get("stale_status_or_facts"), "noul")
    broken = _extract_number(answers.get("broken_or_obsolete_refs"), "noul")
    mech = _extract_number(answers.get("mechanizable_workflow"), "noul")
    discuss = _extract_number(answers.get("needs_discussion"), "noul")

    sev_ans = answers.get("drift_severity") if isinstance(answers.get("drift_severity"), dict) else {}
    sev_score = _extract_number(sev_ans, "score")
    sev_norm = _extract_number(sev_ans, "normalized_score")
    if sev_norm is None and sev_score is not None and len(DRIFT_SEVERITY_CRITERIA) >= 2:
        sev_norm = round(sev_score / (len(DRIFT_SEVERITY_CRITERIA) - 1), 4)

    act_ans = answers.get("recommended_action") if isinstance(answers.get("recommended_action"), dict) else {}
    rec_action = act_ans.get("choice") if isinstance(act_ans.get("choice"), str) else None
    act_conf = _extract_number(act_ans, "confidence")

    no_missing_hints = len(entry.missing_path_hints) == 0 and len(entry.missing_flag_hints) == 0
    low_noul_drift = (
        stale is not None
        and stale < DEFAULT_NOUL_CLEAN_CEILING
        and broken is not None
        and broken < DEFAULT_NOUL_CLEAN_CEILING
    )
    low_mech = mech is None or mech < DEFAULT_MECHANIZABLE_THRESHOLD

    reasons: list[str] = []
    if (
        rec_action == "likely_clean"
        and act_conf is not None
        and act_conf >= min_confidence
        and low_noul_drift
        and no_missing_hints
        and low_mech
    ):
        bucket = "low_priority_clean"
        reasons.append(f"recommended_action=likely_clean(confidence>={min_confidence:.2f})")
        reasons.append(f"stale_and_broken<{DEFAULT_NOUL_CLEAN_CEILING:.2f}")
    elif (
        no_missing_hints
        and low_noul_drift
        and rec_action in ("mechanization_review", "likely_clean")
        and (
            rec_action == "mechanization_review"
            or (mech is not None and mech >= DEFAULT_MECHANIZABLE_THRESHOLD)
        )
    ):
        bucket = "mechanization_candidate"
        if rec_action == "mechanization_review":
            reasons.append("recommended_action=mechanization_review")
        if mech is not None and mech >= DEFAULT_MECHANIZABLE_THRESHOLD:
            reasons.append(f"mechanizable_workflow>={DEFAULT_MECHANIZABLE_THRESHOLD:.2f}")
    else:
        bucket = "prioritize_for_audit"
        if entry.missing_path_hints:
            reasons.append(f"missing_path_hints({len(entry.missing_path_hints)})")
        if entry.missing_flag_hints:
            reasons.append(f"missing_flag_hints({len(entry.missing_flag_hints)})")
        if stale is None:
            reasons.append("missing_stale_score")
        elif stale >= DEFAULT_NOUL_CLEAN_CEILING:
            reasons.append(f"stale_status_or_facts>={DEFAULT_NOUL_CLEAN_CEILING:.2f}")
        if broken is None:
            reasons.append("missing_broken_score")
        elif broken >= DEFAULT_NOUL_CLEAN_CEILING:
            reasons.append(f"broken_or_obsolete_refs>={DEFAULT_NOUL_CLEAN_CEILING:.2f}")
        if rec_action is None or rec_action not in DOCS_RECOMMENDED_ACTIONS:
            reasons.append("missing_recommended_action")
        elif rec_action not in ("likely_clean", "mechanization_review"):
            reasons.append(f"recommended_action={rec_action}")
        if act_conf is None:
            reasons.append("missing_action_confidence")
        elif act_conf < min_confidence:
            reasons.append(f"low_confidence<{min_confidence:.2f}")
        if mech is not None and mech >= DEFAULT_MECHANIZABLE_THRESHOLD and not reasons:
            reasons.append(f"mechanizable_workflow>={DEFAULT_MECHANIZABLE_THRESHOLD:.2f}")

    result: dict[str, Any] = {
        "file": entry.rel_path,
        "bucket": bucket,
        "recommended_action": rec_action,
        "action_confidence": round(act_conf, 4) if act_conf is not None else None,
        "stale_status_or_facts": round(stale, 4) if stale is not None else None,
        "broken_or_obsolete_refs": round(broken, 4) if broken is not None else None,
        "mechanizable_workflow": round(mech, 4) if mech is not None else None,
        "needs_discussion": round(discuss, 4) if discuss is not None else None,
        "drift_severity": round(sev_score, 4) if sev_score is not None else None,
        "drift_severity_normalized": sev_norm,
        "staleness_days": entry.staleness_days,
        "missing_path_hints": entry.missing_path_hints,
        "missing_flag_hints": entry.missing_flag_hints,
        "reasons": reasons,
    }
    if "usage" in enriched and isinstance(enriched["usage"], dict):
        result["usage"] = enriched["usage"]
    return result


def _sanitize_question_key(raw_id: str, used: set[str], fallback_idx: int) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", raw_id).strip("_-")
    if not cleaned:
        cleaned = f"item_{fallback_idx:04d}"
    base = cleaned[:56]
    candidate = base
    suffix = 1
    while candidate in used or not QUESTION_KEY_SAFE_RE.match(candidate):
        suffix_str = f"_{suffix}"
        candidate = f"{base[:64 - len(suffix_str)]}{suffix_str}"
        suffix += 1
    used.add(candidate)
    return candidate


def _split_md_table_row(line: str) -> list[str]:
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|") and not stripped.endswith("\\|"):
        stripped = stripped[:-1]
    parts = re.split(r"(?<!\\)\|", stripped)
    return [p.strip().replace("\\|", "|") for p in parts]


def _normalize_header_label(cell: str) -> str:
    return cell.strip().strip("`*_").strip().lower()


def _is_incomplete_table_status(status_cell: str) -> bool:
    norm = status_cell.strip().strip("`*_").strip().lower()
    if not norm:
        return False
    if norm in COMPLETED_TABLE_MARKERS:
        return False
    if norm in INCOMPLETE_TABLE_MARKERS:
        return True
    if NEGATED_DONE_RE.search(norm):
        return True
    if any(tok in norm for tok in ("未着手", "未完了", "未対応", "進行中", "対応中", "作業中", "保留", "要確認")):
        return True
    if any(tok in norm for tok in ("完了", "対応済", "終了", "クローズ", "見送り", "不要", "✅", "✔")):
        return False
    if COMPLETED_ASCII_WORD_RE.search(norm):
        return False
    if "⏳" in norm or "🚧" in norm or "[ ]" in norm:
        return True
    return bool(INCOMPLETE_ASCII_WORD_RE.search(norm))


def _update_heading_stack(heading_stack: dict[int, str], line: str) -> bool:
    match = HEADING_RE.match(line)
    if not match:
        return False
    level = len(match.group(1))
    title = re.sub(r"\s+#+\s*$", "", match.group(2)).strip()
    if not title:
        return False
    for existing_level in [k for k in heading_stack if k >= level]:
        del heading_stack[existing_level]
    heading_stack[level] = title
    return True


def _format_heading_breadcrumb(heading_stack: dict[int, str]) -> str | None:
    if not heading_stack:
        return None
    return " > ".join(heading_stack[lvl] for lvl in sorted(heading_stack))


def _parse_markdown_backlog(
    raw_text: str,
    rel_label: str,
    *,
    fmt: str,
    include_tables: bool,
) -> list[BacklogItem]:
    lines = raw_text.splitlines()
    n = len(lines)
    in_fence = False
    fence_char = ""
    fence_len = 0
    heading_stack: dict[int, str] = {}

    checkbox_raw: list[tuple[int, str | None, str]] = []
    table_raw: list[tuple[int, str | None, str]] = []

    i = 0
    while i < n:
        line = lines[i]
        fence_match = FENCE_RE.match(line)
        if fence_match:
            marker = fence_match.group(1)
            if not in_fence:
                in_fence = True
                fence_char = marker[0]
                fence_len = len(marker)
                i += 1
                continue
            if marker[0] == fence_char and len(marker) >= fence_len:
                in_fence = False
                fence_char = ""
                fence_len = 0
                i += 1
                continue
        if in_fence:
            i += 1
            continue

        if _update_heading_stack(heading_stack, line):
            i += 1
            continue

        current_section = _format_heading_breadcrumb(heading_stack)

        task_match = UNCHECKED_TASK_RE.match(line)
        if task_match:
            checkbox_raw.append((i + 1, current_section, task_match.group(1).strip()))
            i += 1
            continue

        if (
            "|" in line
            and i + 1 < n
            and not FENCE_RE.match(lines[i + 1])
            and TABLE_SEP_RE.match(lines[i + 1])
        ):
            header_cells = _split_md_table_row(line)
            status_col: int | None = None
            for col_idx, cell in enumerate(header_cells):
                if _normalize_header_label(cell) in STATUS_HEADER_NAMES:
                    status_col = col_idx
                    break
            i += 2
            if status_col is None:
                continue
            while i < n:
                row_line = lines[i]
                if (
                    not row_line.strip()
                    or FENCE_RE.match(row_line)
                    or HEADING_RE.match(row_line)
                    or UNCHECKED_TASK_RE.match(row_line)
                    or LIST_ITEM_START_RE.match(row_line)
                ):
                    break
                if "|" not in row_line or TABLE_SEP_RE.match(row_line):
                    break
                cells = _split_md_table_row(row_line)
                status_val = cells[status_col] if status_col < len(cells) else ""
                if _is_incomplete_table_status(status_val):
                    non_status = [
                        c for c_idx, c in enumerate(cells) if c_idx != status_col and c
                    ]
                    if non_status:
                        row_text = f"{' | '.join(non_status)} [status: {status_val}]"
                        table_raw.append((i + 1, current_section, row_text))
                i += 1
            continue

        i += 1

    if fmt == "table":
        chosen = table_raw
    elif fmt == "markdown":
        chosen = sorted(checkbox_raw + table_raw, key=lambda r: r[0]) if include_tables else checkbox_raw
    else:
        # auto
        if include_tables:
            chosen = sorted(checkbox_raw + table_raw, key=lambda r: r[0])
        elif checkbox_raw:
            chosen = checkbox_raw
        else:
            chosen = table_raw

    items: list[BacklogItem] = []
    used_keys: set[str] = set()
    for seq, (line_no, section, text) in enumerate(chosen, start=1):
        item_id = f"item_{seq:04d}"
        q_key = _sanitize_question_key(item_id, used_keys, seq)
        items.append(
            BacklogItem(
                id=item_id,
                question_key=q_key,
                file=rel_label,
                line=line_no,
                text=text,
                section=section,
            )
        )
    return items


def load_backlog_items(
    backlog_path: Path,
    fmt: str,
    *,
    include_tables: bool = False,
) -> list[BacklogItem]:
    """残課題帳簿（Markdown チェックボックス/表 または JSON）を読み込み、未完了項目を抽出する。"""
    assert_safe_file_path(backlog_path, "--backlog")
    if not backlog_path.is_file():
        raise DriftScreenError(
            "backlog_not_found",
            f"--backlog ファイルが見つかりません: {backlog_path}",
            exit_code=2,
        )
    try:
        raw_text = backlog_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DriftScreenError(
            "backlog_read_error",
            f"--backlog ファイルを読み込めません: {exc}",
            exit_code=2,
        ) from exc

    assert_text_has_no_secrets(raw_text, f"--backlog ({backlog_path.name})")

    resolved_fmt = fmt
    if resolved_fmt == "auto":
        resolved_fmt = "json" if backlog_path.suffix.lower() == ".json" else "auto"

    if resolved_fmt == "json":
        try:
            data = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise DriftScreenError("invalid_json", f"--backlog JSON の構文が不正です: {exc}", exit_code=2) from exc
        if not isinstance(data, list):
            raise DriftScreenError(
                "invalid_input_schema",
                "--backlog JSON のトップレベルは配列である必要があります。",
                exit_code=2,
            )
        items: list[BacklogItem] = []
        used_keys: set[str] = set()
        for idx, row in enumerate(data):
            if not isinstance(row, dict):
                raise DriftScreenError(
                    "invalid_input_schema",
                    f"backlog[{idx}] は JSON オブジェクトである必要があります。",
                    exit_code=2,
                )
            raw_id = row.get("id")
            if isinstance(raw_id, bool) or raw_id is None or not str(raw_id).strip():
                raise DriftScreenError(
                    "invalid_input_schema",
                    f"backlog[{idx}].id は空でない文字列または整数が必要です。",
                    exit_code=2,
                )
            item_id = str(raw_id).strip()
            text_val = row.get("text")
            if not isinstance(text_val, str) or not text_val.strip():
                raise DriftScreenError(
                    "invalid_input_schema",
                    f"backlog[{idx}].text は空でない文字列が必要です。",
                    exit_code=2,
                )
            file_val = row.get("file")
            if file_val is not None and not isinstance(file_val, str):
                raise DriftScreenError(
                    "invalid_input_schema",
                    f"backlog[{idx}].file は文字列または null が必要です。",
                    exit_code=2,
                )
            line_val = row.get("line")
            if line_val is not None and (isinstance(line_val, bool) or not isinstance(line_val, int) or line_val < 0):
                raise DriftScreenError(
                    "invalid_input_schema",
                    f"backlog[{idx}].line は 0 以上の整数または null が必要です。",
                    exit_code=2,
                )
            section_val = row.get("section")
            if section_val is not None and not isinstance(section_val, str):
                raise DriftScreenError(
                    "invalid_input_schema",
                    f"backlog[{idx}].section は文字列または null が必要です。",
                    exit_code=2,
                )
            q_key = _sanitize_question_key(item_id, used_keys, idx + 1)
            items.append(
                BacklogItem(
                    id=item_id,
                    question_key=q_key,
                    file=file_val.strip() if isinstance(file_val, str) and file_val.strip() else None,
                    line=line_val,
                    text=text_val.strip(),
                    section=section_val.strip() if isinstance(section_val, str) and section_val.strip() else None,
                )
            )
        return items

    return _parse_markdown_backlog(
        raw_text,
        backlog_path.as_posix(),
        fmt=resolved_fmt,
        include_tables=include_tables,
    )


def build_backlog_payload(
    items: list[BacklogItem],
    snapshot_text: str,
    *,
    model: str = DEFAULT_MODEL,
    max_chars: int = DEFAULT_BACKLOG_MAX_CHARS,
) -> dict[str, Any]:
    """残課題項目群を 1 リクエストの Decisions API ペイロードにまとめる。"""
    if len(items) > MAX_QUESTIONS:
        raise DriftScreenError(
            "question_limit_exceeded",
            (
                f"残課題の抽出件数（{len(items):,} 件）が Decisions API の 1 リクエスト上限 "
                f"{MAX_QUESTIONS:,} 問を超えています。帳簿または JSON を分割して実行してください。"
            ),
            exit_code=2,
        )
    if len(snapshot_text) > max_chars:
        raise DriftScreenError(
            "input_size_limit_exceeded",
            (
                f"共有スナップショットの文字数（{len(snapshot_text):,} 文字）が上限 "
                f"{max_chars:,} 文字を超えています。--git-log-limit を下げるか --max-chars を調整してください。"
            ),
            exit_code=2,
        )

    questions: dict[str, dict[str, Any]] = {}
    for item in items:
        loc = f"{item.file}:{item.line}" if item.file and item.line is not None else (item.file or "-")
        section_line = f"\nSection: {item.section}" if item.section else ""
        questions[item.question_key] = {
            "type": "choice",
            "instructions": (
                f"Based on the repository snapshot and recent commits, what is the current status "
                f"of backlog item [{item.id}] (location: {loc})?{section_line}\nItem text: {item.text}"
            ),
            "criteria": dict(BACKLOG_STATUS_CRITERIA),
        }

    payload: dict[str, Any] = {
        "model": model,
        "input": [{"type": "text", "text": snapshot_text}],
        "questions": questions,
    }
    errors = run_decisions.validate_payload(payload)
    if errors:
        raise DriftScreenError(
            "payload_validation_failed",
            "backlog ペイロードの事前検証に失敗しました: " + "; ".join(errors),
            exit_code=2,
        )
    return payload


def evaluate_backlog_response(
    items: list[BacklogItem],
    enriched: dict[str, Any],
    *,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
) -> list[dict[str, Any]]:
    """1 リクエストの応答を項目単位へ展開し、要確認フラグを判定する。"""
    answers = enriched.get("answers")
    if not isinstance(answers, dict):
        answers = {}

    rows: list[dict[str, Any]] = []
    for item in items:
        ans = answers.get(item.question_key)
        ans_dict = ans if isinstance(ans, dict) else {}
        choice = ans_dict.get("choice") if isinstance(ans_dict.get("choice"), str) else None
        conf = _extract_number(ans_dict, "confidence")

        reasons: list[str] = []
        if choice is None or choice not in VALID_BACKLOG_CHOICES:
            reasons.append("missing_status_choice")
        elif choice != "still_open":
            reasons.append(f"status={choice}")

        if conf is None:
            reasons.append("missing_confidence")
        elif conf < min_confidence:
            reasons.append(f"low_confidence<{min_confidence:.2f}")

        needs_verification = bool(
            choice is None
            or choice not in VALID_BACKLOG_CHOICES
            or choice != "still_open"
            or conf is None
            or conf < min_confidence
        )
        rows.append(
            {
                "id": item.id,
                "question_key": item.question_key,
                "file": item.file,
                "line": item.line,
                "section": item.section,
                "text": item.text,
                "status_choice": choice,
                "confidence": round(conf, 4) if conf is not None else None,
                "needs_verification": needs_verification,
                "reasons": reasons,
            }
        )
    return rows


def parse_candidates(raw_data: Any) -> list[AuditCandidate]:
    """candidates モードの JSON 配列を検証・正規化する。"""
    if not isinstance(raw_data, list):
        raise DriftScreenError(
            "invalid_input_schema",
            "candidates 入力 JSON のトップレベルはオブジェクトの配列である必要があります。",
            exit_code=2,
        )

    for idx, item in enumerate(raw_data):
        if not isinstance(item, dict):
            raise DriftScreenError(
                "invalid_input_schema",
                f"candidates[{idx}] は JSON オブジェクトである必要があります。",
                exit_code=2,
            )
        for field_name, text in _iter_string_fields(item, f"candidates[{idx}]"):
            assert_text_has_no_secrets(text, field_name)

    parsed: list[AuditCandidate] = []
    for idx, item in enumerate(raw_data):
        req_vals: dict[str, str] = {}
        for req_key in ("id", "category", "title", "evidence", "symptom"):
            val = item.get(req_key)
            if not isinstance(val, str) or not val.strip():
                raise DriftScreenError(
                    "invalid_input_schema",
                    f"candidates[{idx}].{req_key} は空でない文字列が必要です。",
                    exit_code=2,
                )
            req_vals[req_key] = val.strip()

        raw_files = item.get("files")
        files_list: list[str] = []
        if raw_files is None:
            files_list = []
        elif isinstance(raw_files, str):
            if raw_files.strip():
                assert_safe_file_path(raw_files.strip(), f"candidates[{idx}].files")
                files_list = [raw_files.strip()]
        elif isinstance(raw_files, list):
            for f_idx, f_elem in enumerate(raw_files):
                if not isinstance(f_elem, str) or not f_elem.strip():
                    raise DriftScreenError(
                        "invalid_input_schema",
                        f"candidates[{idx}].files[{f_idx}] は空でない文字列が必要です。",
                        exit_code=2,
                    )
                f_clean = f_elem.strip()
                assert_safe_file_path(f_clean, f"candidates[{idx}].files[{f_idx}]")
                files_list.append(f_clean)
        else:
            raise DriftScreenError(
                "invalid_input_schema",
                f"candidates[{idx}].files は文字列または文字列配列が必要です。",
                exit_code=2,
            )

        scope_val = item.get("estimated_scope")
        if scope_val is not None and not isinstance(scope_val, str):
            raise DriftScreenError(
                "invalid_input_schema",
                f"candidates[{idx}].estimated_scope は文字列または null が必要です。",
                exit_code=2,
            )

        parsed.append(
            AuditCandidate(
                id=req_vals["id"],
                category=req_vals["category"],
                title=req_vals["title"],
                evidence=req_vals["evidence"],
                symptom=req_vals["symptom"],
                files=files_list,
                estimated_scope=scope_val.strip() if isinstance(scope_val, str) and scope_val.strip() else None,
            )
        )
    return parsed


def build_candidates_questions() -> dict[str, dict[str, Any]]:
    """candidates モード用の 5 問マップを構築する。"""
    return {
        "fits_single_track": {
            "type": "noul",
            "instructions": (
                "Can this candidate be planned and resolved within a single PR or single track "
                "without requiring a full cross-cutting redesign?"
            ),
            "criteria": {
                "true_description": (
                    "The scope can be isolated to a single PR or exclusive file-ownership track."
                ),
                "false_description": (
                    "Resolving the item requires broad cross-cutting redesign spanning many layers."
                ),
            },
        },
        "needs_discussion": {
            "type": "noul",
            "instructions": (
                "Does this candidate require specification policy alignment or explicit "
                "user decision before writing implementation code?"
            ),
            "criteria": {
                "true_description": (
                    "Addressing the candidate involves trade-offs, policy choices, or "
                    "specification ambiguities requiring user approval."
                ),
                "false_description": (
                    "The fix follows existing rules and specifications without policy ambiguity."
                ),
            },
        },
        "deterministic_mechanizable": {
            "type": "noul",
            "instructions": (
                "Can the core work described in this candidate be automated as a deterministic "
                "script rather than judgment-heavy editing?"
            ),
            "criteria": {
                "true_description": (
                    "The target workflow produces deterministic outputs from inputs and rules "
                    "and can be scripted."
                ),
                "false_description": (
                    "The task requires human or model judgment, prose authoring, or custom refactoring."
                ),
            },
        },
        "impact_severity": {
            "type": "score",
            "instructions": "How severe is the operational or maintenance impact of this candidate?",
            "criteria": list(CANDIDATES_IMPACT_CRITERIA),
        },
        "dispatch_route": {
            "type": "choice",
            "instructions": (
                "Which execution route is most appropriate for this first-pass audit candidate?"
            ),
            "criteria": dict(CANDIDATES_DISPATCH_ROUTES),
        },
    }


def _format_candidate_block(candidate: AuditCandidate, *, cand_ns: str | None = None) -> str:
    lines: list[str] = []
    if cand_ns:
        lines.append(f"Target Candidate [{cand_ns}]:")
    lines.extend(
        [
            f"Candidate ID: {candidate.id}",
            f"Category: {candidate.category}",
            f"Title: {candidate.title}",
            f"Files: {', '.join(candidate.files) if candidate.files else '(none)'}",
        ]
    )
    if candidate.estimated_scope:
        lines.append(f"Estimated Scope: {candidate.estimated_scope}")
    lines.append(f"\nEvidence:\n{candidate.evidence}")
    lines.append(f"\nObserved Symptom:\n{candidate.symptom}\n")
    return "\n".join(lines)


def build_candidate_payload(
    candidate: AuditCandidate,
    *,
    model: str = DEFAULT_MODEL,
    max_chars: int = DEFAULT_CANDIDATES_MAX_CHARS,
    snapshot_text: str | None = None,
) -> dict[str, Any]:
    """candidates モード 1 候補分の Decisions API ペイロードを構築・検証する。"""
    input_text = _format_candidate_block(candidate)
    input_blocks: list[dict[str, str]] = []
    if snapshot_text is not None:
        input_blocks.append({"type": "text", "text": snapshot_text + "\n\n"})
    input_blocks.append({"type": "text", "text": input_text})

    total_chars = sum(len(b["text"]) for b in input_blocks)
    if total_chars > max_chars:
        raise DriftScreenError(
            "input_size_limit_exceeded",
            (
                f"候補 {candidate.id} の入力文字数（{total_chars:,} 文字）が上限 "
                f"{max_chars:,} 文字を超えています。evidence や symptom を要約して再実行してください。"
            ),
            exit_code=2,
        )

    payload: dict[str, Any] = {
        "model": model,
        "input": input_blocks,
        "questions": build_candidates_questions(),
    }
    errors = run_decisions.validate_payload(payload)
    if errors:
        raise DriftScreenError(
            "payload_validation_failed",
            f"候補 {candidate.id} のペイロード検証に失敗しました: " + "; ".join(errors),
            exit_code=2,
        )
    return payload


def build_candidate_chunks(
    candidates: list[AuditCandidate],
    *,
    snapshot_text: str | None = None,
    model: str = DEFAULT_MODEL,
    max_chars: int = DEFAULT_CANDIDATES_MAX_CHARS,
    chunk_max_items: int = DEFAULT_CHUNK_MAX_ITEMS,
) -> list[dict[str, Any]]:
    """candidates モードの候補群を共有スナップショット付きチャンク群へパッキングする。"""
    if (
        isinstance(chunk_max_items, bool)
        or chunk_max_items < 1
        or chunk_max_items > MAX_CHUNK_MAX_ITEMS
    ):
        raise DriftScreenError(
            "invalid_chunk_max_items",
            f"--chunk-max-items は 1 から {MAX_CHUNK_MAX_ITEMS} の整数を指定してください。",
            exit_code=2,
        )
    if not candidates:
        return []

    base_questions = build_candidates_questions()
    q_per_item = len(base_questions)
    snapshot_prefix = (snapshot_text + "\n\n") if snapshot_text is not None else None
    snapshot_chars = len(snapshot_prefix) if snapshot_prefix is not None else 0

    packed_groups: list[list[tuple[str, AuditCandidate, str]]] = []
    cur_group: list[tuple[str, AuditCandidate, str]] = []
    cur_chars = snapshot_chars

    for idx, cand in enumerate(candidates, start=1):
        cand_ns = f"cand_{idx:04d}"
        cand_block = _format_candidate_block(cand, cand_ns=cand_ns)
        single_total = snapshot_chars + len(cand_block)
        if single_total > max_chars:
            raise DriftScreenError(
                "input_size_limit_exceeded",
                (
                    f"候補 {cand.id} の入力文字数（{single_total:,} 文字）が上限 "
                    f"{max_chars:,} 文字を超えています。evidence や symptom を要約して再実行してください。"
                ),
                exit_code=2,
            )

        next_count = len(cur_group) + 1
        if cur_group and (
            next_count > chunk_max_items
            or next_count * q_per_item > MAX_QUESTIONS
            or cur_chars + len(cand_block) > max_chars
        ):
            packed_groups.append(cur_group)
            cur_group = []
            cur_chars = snapshot_chars

        cur_group.append((cand_ns, cand, cand_block))
        cur_chars += len(cand_block)

    if cur_group:
        packed_groups.append(cur_group)

    chunks: list[dict[str, Any]] = []
    for chunk_index, group in enumerate(packed_groups):
        input_blocks: list[dict[str, str]] = []
        if snapshot_prefix is not None:
            input_blocks.append({"type": "text", "text": snapshot_prefix})
        questions: dict[str, dict[str, Any]] = {}
        chunk_cands: list[AuditCandidate] = []
        namespaces: list[str] = []

        for cand_ns, cand, cand_block in group:
            input_blocks.append({"type": "text", "text": cand_block})
            chunk_cands.append(cand)
            namespaces.append(cand_ns)
            for base_key, base_q in base_questions.items():
                q_copy = dict(base_q)
                q_copy["instructions"] = (
                    f"Target candidate [{cand_ns}]: {cand.id} ({cand.title})\n{base_q['instructions']}"
                )
                questions[f"{cand_ns}__{base_key}"] = q_copy

        payload: dict[str, Any] = {
            "model": model,
            "input": input_blocks,
            "questions": questions,
        }
        errors = run_decisions.validate_payload(payload)
        if errors:
            raise DriftScreenError(
                "payload_validation_failed",
                f"candidates チャンク {chunk_index} のペイロード検証に失敗しました: " + "; ".join(errors),
                exit_code=2,
            )

        chunks.append(
            {
                "chunk_index": chunk_index,
                "namespaces": namespaces,
                "candidates": chunk_cands,
                "ids": [c.id for c in chunk_cands],
                "payload": payload,
            }
        )
    return chunks


def classify_candidate_answers(
    candidate: AuditCandidate,
    enriched: dict[str, Any],
    *,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    discussion_threshold: float = DEFAULT_DISCUSSION_THRESHOLD,
) -> dict[str, Any]:
    """candidates モード応答を解釈し、親確認フラグを判定する。"""
    answers = enriched.get("answers")
    if not isinstance(answers, dict):
        answers = {}

    fits = _extract_number(answers.get("fits_single_track"), "noul")
    discuss = _extract_number(answers.get("needs_discussion"), "noul")
    mech = _extract_number(answers.get("deterministic_mechanizable"), "noul")

    sev_ans = answers.get("impact_severity") if isinstance(answers.get("impact_severity"), dict) else {}
    sev_score = _extract_number(sev_ans, "score")
    sev_norm = _extract_number(sev_ans, "normalized_score")
    if sev_norm is None and sev_score is not None and len(CANDIDATES_IMPACT_CRITERIA) >= 2:
        sev_norm = round(sev_score / (len(CANDIDATES_IMPACT_CRITERIA) - 1), 4)

    route_ans = answers.get("dispatch_route") if isinstance(answers.get("dispatch_route"), dict) else {}
    route = route_ans.get("choice") if isinstance(route_ans.get("choice"), str) else None
    route_conf = _extract_number(route_ans, "confidence")

    reasons: list[str] = []
    if route is None or route not in VALID_DISPATCH_ROUTES:
        reasons.append("missing_dispatch_route")
    elif route == "other":
        reasons.append("dispatch_route=other")

    if route_conf is None:
        reasons.append("missing_confidence")
    elif route_conf < min_confidence:
        reasons.append(f"low_confidence<{min_confidence:.2f}")

    if discuss is None:
        reasons.append("missing_needs_discussion")
    elif discuss >= discussion_threshold:
        reasons.append(f"needs_discussion>={discussion_threshold:.2f}")

    needs_parent_review = bool(reasons)
    result: dict[str, Any] = {
        "id": candidate.id,
        "category": candidate.category,
        "title": candidate.title,
        "files": candidate.files,
        "dispatch_route": route,
        "route_confidence": round(route_conf, 4) if route_conf is not None else None,
        "fits_single_track": round(fits, 4) if fits is not None else None,
        "needs_discussion": round(discuss, 4) if discuss is not None else None,
        "deterministic_mechanizable": round(mech, 4) if mech is not None else None,
        "impact_severity": round(sev_score, 4) if sev_score is not None else None,
        "impact_severity_normalized": sev_norm,
        "needs_parent_review": needs_parent_review,
        "reasons": reasons,
    }
    if "usage" in enriched and isinstance(enriched["usage"], dict):
        result["usage"] = enriched["usage"]
    return result


def _emit_report(report: dict[str, Any], output_format: str) -> bool:
    return emit_report(report, output_format)


def _emit_error(
    code: str,
    message: str,
    exit_code: int,
    output_format: str,
    api_key: str,
) -> None:
    emit_error(code, message, exit_code, output_format, api_key)


def _require_api_key(api_key: str) -> None:
    if not api_key:
        raise DriftScreenError(
            "missing_api_key",
            "環境変数 GEMINI_API_KEY が設定されていません。"
            "API キーを設定するか --dry-run を使用してください。",
            exit_code=2,
        )


def _validate_common_args(args: argparse.Namespace) -> None:
    raw_timeout = getattr(args, "timeout", None)
    if raw_timeout is not None and (isinstance(raw_timeout, bool) or raw_timeout <= 0):
        raise DriftScreenError("invalid_timeout", "--timeout は 0 より大きい数を指定してください。", exit_code=2)
    if getattr(args, "max_chars", 1) < 1:
        raise DriftScreenError("invalid_max_chars", "--max-chars は 1 以上の整数を指定してください。", exit_code=2)
    min_conf = getattr(args, "min_confidence", 0.0)
    if not (0.0 <= min_conf <= 1.0):
        raise DriftScreenError(
            "invalid_min_confidence",
            "--min-confidence は 0.0 から 1.0 の範囲で指定してください。",
            exit_code=2,
        )
    if hasattr(args, "max_workers") and args.max_workers < 1:
        raise DriftScreenError("invalid_max_workers", "--max-workers は 1 以上の整数を指定してください。", exit_code=2)
    if hasattr(args, "git_log_limit") and args.git_log_limit < 0:
        raise DriftScreenError("invalid_git_log_limit", "--git-log-limit は 0 以上の整数を指定してください。", exit_code=2)
    if hasattr(args, "discussion_threshold") and not (0.0 <= args.discussion_threshold <= 1.0):
        raise DriftScreenError(
            "invalid_discussion_threshold",
            "--discussion-threshold は 0.0 から 1.0 の範囲で指定してください。",
            exit_code=2,
        )
    backend = getattr(args, "backend", "auto")
    if backend not in run_decisions.VALID_BACKENDS:
        raise DriftScreenError(
            "invalid_backend",
            f"--backend は {sorted(run_decisions.VALID_BACKENDS)} のいずれかを指定してください。",
            exit_code=2,
        )
    if raw_timeout is not None and backend == "sdk":
        raise DriftScreenError(
            "invalid_argument",
            "--backend sdk では明示的な --timeout 指定に対応していません（--backend auto または rest を指定してください）。",
            exit_code=2,
        )
    if hasattr(args, "chunk_max_docs"):
        val = args.chunk_max_docs
        if isinstance(val, bool) or val < 1 or val > MAX_CHUNK_MAX_DOCS:
            raise DriftScreenError(
                "invalid_chunk_max_docs",
                f"--chunk-max-docs は 1 から {MAX_CHUNK_MAX_DOCS} の整数を指定してください。",
                exit_code=2,
            )
    if hasattr(args, "chunk_max_items"):
        val = args.chunk_max_items
        if isinstance(val, bool) or val < 1 or val > MAX_CHUNK_MAX_ITEMS:
            raise DriftScreenError(
                "invalid_chunk_max_items",
                f"--chunk-max-items は 1 から {MAX_CHUNK_MAX_ITEMS} の整数を指定してください。",
                exit_code=2,
            )


def _resolve_effective_timeout_and_backend(args: argparse.Namespace) -> tuple[float, str]:
    raw_timeout = getattr(args, "timeout", None)
    backend = getattr(args, "backend", "auto")
    if raw_timeout is None:
        return DEFAULT_TIMEOUT, backend
    effective_backend = "rest" if backend == "auto" else backend
    return float(raw_timeout), effective_backend


def _unnamespace_answers(
    enriched_answers: Any,
    ns: str,
    base_keys: tuple[str, ...],
) -> dict[str, Any]:
    if not isinstance(enriched_answers, dict):
        return {}
    prefix = f"{ns}__"
    extracted: dict[str, Any] = {}
    for base_key in base_keys:
        full_key = f"{prefix}{base_key}"
        if full_key in enriched_answers:
            extracted[base_key] = enriched_answers[full_key]
    return extracted


def _run_docs_subcommand(
    args: argparse.Namespace,
    *,
    api_key: str,
    opener: Callable[..., Any] | None,
) -> int:
    ctx = collect_repo_context(Path(args.repo), args.git_log_limit)
    facts_blocks = load_facts_blocks(args.facts_file)
    snapshot_text = build_repo_snapshot_text(ctx, facts_blocks)
    assert_text_has_no_secrets(snapshot_text, "リポジトリスナップショット")

    rel_paths = select_doc_files(ctx, args.paths if args.paths else None)
    entries = load_doc_entries(ctx, rel_paths)
    batch_mode = getattr(args, "batch_mode", "chunk")

    if batch_mode == "single":
        payloads = [
            build_doc_payload(entry, snapshot_text, model=args.model, max_chars=args.max_chars)
            for entry in entries
        ]
        if args.dry_run:
            _emit_report(
                {
                    "status": "dry_run",
                    "subcommand": "docs",
                    "batch_mode": "single",
                    "model": args.model,
                    "is_git": ctx.is_git,
                    "total": len(entries),
                    "items": [
                        {
                            "file": e.rel_path,
                            "staleness_days": e.staleness_days,
                            "missing_path_hints": e.missing_path_hints,
                            "missing_flag_hints": e.missing_flag_hints,
                            "payload": p,
                        }
                        for e, p in zip(entries, payloads)
                    ],
                },
                args.format,
            )
            return 0
    else:
        chunks = build_doc_chunks(
            entries,
            snapshot_text,
            model=args.model,
            max_chars=args.max_chars,
            chunk_max_docs=args.chunk_max_docs,
        )
        if args.dry_run:
            _emit_report(
                {
                    "status": "dry_run",
                    "subcommand": "docs",
                    "batch_mode": "chunk",
                    "model": args.model,
                    "is_git": ctx.is_git,
                    "total": len(entries),
                    "chunk_count": len(chunks),
                    "chunks": [
                        {
                            "chunk_index": ch["chunk_index"],
                            "files": ch["files"],
                            "missing_flag_hints": ch["missing_flag_hints"],
                            "payload": ch["payload"],
                        }
                        for ch in chunks
                    ],
                },
                args.format,
            )
            return 0

    if not entries:
        _emit_report(
            {
                "status": "skipped_empty_input",
                "subcommand": "docs",
                "model": args.model,
                "is_git": ctx.is_git,
                "total": 0,
                "summary": {
                    "prioritize_for_audit": 0,
                    "mechanization_candidate": 0,
                    "low_priority_clean": 0,
                },
                "results": [],
                "note": LOW_PRIORITY_CLEAN_NOTE,
            },
            args.format,
        )
        return 0

    _require_api_key(api_key)
    effective_timeout, effective_backend = _resolve_effective_timeout_and_backend(args)

    if batch_mode == "single":
        def _call_one(entry: DocEntry, payload: dict[str, Any]) -> tuple[dict[str, Any], str]:
            raw, used_backend = run_decisions.call_decisions_backend(
                payload,
                api_key=api_key,
                backend=effective_backend,
                endpoint=args.endpoint,
                timeout=effective_timeout,
                opener=opener,
            )
            enriched = run_decisions.enrich_response(raw, min_confidence=args.min_confidence)
            return classify_doc_answers(entry, enriched, min_confidence=args.min_confidence), used_backend

        worker_count = max(1, min(args.max_workers, len(entries)))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(_call_one, e, p) for e, p in zip(entries, payloads)]
            pair_results = [future.result() for future in futures]

        results = [row for row, _ in pair_results]
        used_backends = sorted({b for _, b in pair_results})
        usage_summary = _aggregate_usage(results)
    else:
        doc_q_keys = tuple(build_docs_questions().keys())

        def _call_chunk(chunk: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
            raw, used_backend = run_decisions.call_decisions_backend(
                chunk["payload"],
                api_key=api_key,
                backend=effective_backend,
                endpoint=args.endpoint,
                timeout=effective_timeout,
                opener=opener,
            )
            enriched = run_decisions.enrich_response(raw, min_confidence=args.min_confidence)
            chunk_rows: list[dict[str, Any]] = []
            for doc_ns, entry in zip(chunk["namespaces"], chunk["entries"]):
                doc_answers = _unnamespace_answers(enriched.get("answers"), doc_ns, doc_q_keys)
                doc_enriched = {"answers": doc_answers}
                chunk_rows.append(
                    classify_doc_answers(entry, doc_enriched, min_confidence=args.min_confidence)
                )
            usage_record = (
                {"usage": enriched["usage"]}
                if isinstance(enriched.get("usage"), dict)
                else {}
            )
            return chunk_rows, usage_record, used_backend

        worker_count = max(1, min(args.max_workers, len(chunks)))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(_call_chunk, ch) for ch in chunks]
            chunk_outputs = [future.result() for future in futures]

        results = [row for chunk_rows, _, _ in chunk_outputs for row in chunk_rows]
        usage_records = [u_rec for _, u_rec, _ in chunk_outputs if u_rec]
        used_backends = sorted({b for _, _, b in chunk_outputs})
        usage_summary = _aggregate_usage(usage_records)

    summary = {
        "prioritize_for_audit": sum(1 for r in results if r["bucket"] == "prioritize_for_audit"),
        "mechanization_candidate": sum(1 for r in results if r["bucket"] == "mechanization_candidate"),
        "low_priority_clean": sum(1 for r in results if r["bucket"] == "low_priority_clean"),
    }
    report: dict[str, Any] = {
        "status": "completed",
        "subcommand": "docs",
        "batch_mode": batch_mode,
        "backend": used_backends[0] if len(used_backends) == 1 else ",".join(used_backends),
        "model": args.model,
        "is_git": ctx.is_git,
        "total": len(results),
        "summary": summary,
        "results": results,
        "note": LOW_PRIORITY_CLEAN_NOTE,
    }
    if usage_summary is not None:
        report["usage"] = usage_summary

    _emit_report(report, args.format)
    return 0


def _run_backlog_subcommand(
    args: argparse.Namespace,
    *,
    api_key: str,
    opener: Callable[..., Any] | None,
) -> int:
    ctx = collect_repo_context(Path(args.repo), args.git_log_limit)
    facts_blocks = load_facts_blocks(args.facts_file)
    snapshot_text = build_repo_snapshot_text(ctx, facts_blocks)
    assert_text_has_no_secrets(snapshot_text, "リポジトリスナップショット")

    items = load_backlog_items(
        Path(args.backlog),
        args.backlog_format,
        include_tables=getattr(args, "include_tables", False),
    )
    if not items and not args.dry_run:
        _emit_report(
            {
                "status": "skipped_empty_input",
                "subcommand": "backlog",
                "model": args.model,
                "is_git": ctx.is_git,
                "total": 0,
                "summary": {"needs_verification": 0, "still_open": 0},
                "results": [],
            },
            args.format,
        )
        return 0

    if not items and args.dry_run:
        _emit_report(
            {
                "status": "dry_run",
                "subcommand": "backlog",
                "model": args.model,
                "is_git": ctx.is_git,
                "total": 0,
                "items": [],
                "payload": None,
            },
            args.format,
        )
        return 0

    payload = build_backlog_payload(
        items,
        snapshot_text,
        model=args.model,
        max_chars=args.max_chars,
    )

    if args.dry_run:
        _emit_report(
            {
                "status": "dry_run",
                "subcommand": "backlog",
                "model": args.model,
                "is_git": ctx.is_git,
                "total": len(items),
                "items": [
                    {
                        "id": it.id,
                        "question_key": it.question_key,
                        "file": it.file,
                        "line": it.line,
                        "section": it.section,
                        "text": it.text,
                    }
                    for it in items
                ],
                "payload": payload,
            },
            args.format,
        )
        return 0

    _require_api_key(api_key)
    effective_timeout, effective_backend = _resolve_effective_timeout_and_backend(args)
    raw, used_backend = run_decisions.call_decisions_backend(
        payload,
        api_key=api_key,
        backend=effective_backend,
        endpoint=args.endpoint,
        timeout=effective_timeout,
        opener=opener,
    )
    enriched = run_decisions.enrich_response(raw, min_confidence=args.min_confidence)
    results = evaluate_backlog_response(items, enriched, min_confidence=args.min_confidence)

    needs_ver = sum(1 for r in results if r["needs_verification"])
    report: dict[str, Any] = {
        "status": "completed",
        "subcommand": "backlog",
        "backend": used_backend,
        "model": args.model,
        "is_git": ctx.is_git,
        "total": len(results),
        "summary": {
            "needs_verification": needs_ver,
            "still_open": len(results) - needs_ver,
        },
        "results": results,
    }
    if isinstance(enriched.get("usage"), dict):
        report["usage"] = enriched["usage"]

    _emit_report(report, args.format)
    return 0


def _load_candidates_json(
    input_path: str | None,
    use_stdin: bool,
    stdin_text: str | None,
) -> Any:
    if bool(input_path) == bool(use_stdin):
        raise DriftScreenError(
            "invalid_input_source",
            "--input <path> または --stdin のどちらか一方だけを指定してください。",
            exit_code=2,
        )
    if input_path:
        path = Path(input_path)
        assert_safe_file_path(path, "--input")
        if os.path.lexists(path) and is_reparse_or_symlink(path):
            raise DriftScreenError(
                "unsafe_input_file",
                f"--input にシンボリックリンクまたはリパースポイントは指定できません: {input_path}",
                exit_code=2,
            )
        try:
            raw_text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise DriftScreenError(
                "input_read_error",
                f"入力ファイルを読み込めません: {exc}",
                exit_code=2,
            ) from exc
    else:
        raw_text = stdin_text if stdin_text is not None else sys.stdin.read()

    try:
        return json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise DriftScreenError("invalid_json", f"入力 JSON の構文が不正です: {exc}", exit_code=2) from exc


def _build_optional_candidates_snapshot(args: argparse.Namespace) -> tuple[str | None, bool | None]:
    repo_arg = getattr(args, "repo", None)
    facts_files = getattr(args, "facts_file", []) or []
    if repo_arg is not None:
        ctx = collect_repo_context(Path(repo_arg), getattr(args, "git_log_limit", DEFAULT_CANDIDATES_GIT_LOG_LIMIT))
        facts_blocks = load_facts_blocks(facts_files)
        snapshot_text = build_repo_snapshot_text(ctx, facts_blocks)
        assert_text_has_no_secrets(snapshot_text, "リポジトリスナップショット")
        return snapshot_text, ctx.is_git
    if facts_files:
        facts_blocks = load_facts_blocks(facts_files)
        snapshot_text = "\n\n".join(
            f"Supplemental Facts ({label}):\n{content}" for label, content in facts_blocks
        )
        assert_text_has_no_secrets(snapshot_text, "補助事実テキスト")
        return snapshot_text, None
    return None, None


def _run_candidates_subcommand(
    args: argparse.Namespace,
    *,
    api_key: str,
    opener: Callable[..., Any] | None,
    stdin_text: str | None,
) -> int:
    raw_data = _load_candidates_json(args.input, args.stdin, stdin_text)
    candidates = parse_candidates(raw_data)
    snapshot_text, is_git_flag = _build_optional_candidates_snapshot(args)
    batch_mode = getattr(args, "batch_mode", "chunk")

    if batch_mode == "single":
        payloads = [
            build_candidate_payload(
                c,
                model=args.model,
                max_chars=args.max_chars,
                snapshot_text=snapshot_text,
            )
            for c in candidates
        ]
        if args.dry_run:
            dry_report: dict[str, Any] = {
                "status": "dry_run",
                "subcommand": "candidates",
                "batch_mode": "single",
                "model": args.model,
                "total": len(candidates),
                "items": [
                    {
                        "id": c.id,
                        "category": c.category,
                        "title": c.title,
                        "payload": p,
                    }
                    for c, p in zip(candidates, payloads)
                ],
            }
            if is_git_flag is not None:
                dry_report["is_git"] = is_git_flag
            _emit_report(dry_report, args.format)
            return 0
    else:
        chunks = build_candidate_chunks(
            candidates,
            snapshot_text=snapshot_text,
            model=args.model,
            max_chars=args.max_chars,
            chunk_max_items=args.chunk_max_items,
        )
        if args.dry_run:
            dry_report = {
                "status": "dry_run",
                "subcommand": "candidates",
                "batch_mode": "chunk",
                "model": args.model,
                "total": len(candidates),
                "chunk_count": len(chunks),
                "chunks": [
                    {
                        "chunk_index": ch["chunk_index"],
                        "ids": ch["ids"],
                        "payload": ch["payload"],
                    }
                    for ch in chunks
                ],
            }
            if is_git_flag is not None:
                dry_report["is_git"] = is_git_flag
            _emit_report(dry_report, args.format)
            return 0

    if not candidates:
        _emit_report(
            {
                "status": "skipped_empty_input",
                "subcommand": "candidates",
                "model": args.model,
                "total": 0,
                "summary": {"needs_parent_review": 0, "ready": 0},
                "results": [],
            },
            args.format,
        )
        return 0

    _require_api_key(api_key)
    effective_timeout, effective_backend = _resolve_effective_timeout_and_backend(args)

    if batch_mode == "single":
        def _call_one(candidate: AuditCandidate, payload: dict[str, Any]) -> tuple[dict[str, Any], str]:
            raw, used_backend = run_decisions.call_decisions_backend(
                payload,
                api_key=api_key,
                backend=effective_backend,
                endpoint=args.endpoint,
                timeout=effective_timeout,
                opener=opener,
            )
            enriched = run_decisions.enrich_response(raw, min_confidence=args.min_confidence)
            row = classify_candidate_answers(
                candidate,
                enriched,
                min_confidence=args.min_confidence,
                discussion_threshold=args.discussion_threshold,
            )
            return row, used_backend

        worker_count = max(1, min(args.max_workers, len(candidates)))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(_call_one, c, p) for c, p in zip(candidates, payloads)]
            pair_results = [future.result() for future in futures]

        results = [row for row, _ in pair_results]
        used_backends = sorted({b for _, b in pair_results})
        usage_summary = _aggregate_usage(results)
    else:
        cand_q_keys = tuple(build_candidates_questions().keys())

        def _call_chunk(chunk: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any], str]:
            raw, used_backend = run_decisions.call_decisions_backend(
                chunk["payload"],
                api_key=api_key,
                backend=effective_backend,
                endpoint=args.endpoint,
                timeout=effective_timeout,
                opener=opener,
            )
            enriched = run_decisions.enrich_response(raw, min_confidence=args.min_confidence)
            chunk_rows: list[dict[str, Any]] = []
            for cand_ns, cand in zip(chunk["namespaces"], chunk["candidates"]):
                cand_answers = _unnamespace_answers(enriched.get("answers"), cand_ns, cand_q_keys)
                cand_enriched = {"answers": cand_answers}
                chunk_rows.append(
                    classify_candidate_answers(
                        cand,
                        cand_enriched,
                        min_confidence=args.min_confidence,
                        discussion_threshold=args.discussion_threshold,
                    )
                )
            usage_record = (
                {"usage": enriched["usage"]}
                if isinstance(enriched.get("usage"), dict)
                else {}
            )
            return chunk_rows, usage_record, used_backend

        worker_count = max(1, min(args.max_workers, len(chunks)))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = [executor.submit(_call_chunk, ch) for ch in chunks]
            chunk_outputs = [future.result() for future in futures]

        results = [row for chunk_rows, _, _ in chunk_outputs for row in chunk_rows]
        usage_records = [u_rec for _, u_rec, _ in chunk_outputs if u_rec]
        used_backends = sorted({b for _, _, b in chunk_outputs})
        usage_summary = _aggregate_usage(usage_records)

    review_count = sum(1 for r in results if r["needs_parent_review"])
    report: dict[str, Any] = {
        "status": "completed",
        "subcommand": "candidates",
        "batch_mode": batch_mode,
        "backend": used_backends[0] if len(used_backends) == 1 else ",".join(used_backends),
        "model": args.model,
        "total": len(results),
        "summary": {
            "needs_parent_review": review_count,
            "ready": len(results) - review_count,
        },
        "results": results,
    }
    if is_git_flag is not None:
        report["is_git"] = is_git_flag
    if usage_summary is not None:
        report["usage"] = usage_summary

    _emit_report(report, args.format)
    return 0


def _add_shared_api_options(parser: argparse.ArgumentParser, default_max_chars: int) -> None:
    parser.add_argument("--model", default=DEFAULT_MODEL, help="モデル ID（既定: gemini-decision-1）")
    parser.add_argument(
        "--backend",
        choices=("auto", "sdk", "rest"),
        default="auto",
        help="API 呼び出し経路（既定: auto、SDK 優先で REST フォールバック）",
    )
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT, help="Decisions API エンドポイント URL")
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="HTTP タイムアウト秒（既定: 30、明示指定時は REST 経路を使用）",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=DEFAULT_MIN_CONFIDENCE,
        help="信頼度下限（既定: 0.80）",
    )
    parser.add_argument(
        "--max-chars",
        type=int,
        default=default_max_chars,
        help=f"1 リクエスト入力文字数上限（既定: {default_max_chars:,}）",
    )
    parser.add_argument(
        "--format",
        choices=("json", "table"),
        default="json",
        help="出力形式（既定: json）",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="API 送信せず検証済みペイロードを出力して終了する（GEMINI_API_KEY 不要）",
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Gemini Decision 1 で repo-drift-audit の一次スクリーニングを行う CLI"
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    docs_parser = subparsers.add_parser(
        "docs",
        help="文書・スキルの陳腐化と機械化余地を一次スクリーニングする",
    )
    docs_parser.add_argument("--repo", default=".", help="対象リポジトリルート（既定: .）")
    docs_parser.add_argument(
        "--paths",
        nargs="+",
        action="extend",
        default=[],
        help="検査対象の相対パスまたはグロブ（省略時は主要ルート文書と docs / skills / rules 配下の Markdown、slop-catalog.md を除く）",
    )
    docs_parser.add_argument(
        "--facts-file",
        action="append",
        default=[],
        help="共有スナップショットへ追加する補助事実テキストファイル（複数指定可）",
    )
    docs_parser.add_argument(
        "--git-log-limit",
        type=int,
        default=DEFAULT_DOCS_GIT_LOG_LIMIT,
        help="共有スナップショットに含める直近コミット件数（既定: 30）",
    )
    docs_parser.add_argument(
        "--max-workers",
        type=int,
        default=DEFAULT_MAX_WORKERS,
        help="並列リクエスト数上限（既定: 4）",
    )
    docs_parser.add_argument(
        "--batch-mode",
        choices=("chunk", "single"),
        default="chunk",
        help="バッチ送信方式（既定: chunk、single で従来の 1 文書 1 リクエスト）",
    )
    docs_parser.add_argument(
        "--chunk-max-docs",
        type=int,
        default=DEFAULT_CHUNK_MAX_DOCS,
        help=f"chunk モード時の 1 チャンクあたり最大文書数（1..{MAX_CHUNK_MAX_DOCS}、既定: {DEFAULT_CHUNK_MAX_DOCS}）",
    )
    _add_shared_api_options(docs_parser, DEFAULT_DOCS_MAX_CHARS)

    backlog_parser = subparsers.add_parser(
        "backlog",
        help="残課題帳簿の未完了項目を共有スナップショットへ 1 リクエストで一括突合する",
    )
    backlog_parser.add_argument("--backlog", required=True, help="残課題帳簿ファイル（Markdown または JSON）")
    backlog_parser.add_argument(
        "--backlog-format",
        choices=("auto", "markdown", "table", "json"),
        default="auto",
        help="残課題ファイルの形式（既定: auto）",
    )
    backlog_parser.add_argument(
        "--include-tables",
        action="store_true",
        help="auto/markdown モード時にチェックボックスと併せて Markdown 表からも未完了項目を抽出する",
    )
    backlog_parser.add_argument("--repo", default=".", help="対象リポジトリルート（既定: .）")
    backlog_parser.add_argument(
        "--facts-file",
        action="append",
        default=[],
        help="共有スナップショットへ追加する補助事実テキストファイル（複数指定可）",
    )
    backlog_parser.add_argument(
        "--git-log-limit",
        type=int,
        default=DEFAULT_BACKLOG_GIT_LOG_LIMIT,
        help="共有スナップショットに含める直近コミット件数（既定: 50）",
    )
    _add_shared_api_options(backlog_parser, DEFAULT_BACKLOG_MAX_CHARS)

    cand_parser = subparsers.add_parser(
        "candidates",
        help="第一走査候補を計画ワーカー投入前に並列トリアージする",
    )
    cand_parser.add_argument("--input", default=None, help="候補 JSON 配列ファイルのパス")
    cand_parser.add_argument("--stdin", action="store_true", help="標準入力から候補 JSON 配列を読み込む")
    cand_parser.add_argument(
        "--repo",
        default=None,
        help="任意: 共有スナップショットを構築する対象リポジトリルート",
    )
    cand_parser.add_argument(
        "--facts-file",
        action="append",
        default=[],
        help="共有スナップショットへ追加する補助事実テキストファイル（複数指定可）",
    )
    cand_parser.add_argument(
        "--git-log-limit",
        type=int,
        default=DEFAULT_CANDIDATES_GIT_LOG_LIMIT,
        help="--repo 指定時にスナップショットへ含める直近コミット件数（既定: 30）",
    )
    cand_parser.add_argument(
        "--batch-mode",
        choices=("chunk", "single"),
        default="chunk",
        help="バッチ送信方式（既定: chunk、single で従来の 1 候補 1 リクエスト）",
    )
    cand_parser.add_argument(
        "--chunk-max-items",
        type=int,
        default=DEFAULT_CHUNK_MAX_ITEMS,
        help=f"chunk モード時の 1 チャンクあたり最大候補数（1..{MAX_CHUNK_MAX_ITEMS}、既定: {DEFAULT_CHUNK_MAX_ITEMS}）",
    )
    cand_parser.add_argument(
        "--max-workers",
        type=int,
        default=DEFAULT_MAX_WORKERS,
        help="並列リクエスト数上限（既定: 4）",
    )
    cand_parser.add_argument(
        "--discussion-threshold",
        type=float,
        default=DEFAULT_DISCUSSION_THRESHOLD,
        help="要親確認へ上げる needs_discussion の閾値（既定: 0.50）",
    )
    _add_shared_api_options(cand_parser, DEFAULT_CANDIDATES_MAX_CHARS)

    return parser


def main(
    argv: list[str] | None = None,
    *,
    opener: Callable[..., Any] | None = None,
    env: dict[str, str] | None = None,
    stdin_text: str | None = None,
) -> int:
    """CLI 引数を解釈して指定サブコマンドを実行し、終了コードを返す。"""
    configure_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    environ = os.environ if env is None else env
    api_key = environ.get("GEMINI_API_KEY", "").strip()

    try:
        _validate_common_args(args)
        if args.subcommand == "docs":
            return _run_docs_subcommand(args, api_key=api_key, opener=opener)
        if args.subcommand == "backlog":
            return _run_backlog_subcommand(args, api_key=api_key, opener=opener)
        if args.subcommand == "candidates":
            return _run_candidates_subcommand(
                args,
                api_key=api_key,
                opener=opener,
                stdin_text=stdin_text,
            )
        raise DriftScreenError("unknown_subcommand", f"不明なサブコマンドです: {args.subcommand}", exit_code=2)
    except DriftScreenError as exc:
        _emit_error(exc.code, exc.message, exc.exit_code, args.format, api_key)
        return exc.exit_code
    except run_decisions.SafetyBlockError as exc:
        _emit_error(
            "safety_blocked",
            f"安全フィルタにより遮断されました ({exc.source}/{exc.code}): {exc.message}",
            3,
            args.format,
            api_key,
        )
        return 3
    except (run_decisions.ApiRequestError, TimeoutError, ValueError) as exc:
        msg = exc.message if isinstance(exc, run_decisions.ApiRequestError) else str(exc)
        _emit_error("api_request_failed", f"API 呼び出しエラー: {msg}", 1, args.format, api_key)
        return 1
    except OSError as exc:
        if decision_common.is_broken_pipe_error(exc):
            discard_fn = getattr(drift_format, "discard_broken_stdout", None)
            if callable(discard_fn):
                discard_fn()
            return 0
        _emit_error("unexpected_error", str(exc), 2, args.format, api_key)
        return 2
    except Exception as exc:  # noqa: BLE001
        if decision_common.is_broken_pipe_error(exc):
            discard_fn = getattr(drift_format, "discard_broken_stdout", None)
            if callable(discard_fn):
                discard_fn()
            return 0
        _emit_error("unexpected_error", str(exc), 2, args.format, api_key)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
