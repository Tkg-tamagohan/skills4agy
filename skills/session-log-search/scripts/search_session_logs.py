#!/usr/bin/env python3
"""Antigravity 過去ログとアーティファクトのステートレス語句検索 CLI。

外部依存・API 課金・永続 DB を使わず、os.scandir + ripgrep (-l 事前フィルタ)
+ 768 文字窓 Hybrid BM25 + 5K 予算つき時系列復元を実行する。
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Sequence
import unicodedata

_DECISIONS_SCRIPTS_DIR = (
    Path(__file__).resolve().parents[2] / "gemini-decisions-api" / "scripts"
)
if str(_DECISIONS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_DECISIONS_SCRIPTS_DIR))

import decision_hygiene  # noqa: E402

NOISE_TOOLS: frozenset[str] = frozenset(
    {"read_file", "view_file", "read_board", "update_focus", "update_steps"}
)
WINDOW_CHARS = 768
WINDOW_OVERLAP = 96
WINDOW_STRIDE = WINDOW_CHARS - WINDOW_OVERLAP
TOP_WINDOWS = 30
DEFAULT_MAX_PRIMARY = 8
MAX_PRIMARY_UPPER = 10
DEFAULT_MAX_TURNS = 15
DEFAULT_BUDGET_TOKENS = 4500
EXCERPT_RADIUS = 400
MIN_EXCERPT_RADIUS = 60
CONTEXT_EXCERPT_CHARS = 800
FULL_HEAD_LINES = 40
FULL_TAIL_LINES = 60
GIT_LOG_LIMIT = 200
MAX_TERMS = 12
MIN_GENERIC_CHARS = 40
RG_BATCH_MAX_CHARS = 24000
SELF_SCRIPT_NAME = "search_session_logs.py"

URL_CREDENTIAL_RE = re.compile(r"(?<=://)[^\s/?#@:]+:[^\s/?#@]+(?=@)")
USER_REQUEST_RE = re.compile(r"<USER_REQUEST>(.*?)</USER_REQUEST>", re.DOTALL)
STRIP_TAG_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<ADDITIONAL_METADATA>.*?</ADDITIONAL_METADATA>", re.DOTALL),
    re.compile(r"<USER_SETTINGS_CHANGE>.*?</USER_SETTINGS_CHANGE>", re.DOTALL),
    re.compile(r"<PLAN>.*?</PLAN>", re.DOTALL),
)
TIMESTAMP_HEADER_RE = re.compile(
    r"^(?:Created At|Completed At):[^\n]*\n?", re.MULTILINE
)
EXIT0_BOILERPLATE_RE = re.compile(
    r"Command exited with code 0\.?\s*|Command output:\s*"
)
ERROR_SIGNAL_RE = re.compile(
    r"(?:Command exited with code [1-9]\d*|Traceback \(most recent call last\)|"
    r"\bFAILED\b|\bERROR:|error:|AssertionError|Exception:|PermissionError|SyntaxError)"
)
BACKTICK_RUN_RE = re.compile(r"`+")

PRIORITY_ARG_KEYS: tuple[str, ...] = (
    "CommandLine",
    "Path",
    "Target",
    "query",
    "Query",
    "Action",
    "Role",
    "Prompt",
    "TaskId",
)

ASCII_COMPOUND_RE = re.compile(
    r"[0-9A-Za-z_]+(?:[:.\-/]+[0-9A-Za-z_]+)*"
)
CAMEL_SPLIT_RE = re.compile(
    r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[0-9]+|[A-Z]+"
)
JAPANESE_RUN_RE = re.compile(
    r"[\u3040-\u309f\u30a0-\u30ff\u30fc\u4e00-\u9fff\u3400-\u4dbf]+"
)
LEADING_HYPHENS_RE = re.compile(r"^-+")


@dataclass
class SourceSpec:
    """検索対象の単一データソース。"""

    source_id: str
    kind: str  # "transcript" | "artifact" | "repo_doc" | "git_commit"
    conv_id: str
    path: Path | None = None
    mtime_iso: str = ""
    raw_text: str = ""
    label: str = ""


@dataclass
class TurnEntry:
    """会話内の 1 ターン（または単一文書・コミット）。"""

    conv_id: str
    turn_idx: int
    source_kind: str
    created_at: str
    first_line_idx: int
    step_index: int
    lines: list[tuple[int, str]] = field(default_factory=list)
    label: str = ""
    can_expand_context: bool = True
    source_key: str = ""

    def full_text(self) -> str:
        return "\n".join(text for _, text in self.lines if text)


@dataclass
class WindowCandidate:
    """BM25 評価対象の 768 文字窓。"""

    conv_id: str
    turn_idx: int
    line_idx: int
    window_idx: int
    line_text: str
    window_text: str
    created_at: str
    tokens: list[str]
    source_key: str = ""
    score: float = 0.0
    term_hits: int = 0


@dataclass
class SelectedTurn:
    """出力用に採用されたターン。"""

    turn: TurnEntry
    role: str  # "primary" | "context"
    rendered_text: str
    excerpted: bool
    tokens: int
    best_score: float
    match_line_idx: int | None = None


def apply_mask(text: str) -> str:
    """窓分割や切り出しの前に必ずシークレットと資格情報をマスクする。"""
    if not text:
        return ""
    return decision_hygiene.mask_secrets(
        text,
        extra_patterns=(decision_hygiene.BEARER_TOKEN_RE, URL_CREDENTIAL_RE),
    )


def estimate_tokens(text: str) -> int:
    """文字種別の簡易式（ascii/4 + non_ascii/1.5）でトークン数を見積もる。"""
    if not text:
        return 0
    ascii_chars = sum(1 for ch in text if ord(ch) < 128)
    non_ascii_chars = len(text) - ascii_chars
    return math.ceil(ascii_chars / 4.0 + non_ascii_chars / 1.5)


def is_blocked_path(path: Path | str) -> bool:
    """厳格ブロックリストに該当するパスか判定する。"""
    norm = str(path).replace("\\", "/").lower()
    basename = norm.rsplit("/", 1)[-1]
    if "/.system_generated/logs/chunks/" in norm or norm.endswith("/.system_generated/logs/chunks"):
        return True
    if "/.system_generated/steps/" in norm or norm.endswith("/.system_generated/steps"):
        return True
    if basename.startswith("conversation_summaries.db"):
        return True
    if "/conversations/" in norm and ".db" in basename:
        return True
    if norm.endswith(".pb"):
        return True
    if basename in ("oauth_creds.json", "google_accounts.json"):
        return True
    return decision_hygiene.is_blocked_env_path(path)


def tokenize(text: str) -> list[str]:
    """NFKC 正規化・識別子分割・日本語 2/3-gram によるトークン化を行う。"""
    if not text:
        return []
    nfkc = unicodedata.normalize("NFKC", text)
    # 検索語の先頭ハイフン（例: --min-steps）を落としても複合語・部品の両方が出るよう前処理する
    cleaned = re.sub(r"(?:^|(?<=\s))-+", "", nfkc)
    tokens: list[str] = []

    for match in ASCII_COMPOUND_RE.finditer(cleaned):
        raw_comp = match.group(0)
        comp_lower = raw_comp.casefold()
        tokens.append(comp_lower)
        parts = re.split(r"[:.\-/]+", raw_comp)
        sub_tokens: list[str] = []
        for part in parts:
            if not part:
                continue
            sub_tokens.append(part.casefold())
            for under in part.split("_"):
                if not under:
                    continue
                sub_tokens.append(under.casefold())
                for camel in CAMEL_SPLIT_RE.findall(under):
                    if camel:
                        sub_tokens.append(camel.casefold())
        for sub in sub_tokens:
            if sub != comp_lower:
                tokens.append(sub)

    for jmatch in JAPANESE_RUN_RE.finditer(cleaned.casefold()):
        chunk = jmatch.group(0)
        n = len(chunk)
        if n == 1:
            tokens.append(chunk)
            continue
        for i in range(n - 1):
            tokens.append(chunk[i : i + 2])
        for i in range(n - 2):
            tokens.append(chunk[i : i + 3])

    return tokens


def _mtime_iso(stat_res: os.stat_result) -> str:
    return datetime.fromtimestamp(stat_res.st_mtime, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _parse_iso_to_utc_dt(value: str) -> datetime | None:
    if not value:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if cleaned.endswith(("Z", "z")):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _utc_sort_key(value: str) -> str:
    """ISO 8601 文字列を UTC 基準の比較用文字列へ正規化する（欠損時は末尾扱い）。"""
    dt = _parse_iso_to_utc_dt(value)
    if dt is None:
        return "9999-12-31T23:59:59.999999Z"
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse_since_timestamp(since: str | None) -> float | None:
    if not since:
        return None
    try:
        dt = datetime.strptime(since, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError(f"--since は YYYY-MM-DD 形式で指定してください: {since}") from exc
    return dt.timestamp()


def _collect_git_commits(
    repo_path: Path, since: str | None, warnings: list[str]
) -> list[SourceSpec]:
    since_ts = _parse_since_timestamp(since)
    cmd = [
        "git",
        "-c",
        "core.quotePath=false",
        "-C",
        str(repo_path),
        "--no-optional-locks",
        "log",
        "-n",
        str(GIT_LOG_LIMIT),
        "--format=%H%x1f%cI%x1f%s%x1f%b%x1e",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        warnings.append(f"git log の実行をスキップしました: {exc}")
        return []
    if proc.returncode != 0:
        err_msg = apply_mask(proc.stderr.strip())
        warnings.append(f"git log が終了コード {proc.returncode} のためスキップしました: {err_msg}")
        return []

    specs: list[SourceSpec] = []
    for record in proc.stdout.split("\x1e"):
        rec = record.strip()
        if not rec:
            continue
        fields = rec.split("\x1f")
        if len(fields) < 3:
            continue
        commit_hash = fields[0].strip()
        committed_iso = fields[1].strip()
        subject = fields[2].strip()
        body = fields[3].strip() if len(fields) > 3 else ""
        if since_ts is not None:
            commit_dt = _parse_iso_to_utc_dt(committed_iso)
            if commit_dt is not None and commit_dt.timestamp() < since_ts:
                continue
        text = f"commit {commit_hash}\n{subject}"
        if body:
            text += f"\n\n{body}"
        masked_subject = apply_mask(subject)
        specs.append(
            SourceSpec(
                source_id=f"git:{commit_hash[:8]}",
                kind="git_commit",
                conv_id=f"git:{commit_hash[:8]}",
                mtime_iso=committed_iso,
                raw_text=text,
                label=f"git:{commit_hash[:8]} ({masked_subject[:60]})",
            )
        )
    return specs


def enumerate_sources(
    app_data_dir: Path,
    *,
    conversation_ids: Sequence[str] = (),
    exclude_conversation_ids: Sequence[str] = (),
    repo_path: Path | None = None,
    since: str | None = None,
    warnings: list[str] | None = None,
) -> list[SourceSpec]:
    """os.scandir により厳格ブロックリストを回避しつつ検索対象を直接列挙する。"""
    warn_list = warnings if warnings is not None else []
    brain_dir = app_data_dir / "brain"
    if not brain_dir.is_dir():
        raise FileNotFoundError(f"brain ディレクトリが見つかりません: {brain_dir}")

    since_ts = _parse_since_timestamp(since)
    include_set = {cid for cid in conversation_ids if cid}
    exclude_set = {cid for cid in exclude_conversation_ids if cid}
    sources: list[SourceSpec] = []

    with os.scandir(brain_dir) as brain_it:
        for entry in brain_it:
            try:
                if not entry.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            conv_id = entry.name
            if include_set and conv_id not in include_set:
                continue
            if conv_id in exclude_set:
                continue

            conv_dir = Path(entry.path)
            transcript = conv_dir / ".system_generated" / "logs" / "transcript.jsonl"
            if not is_blocked_path(transcript) and transcript.is_file():
                try:
                    st = transcript.stat()
                    if since_ts is None or st.st_mtime >= since_ts:
                        sources.append(
                            SourceSpec(
                                source_id=f"transcript:{conv_id}",
                                kind="transcript",
                                conv_id=conv_id,
                                path=transcript,
                                mtime_iso=_mtime_iso(st),
                                label=f"transcript:{conv_id}",
                            )
                        )
                except OSError:
                    pass

            try:
                with os.scandir(conv_dir) as conv_it:
                    for sub in conv_it:
                        try:
                            if not sub.is_file(follow_symlinks=False):
                                continue
                        except OSError:
                            continue
                        if not sub.name.lower().endswith(".md"):
                            continue
                        sub_path = Path(sub.path)
                        if is_blocked_path(sub_path):
                            continue
                        try:
                            st = sub.stat()
                            if since_ts is None or st.st_mtime >= since_ts:
                                sources.append(
                                    SourceSpec(
                                        source_id=f"artifact:{conv_id}:{sub.name}",
                                        kind="artifact",
                                        conv_id=conv_id,
                                        path=sub_path,
                                        mtime_iso=_mtime_iso(st),
                                        label=f"{conv_id}/{sub.name}",
                                    )
                                )
                        except OSError:
                            continue
            except OSError:
                continue

    if repo_path is not None:
        docs_dir = repo_path / "docs"
        if docs_dir.is_dir():
            try:
                with os.scandir(docs_dir) as doc_it:
                    for entry in doc_it:
                        try:
                            if not entry.is_file(follow_symlinks=False):
                                continue
                        except OSError:
                            continue
                        if not entry.name.lower().endswith(".md"):
                            continue
                        doc_path = Path(entry.path)
                        if is_blocked_path(doc_path):
                            continue
                        try:
                            st = doc_path.stat()
                            if since_ts is None or st.st_mtime >= since_ts:
                                sources.append(
                                    SourceSpec(
                                        source_id=f"doc:{entry.name}",
                                        kind="repo_doc",
                                        conv_id=f"docs/{entry.name}",
                                        path=doc_path,
                                        mtime_iso=_mtime_iso(st),
                                        label=f"docs/{entry.name}",
                                    )
                                )
                        except OSError:
                            continue
            except OSError as exc:
                warn_list.append(f"docs ディレクトリの列挙に失敗しました: {exc}")

        sources.extend(_collect_git_commits(repo_path, since, warn_list))

    return sources


def _term_variants_for_rg(terms: Sequence[str]) -> list[str]:
    variants: list[str] = []
    seen: set[str] = set()
    for term in terms:
        if not term:
            continue
        if term not in seen:
            seen.add(term)
            variants.append(term)
        esc = json.dumps(term, ensure_ascii=False)[1:-1]
        if esc != term and esc not in seen:
            seen.add(esc)
            variants.append(esc)
    return variants


def prefilter_python(paths: Sequence[Path], terms: Sequence[str]) -> set[str]:
    """Python ストリーミングで検索語（JSON エスケープ形を含む）を含むファイルパス集合を返す。"""
    terms_cf = [v.casefold() for v in _term_variants_for_rg(terms) if v]
    matched: set[str] = set()
    if not terms_cf:
        return matched
    for path in paths:
        if is_blocked_path(path):
            continue
        try:
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    cf = line.casefold()
                    if any(t in cf for t in terms_cf):
                        matched.add(os.path.normcase(os.path.abspath(str(path))))
                        break
        except OSError:
            continue
    return matched


def prefilter_with_rg(
    paths: Sequence[Path],
    terms: Sequence[str],
    warnings: list[str],
) -> tuple[set[str] | None, bool]:
    """ripgrep (-l -i -F -e) で候補ファイルを高速絞り込みする。戻り値は (matched_set, used_rg)。"""
    safe_paths = [p for p in paths if not is_blocked_path(p)]
    if not safe_paths:
        return set(), False
    rg_bin = shutil.which("rg")
    if not rg_bin:
        return None, False

    variants = _term_variants_for_rg(terms)
    if not variants:
        return set(), True

    expr_args: list[str] = []
    for var in variants:
        expr_args.extend(["-e", var])

    batches: list[list[Path]] = []
    cur_batch: list[Path] = []
    cur_len = 0
    for path in safe_paths:
        p_str = str(path)
        add_len = len(p_str) + 3
        if cur_batch and cur_len + add_len > RG_BATCH_MAX_CHARS:
            batches.append(cur_batch)
            cur_batch = [path]
            cur_len = add_len
        else:
            cur_batch.append(path)
            cur_len += add_len
    if cur_batch:
        batches.append(cur_batch)

    matched: set[str] = set()
    used_rg_any = False
    for batch in batches:
        cmd = [
            rg_bin,
            "--no-config",
            "--no-messages",
            "-l",
            "-i",
            "-F",
            *expr_args,
            "--",
            *[str(p) for p in batch],
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                shell=False,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            warnings.append(f"rg 実行に失敗したため Python 走査へ切り替えました: {exc}")
            matched.update(prefilter_python(batch, terms))
            continue

        if proc.returncode in (0, 1):
            used_rg_any = True
            for raw_line in proc.stdout.splitlines():
                hit = raw_line.strip()
                if hit:
                    matched.add(os.path.normcase(os.path.abspath(hit)))
        else:
            warnings.append(
                f"rg が終了コード {proc.returncode} を返したため一部バッチを Python 走査へ切り替えました"
            )
            matched.update(prefilter_python(batch, terms))

    return matched, used_rg_any


def _extract_user_input_text(content: str) -> str:
    match = USER_REQUEST_RE.search(content)
    if match:
        body = match.group(1).strip()
        if body:
            return body
    stripped = content
    for pat in STRIP_TAG_PATTERNS:
        stripped = pat.sub("", stripped)
    stripped = re.sub(r"</?USER_REQUEST>", "", stripped)
    return stripped.strip()


def _parse_tool_calls(raw_tool_calls: Any) -> list[tuple[str, dict[str, Any], str]]:
    if not isinstance(raw_tool_calls, list):
        return []
    parsed: list[tuple[str, dict[str, Any], str]] = []
    for call in raw_tool_calls:
        if not isinstance(call, dict):
            continue
        name = str(call.get("name") or "unknown")
        raw_args = call.get("args")
        if raw_args is None:
            raw_args = call.get("arguments")
        if isinstance(raw_args, str):
            try:
                decoded = json.loads(raw_args)
                args_dict = decoded if isinstance(decoded, dict) else {}
            except json.JSONDecodeError:
                args_dict = {}
        elif isinstance(raw_args, dict):
            args_dict = raw_args
        else:
            args_dict = {}
        cmd_str = str(args_dict.get("CommandLine") or args_dict.get("command") or "")
        parsed.append((name, args_dict, cmd_str))
    return parsed


def _summarize_non_noise_tools(
    tools: Sequence[tuple[str, dict[str, Any], str]]
) -> str:
    items: list[str] = []
    for name, args_dict, cmd_str in tools:
        if name in NOISE_TOOLS:
            continue
        if name == "run_command" and SELF_SCRIPT_NAME in cmd_str:
            continue
        arg_preview = ""
        if args_dict:
            chosen_key: str | None = None
            for key in PRIORITY_ARG_KEYS:
                if key in args_dict and args_dict[key] not in (None, ""):
                    chosen_key = key
                    break
            if chosen_key is None:
                chosen_key = next(iter(args_dict.keys()))
            val_str = apply_mask(re.sub(r"\s+", " ", str(args_dict[chosen_key])).strip())
            if len(val_str) > 200:
                val_str = val_str[:197] + "..."
            arg_preview = f"{chosen_key}={val_str}"
        items.append(f"{name}({arg_preview})" if arg_preview else f"{name}()")
    return ", ".join(items)


def _extract_generic_content(raw_content: str) -> str:
    text = raw_content
    if text.lstrip().startswith("{"):
        try:
            obj = json.loads(text)
            if isinstance(obj, dict) and isinstance(obj.get("output"), str):
                text = obj["output"]
        except json.JSONDecodeError:
            pass
    return TIMESTAMP_HEADER_RE.sub("", text).strip()


def _is_trivial_generic(text: str) -> bool:
    without_boiler = EXIT0_BOILERPLATE_RE.sub("", text)
    non_ws_len = len(re.sub(r"\s+", "", without_boiler))
    return non_ws_len < MIN_GENERIC_CHARS


def _load_full_lines(full_path: Path, line_idxs: set[int]) -> dict[int, str]:
    if not line_idxs or is_blocked_path(full_path) or not full_path.is_file():
        return {}
    result: dict[int, str] = {}
    with full_path.open("r", encoding="utf-8", errors="replace") as fh:
        for idx, raw_line in enumerate(fh):
            if idx not in line_idxs:
                continue
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                result[idx] = str(obj.get("content") or "")
            if len(result) >= len(line_idxs):
                break
    return result


def _head_tail_lines(text: str, head_lines: int, tail_lines: int) -> str:
    lines = text.splitlines()
    if len(lines) <= head_lines + tail_lines:
        return text
    omitted = len(lines) - head_lines - tail_lines
    return "\n".join(
        lines[:head_lines]
        + [f"...[{omitted} 行省略]..."]
        + lines[-tail_lines:]
    )


def load_transcript_turns(
    path: Path,
    conv_id: str,
    *,
    include_thinking: bool,
    terms_cf: Sequence[str],
    warnings: list[str],
) -> list[TurnEntry]:
    """transcript.jsonl を読み込み、ノイズを除外してターン列へまとめる。"""
    if is_blocked_path(path):
        return []

    turns: list[TurnEntry] = []
    current_turn: TurnEntry | None = None
    pending_tools: list[tuple[str, dict[str, Any], str]] = []
    tool_cursor = 0
    full_candidates: list[tuple[int, int, int]] = []  # (turn_list_idx, line_pos_in_turn, line_idx)

    try:
        fh = path.open("r", encoding="utf-8", errors="replace")
    except OSError as exc:
        warnings.append(f"transcript 読み込み失敗 ({conv_id}): {exc}")
        return []

    with fh:
        for line_idx, raw_line in enumerate(fh):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue

            step_type = str(obj.get("type") or "")
            created_at = str(obj.get("created_at") or "")
            step_index_raw = obj.get("step_index")
            step_index = step_index_raw if isinstance(step_index_raw, int) else -1
            status = str(obj.get("status") or "")

            if step_type == "SYSTEM_MESSAGE":
                continue

            if step_type == "USER_INPUT":
                pending_tools = []
                tool_cursor = 0
                user_text = _extract_user_input_text(str(obj.get("content") or ""))
                turn = TurnEntry(
                    conv_id=conv_id,
                    turn_idx=len(turns),
                    source_kind="USER_INPUT",
                    created_at=created_at,
                    first_line_idx=line_idx,
                    step_index=step_index,
                    lines=[(line_idx, user_text)] if user_text else [],
                    source_key=conv_id,
                )
                turns.append(turn)
                current_turn = turn
                continue

            if step_type == "PLANNER_RESPONSE":
                pending_tools = _parse_tool_calls(obj.get("tool_calls"))
                tool_cursor = 0
                parts: list[str] = []
                content_str = str(obj.get("content") or "").strip()
                if content_str:
                    parts.append(content_str)
                tool_sum = _summarize_non_noise_tools(pending_tools)
                if tool_sum:
                    parts.append(f"[tools] {tool_sum}")
                if include_thinking:
                    thinking_str = str(obj.get("thinking") or "").strip()
                    if thinking_str:
                        parts.append(f"[thinking] {thinking_str}")
                body = "\n".join(parts)
                turn = TurnEntry(
                    conv_id=conv_id,
                    turn_idx=len(turns),
                    source_kind="PLANNER_RESPONSE",
                    created_at=created_at,
                    first_line_idx=line_idx,
                    step_index=step_index,
                    lines=[(line_idx, body)] if body else [],
                    source_key=conv_id,
                )
                turns.append(turn)
                current_turn = turn
                continue

            if step_type == "GENERIC":
                if tool_cursor < len(pending_tools):
                    tool_name, _, cmd_str = pending_tools[tool_cursor]
                    tool_cursor += 1
                else:
                    tool_name, cmd_str = "unknown", ""

                if tool_name in NOISE_TOOLS:
                    continue
                if tool_name == "run_command" and SELF_SCRIPT_NAME in cmd_str:
                    continue

                raw_content = str(obj.get("content") or "")
                cleaned = _extract_generic_content(raw_content)
                is_err = status.upper() == "ERROR" or bool(ERROR_SIGNAL_RE.search(cleaned))
                if not cleaned or (_is_trivial_generic(cleaned) and not is_err):
                    continue

                if current_turn is None:
                    current_turn = TurnEntry(
                        conv_id=conv_id,
                        turn_idx=len(turns),
                        source_kind="GENERIC",
                        created_at=created_at,
                        first_line_idx=line_idx,
                        step_index=step_index,
                        source_key=conv_id,
                    )
                    turns.append(current_turn)

                tagged_text = f"[{tool_name}] {cleaned}"
                line_pos = len(current_turn.lines)
                current_turn.lines.append((line_idx, tagged_text))

                raw_trunc = obj.get("truncated_fields")
                is_truncated = isinstance(raw_trunc, list) and "content" in raw_trunc
                if tool_name == "run_command" and is_truncated and is_err:
                    cf = tagged_text.casefold()
                    if any(t in cf for t in terms_cf):
                        full_candidates.append((len(turns) - 1, line_pos, line_idx))

    if full_candidates:
        full_path = path.with_name("transcript_full.jsonl")
        try:
            same = full_path == path or (
                full_path.exists()
                and path.exists()
                and full_path.resolve() == path.resolve()
            )
        except OSError:
            same = full_path == path

        if not same and full_path.is_file() and not is_blocked_path(full_path):
            needed = {lidx for _, _, lidx in full_candidates}
            try:
                loaded = _load_full_lines(full_path, needed)
            except OSError as exc:
                warnings.append(f"transcript_full.jsonl 読み込み失敗 ({conv_id}): {exc}")
                loaded = {}
            for t_idx, l_pos, l_idx in full_candidates:
                full_raw = loaded.get(l_idx)
                if not full_raw:
                    continue
                full_cleaned = _extract_generic_content(full_raw)
                if not full_cleaned:
                    continue
                # 先行シークレットマスク後に head/tail 切り出しを行う
                full_masked = apply_mask(full_cleaned)
                excerpted_full = _head_tail_lines(
                    full_masked, FULL_HEAD_LINES, FULL_TAIL_LINES
                )
                orig_masked = apply_mask(turns[t_idx].lines[l_pos][1])
                orig_cf = orig_masked.casefold()
                excerpt_cf = excerpted_full.casefold()
                if all(t in excerpt_cf for t in terms_cf if t in orig_cf):
                    turns[t_idx].lines[l_pos] = (l_idx, f"[run_command full] {excerpted_full}")
                else:
                    turns[t_idx].lines[l_pos] = (
                        l_idx,
                        f"{orig_masked}\n[run_command full]\n{excerpted_full}",
                    )

    return turns


def load_document_turn(spec: SourceSpec, warnings: list[str]) -> list[TurnEntry]:
    """アーティファクト md / docs / git log を単一ターンとして読み込む。"""
    if spec.kind == "git_commit":
        text = spec.raw_text
    else:
        if spec.path is None or is_blocked_path(spec.path):
            return []
        try:
            text = spec.path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            warnings.append(f"文書読み込み失敗 ({spec.label}): {exc}")
            return []

    if not text.strip():
        return []
    return [
        TurnEntry(
            conv_id=spec.conv_id,
            turn_idx=0,
            source_kind=spec.kind,
            created_at=spec.mtime_iso,
            first_line_idx=0,
            step_index=-1,
            lines=[(0, text)],
            label=spec.label,
            can_expand_context=False,
            source_key=spec.source_id,
        )
    ]


def split_windows(text: str) -> list[str]:
    """表示テキストを 768 文字窓・96 文字重複で分割する。"""
    if len(text) <= WINDOW_CHARS:
        return [text]
    windows: list[str] = []
    pos = 0
    while pos < len(text):
        chunk = text[pos : pos + WINDOW_CHARS]
        windows.append(chunk)
        if pos + WINDOW_CHARS >= len(text):
            break
        pos += WINDOW_STRIDE
    return windows


def score_windows_bm25(
    windows: list[WindowCandidate],
    terms: Sequence[str],
) -> list[WindowCandidate]:
    """候補窓集合に対して Hybrid BM25 (k1=1.2, b=0.75) を計算し、スコア降順の全窓を返す。"""
    if not windows:
        return []

    query_tokens: list[str] = []
    seen_q: set[str] = set()
    for term in terms:
        for tok in tokenize(term):
            if tok not in seen_q:
                seen_q.add(tok)
                query_tokens.append(tok)

    if not query_tokens:
        return []

    n_docs = len(windows)
    df: Counter[str] = Counter()
    tf_list: list[Counter[str]] = []
    total_len = 0
    for win in windows:
        counts = Counter(win.tokens)
        tf_list.append(counts)
        total_len += len(win.tokens)
        for qt in query_tokens:
            if counts.get(qt, 0) > 0:
                df[qt] += 1

    avgdl = total_len / n_docs if total_len > 0 else 1.0
    k1 = 1.2
    b = 0.75

    terms_cf = [t.casefold() for t in terms if t]
    for win, counts in zip(windows, tf_list):
        dl = len(win.tokens)
        norm_len = 1.0 - b + b * (dl / avgdl) if avgdl > 0 else 1.0
        score = 0.0
        for qt in query_tokens:
            tf = counts.get(qt, 0)
            if tf <= 0:
                continue
            df_q = df[qt]
            idf = math.log((n_docs - df_q + 0.5) / (df_q + 0.5) + 1.0)
            tf_part = (tf * (k1 + 1.0)) / (tf + k1 * norm_len)
            score += idf * tf_part
        win.score = score
        win_cf = win.window_text.casefold()
        win.term_hits = sum(1 for t in terms_cf if t in win_cf)

    windows.sort(
        key=lambda w: (
            -w.score,
            -w.term_hits,
            _utc_sort_key(w.created_at),
            w.source_key or w.conv_id,
            w.line_idx,
            w.window_idx,
        )
    )
    return windows


def _find_best_casefold_span(
    text: str, terms_cf: Sequence[str]
) -> tuple[int, int] | None:
    """text を casefold() した空間で一致を探し、元の文字位置 (start, end) を返す。"""
    if not text:
        return None
    cf_chars: list[str] = []
    cf_to_orig_start: list[int] = []
    cf_to_orig_end: list[int] = []
    for orig_idx, ch in enumerate(text):
        for fch in ch.casefold():
            cf_chars.append(fch)
            cf_to_orig_start.append(orig_idx)
            cf_to_orig_end.append(orig_idx + 1)
    cf_text = "".join(cf_chars)

    best_span: tuple[int, int] | None = None
    for term in terms_cf:
        if not term:
            continue
        pos = cf_text.find(term)
        if pos < 0:
            continue
        span = (cf_to_orig_start[pos], cf_to_orig_end[pos + len(term) - 1])
        # 前方の一致を優先し、開始位置が同じなら終了位置が最も後ろ（最長）の一致を選ぶ
        if (
            best_span is None
            or span[0] < best_span[0]
            or (span[0] == best_span[0] and span[1] > best_span[1])
        ):
            best_span = span
    return best_span


_UNSET_SPAN = object()


def _resolve_excerpt_span(
    best_win: WindowCandidate, terms_cf: Sequence[str]
) -> tuple[int, int] | None:
    """代表窓（窓内に収まらない場合は行全体）から一致範囲 (start, end) を 1 回だけ解決する。"""
    win_start = best_win.window_idx * WINDOW_STRIDE
    win_span = _find_best_casefold_span(best_win.window_text, terms_cf)
    if win_span is not None:
        return (win_start + win_span[0], win_start + win_span[1])
    return _find_best_casefold_span(best_win.line_text, terms_cf)


def _make_window_excerpt(
    best_win: WindowCandidate,
    terms_cf: Sequence[str],
    radius: int = EXCERPT_RADIUS,
    *,
    resolved_span: Any = _UNSET_SPAN,
) -> str:
    """一致窓（またはキャッシュ済みスパン）で検索範囲の前後 radius 文字を切り出す（マスク済みテキスト前提）。"""
    line_text = best_win.line_text
    win_text = best_win.window_text
    win_start = best_win.window_idx * WINDOW_STRIDE

    span = (
        _resolve_excerpt_span(best_win, terms_cf)
        if resolved_span is _UNSET_SPAN
        else resolved_span
    )
    if span is not None:
        match_start, match_end = span
        start = max(0, match_start - radius)
        end = min(len(line_text), match_end + radius)
    else:
        center = min(len(line_text), win_start + len(win_text) // 2)
        start = max(0, center - radius)
        end = min(len(line_text), center + radius)

    if start >= end and line_text:
        anchor = min(start if span is not None else min(len(line_text), win_start + len(win_text) // 2), len(line_text) - 1)
        start = max(0, anchor)
        end = min(len(line_text), start + 1)

    excerpt = line_text[start:end]
    prefix = "..." if start > 0 else ""
    suffix = "..." if end < len(line_text) else ""
    return f"{prefix}{excerpt}{suffix}"


def _next_smaller_radius(radius: int, floor_radius: int) -> int:
    if radius <= floor_radius:
        return floor_radius
    nxt = int(radius * 0.8)
    if nxt >= radius:
        nxt = radius - 1
    return max(floor_radius, nxt)


def _shrink_excerpt_to_budget(
    win: WindowCandidate,
    terms_cf: Sequence[str],
    target_tokens: float,
    *,
    floor_radius: int = MIN_EXCERPT_RADIUS,
    resolved_span: Any = _UNSET_SPAN,
) -> tuple[str, int, int]:
    """一致範囲を保ったまま割当トークン予算内に収まるまで外側余白を縮小する。"""
    span = (
        _resolve_excerpt_span(win, terms_cf)
        if resolved_span is _UNSET_SPAN
        else resolved_span
    )
    radius = EXCERPT_RADIUS
    ex = _make_window_excerpt(win, terms_cf, radius, resolved_span=span)
    tok = estimate_tokens(ex)
    while tok > target_tokens and radius > floor_radius:
        next_radius = _next_smaller_radius(radius, floor_radius)
        if next_radius == radius:
            break
        radius = next_radius
        ex = _make_window_excerpt(win, terms_cf, radius, resolved_span=span)
        tok = estimate_tokens(ex)
    return ex, tok, radius


def _truncate_head_tail(text: str, max_chars: int) -> str:
    cleaned = text.strip()
    if len(cleaned) <= max_chars:
        return cleaned
    marker = "\n...[省略]...\n"
    budget = max_chars - len(marker)
    if budget <= 20:
        return cleaned[:max_chars]
    head_len = max(1, int(budget * 0.6))
    tail_len = max(1, budget - head_len)
    return f"{cleaned[:head_len].rstrip()}{marker}{cleaned[-tail_len:].lstrip()}"


def _masked_turn_full_text(turn: TurnEntry) -> str:
    parts = [apply_mask(text) for _, text in turn.lines if text]
    return "\n".join(p for p in parts if p)


def select_and_restore_turns(
    scored_windows: list[WindowCandidate],
    turns_by_key: dict[str, list[TurnEntry]],
    terms_cf: Sequence[str],
    *,
    windows_by_key: dict[tuple[str, int], list[WindowCandidate]] | None = None,
    max_primary: int,
    max_turns: int,
    budget_tokens: int,
    warnings: list[str],
) -> tuple[list[SelectedTurn], bool, int]:
    """ターン単位で重複排除した代表窓から主ヒット枠を確保し、予算内で前後ターンを時系列復元する。"""
    if not scored_windows:
        return [], False, 0

    primary_limit = min(max_primary, max_turns, TOP_WINDOWS)
    primary_entries: list[tuple[TurnEntry, WindowCandidate, float]] = []
    seen_keys: set[tuple[str, int]] = set()
    for win in scored_windows:
        key_id = win.source_key or win.conv_id
        key = (key_id, win.turn_idx)
        if key in seen_keys:
            continue
        conv_turns = turns_by_key.get(key_id)
        if not conv_turns or win.turn_idx >= len(conv_turns):
            continue
        seen_keys.add(key)
        cand_wins = (windows_by_key or {}).get(key)
        best_excerpt_win = (
            max(cand_wins, key=lambda w: (w.term_hits, w.score))
            if cand_wins
            else win
        )
        primary_entries.append((conv_turns[win.turn_idx], best_excerpt_win, win.score))
        if len(primary_entries) >= primary_limit:
            break

    if not primary_entries:
        return [], False, 0

    # ステップ (b): 主ヒット全件の全文サイズを計測し、超過時は抜粋（必要に応じて半径縮小）へフォールバック
    full_texts = [_masked_turn_full_text(turn) for turn, _, _ in primary_entries]
    full_tokens = [estimate_tokens(txt) for txt in full_texts]
    fallback = False

    if sum(full_tokens) <= budget_tokens:
        selected: list[SelectedTurn] = [
            SelectedTurn(
                turn=turn,
                role="primary",
                rendered_text=txt,
                excerpted=False,
                tokens=tok,
                best_score=b_score,
                match_line_idx=ex_win.line_idx,
            )
            for (turn, ex_win, b_score), txt, tok in zip(primary_entries, full_texts, full_tokens)
        ]
    else:
        fallback = True
        per_cap = budget_tokens / len(primary_entries)
        resolved_spans = [
            _resolve_excerpt_span(ex_win, terms_cf) for _, ex_win, _ in primary_entries
        ]
        # state: [text, is_excerpt, tokens, radius]
        rendered_states: list[list[Any]] = []
        for idx, ((turn, ex_win, _), txt, tok) in enumerate(
            zip(primary_entries, full_texts, full_tokens)
        ):
            if tok > per_cap:
                ex, ex_tok, rad = _shrink_excerpt_to_budget(
                    ex_win, terms_cf, per_cap, resolved_span=resolved_spans[idx]
                )
                rendered_states.append([ex, True, ex_tok, rad])
            else:
                rendered_states.append([txt, False, tok, EXCERPT_RADIUS])

        if sum(st[2] for st in rendered_states) > budget_tokens:
            rendered_states = []
            for idx, (_, ex_win, _) in enumerate(primary_entries):
                ex, ex_tok, rad = _shrink_excerpt_to_budget(
                    ex_win, terms_cf, per_cap, resolved_span=resolved_spans[idx]
                )
                rendered_states.append([ex, True, ex_tok, rad])

        # 均等割当後も超過する場合は、第1段として MIN_EXCERPT_RADIUS まで、
        # なお超過する場合は第2段として外側余白 0 まで最大トークン抜粋から順に縮小する
        for floor_rad in (MIN_EXCERPT_RADIUS, 0):
            while sum(st[2] for st in rendered_states) > budget_tokens:
                shrinkable = [
                    idx
                    for idx, st in enumerate(rendered_states)
                    if st[3] > floor_rad
                ]
                if not shrinkable:
                    break
                target_idx = max(shrinkable, key=lambda idx: (rendered_states[idx][2], rendered_states[idx][3]))
                cur_rad = rendered_states[target_idx][3]
                new_rad = _next_smaller_radius(cur_rad, floor_rad)
                if new_rad == cur_rad:
                    break
                _, ex_win, _ = primary_entries[target_idx]
                new_ex = _make_window_excerpt(
                    ex_win, terms_cf, new_rad, resolved_span=resolved_spans[target_idx]
                )
                rendered_states[target_idx] = [
                    new_ex,
                    True,
                    estimate_tokens(new_ex),
                    new_rad,
                ]

        selected = [
            SelectedTurn(
                turn=turn,
                role="primary",
                rendered_text=st[0],
                excerpted=st[1],
                tokens=st[2],
                best_score=b_score,
                match_line_idx=ex_win.line_idx,
            )
            for (turn, ex_win, b_score), st in zip(primary_entries, rendered_states)
        ]
        if sum(s.tokens for s in selected) > budget_tokens:
            warnings.append(
                f"主ヒット件数と一致範囲の保持を優先したため予算 {budget_tokens} トークンを超過しました"
            )

    used_tokens = sum(s.tokens for s in selected)

    # ステップ (c): 残余予算で前後 ±1 因果ターンを展開
    if used_tokens < budget_tokens and len(selected) < max_turns:
        for turn, _, _ in primary_entries:
            if len(selected) >= max_turns or used_tokens >= budget_tokens:
                break
            if not turn.can_expand_context:
                continue
            turn_key_id = turn.source_key or turn.conv_id
            conv_turns = turns_by_key.get(turn_key_id, [])

            neighbors: list[TurnEntry] = []
            for direction in (-1, 1):
                pos = turn.turn_idx + direction
                while 0 <= pos < len(conv_turns):
                    cand = conv_turns[pos]
                    if cand.lines and any(t.strip() for _, t in cand.lines):
                        neighbors.append(cand)
                        break
                    pos += direction

            for nb in neighbors:
                if len(selected) >= max_turns or used_tokens >= budget_tokens:
                    break
                nb_key = (nb.source_key or nb.conv_id, nb.turn_idx)
                if nb_key in seen_keys:
                    continue
                nb_full = _masked_turn_full_text(nb)
                if not nb_full.strip():
                    continue
                nb_tok = estimate_tokens(nb_full)
                if used_tokens + nb_tok <= budget_tokens:
                    seen_keys.add(nb_key)
                    selected.append(
                        SelectedTurn(
                            turn=nb,
                            role="context",
                            rendered_text=nb_full,
                            excerpted=False,
                            tokens=nb_tok,
                            best_score=0.0,
                            match_line_idx=None,
                        )
                    )
                    used_tokens += nb_tok
                else:
                    nb_ex = _truncate_head_tail(nb_full, CONTEXT_EXCERPT_CHARS)
                    nb_ex_tok = estimate_tokens(nb_ex)
                    if used_tokens + nb_ex_tok <= budget_tokens:
                        seen_keys.add(nb_key)
                        selected.append(
                            SelectedTurn(
                                turn=nb,
                                role="context",
                                rendered_text=nb_ex,
                                excerpted=True,
                                tokens=nb_ex_tok,
                                best_score=0.0,
                                match_line_idx=None,
                            )
                        )
                        used_tokens += nb_ex_tok

    # ステップ (d): UTC 正規化時刻の昇順 (_utc_sort_key(created_at), conv_id, first_line_idx)
    selected.sort(
        key=lambda s: (_utc_sort_key(s.turn.created_at), s.turn.conv_id, s.turn.first_line_idx)
    )
    return selected, fallback, used_tokens


def _safe_fence(text: str) -> str:
    max_run = 0
    for m in BACKTICK_RUN_RE.finditer(text):
        if len(m.group(0)) > max_run:
            max_run = len(m.group(0))
    return "`" * max(3, max_run + 1)


def _format_turn_heading(item: SelectedTurn) -> str:
    turn = item.turn
    tag = "PRIMARY" if item.role == "primary" else "CONTEXT"
    ex_note = " excerpt" if item.excerpted else ""
    if turn.source_kind in ("repo_doc", "git_commit"):
        safe_label = apply_mask(turn.label or turn.conv_id)
        return (
            f"### [{tag}{ex_note}] {safe_label} "
            f"({turn.created_at or 'unknown'})"
        )
    if turn.source_kind == "artifact":
        file_label = apply_mask(turn.label or turn.conv_id)
        return (
            f"### [{tag}{ex_note}] artifact `{turn.conv_id}` "
            f"({file_label}, {turn.created_at or 'unknown'}) "
            f"[session](conversation://{turn.conv_id})"
        )
    step_str = f"step={turn.step_index}" if turn.step_index >= 0 else "doc"
    match_str = (
        f", match L{item.match_line_idx}"
        if item.match_line_idx is not None and item.match_line_idx != turn.first_line_idx
        else ""
    )
    return (
        f"### [{tag}{ex_note}] `{turn.conv_id}` L{turn.first_line_idx} "
        f"({step_str}{match_str}, {turn.source_kind}, {turn.created_at or 'unknown'}) "
        f"[session](conversation://{turn.conv_id})"
    )


def render_markdown(
    *,
    terms: Sequence[str],
    elapsed_ms: float,
    candidate_count: int,
    matched_count: int,
    window_count: int,
    selected: Sequence[SelectedTurn],
    fallback: bool,
    total_tokens: int,
    used_rg: bool,
    warnings: Sequence[str],
    stats_only: bool,
) -> str:
    masked_terms = [apply_mask(t) for t in terms]
    lines: list[str] = [
        "# Session Log Search Results",
        "",
        f"- 検索語: {', '.join(f'`{t}`' for t in masked_terms)}",
        f"- 走査経路: {'ripgrep (-l) + Python BM25' if used_rg else 'Python ストリーミング + BM25'}",
        f"- 経過時間: {elapsed_ms:.1f} ms",
        f"- 対象ソース数: {candidate_count} / ヒットソース数: {matched_count} / 評価窓数: {window_count}",
        f"- 復元ターン数: {len(selected)} / 推定トークン数: {total_tokens} / fallback: {str(fallback).lower()}",
    ]
    primary_short_ids = [
        s.turn.conv_id[:8] for s in selected if s.role == "primary"
    ]
    lines.append(
        f"- 主ヒット先頭 ID: {', '.join(primary_short_ids) if primary_short_ids else '(なし)'}"
    )
    if warnings:
        lines.append("- 警告:")
        for w in warnings:
            lines.append(f"  - {apply_mask(w)}")

    if stats_only:
        return "\n".join(lines)

    lines.append("")
    if not selected:
        lines.append("一致する履歴は 0 件でした。")
        return "\n".join(lines)

    for item in selected:
        lines.append(_format_turn_heading(item))
        fence = _safe_fence(item.rendered_text)
        lines.append(f"{fence}text")
        lines.append(item.rendered_text)
        lines.append(fence)
        lines.append("")

    return "\n".join(lines).rstrip()


def render_json(
    *,
    terms: Sequence[str],
    elapsed_ms: float,
    candidate_count: int,
    matched_count: int,
    window_count: int,
    selected: Sequence[SelectedTurn],
    fallback: bool,
    total_tokens: int,
    used_rg: bool,
    warnings: Sequence[str],
    stats_only: bool,
) -> str:
    masked_terms = [apply_mask(t) for t in terms]
    payload: dict[str, Any] = {
        "terms": masked_terms,
        "used_rg": used_rg,
        "elapsed_ms": round(elapsed_ms, 2),
        "candidate_sources": candidate_count,
        "matched_sources": matched_count,
        "evaluated_windows": window_count,
        "restored_turns": len(selected),
        "estimated_tokens": total_tokens,
        "fallback": fallback,
        "primary_conv_ids_short": [
            s.turn.conv_id[:8] for s in selected if s.role == "primary"
        ],
        "warnings": [apply_mask(w) for w in warnings],
    }
    if not stats_only:
        payload["results"] = [
            {
                "conv_id": s.turn.conv_id,
                "source_key": s.turn.source_key or s.turn.conv_id,
                "turn_idx": s.turn.turn_idx,
                "source_kind": s.turn.source_kind,
                "created_at": s.turn.created_at,
                "line_idx": s.turn.first_line_idx,
                "match_line_idx": s.match_line_idx,
                "step_index": s.turn.step_index,
                "label": apply_mask(s.turn.label),
                "role": s.role,
                "excerpted": s.excerpted,
                "tokens": s.tokens,
                "score": round(s.best_score, 4),
                "text": s.rendered_text,
            }
            for s in selected
        ]
    return json.dumps(payload, ensure_ascii=False, indent=2)


def run_search(
    *,
    terms: Sequence[str],
    app_data_dir: Path,
    conversation_ids: Sequence[str] = (),
    exclude_conversation_ids: Sequence[str] = (),
    repo_path: Path | None = None,
    since: str | None = None,
    max_primary: int = DEFAULT_MAX_PRIMARY,
    max_turns: int = DEFAULT_MAX_TURNS,
    budget_tokens: int = DEFAULT_BUDGET_TOKENS,
    include_thinking: bool = False,
    no_rg: bool = False,
) -> dict[str, Any]:
    """検索パイプライン全体を実行し、結果辞書を返す。"""
    t0 = time.perf_counter()
    warnings: list[str] = []
    sources = enumerate_sources(
        app_data_dir,
        conversation_ids=conversation_ids,
        exclude_conversation_ids=exclude_conversation_ids,
        repo_path=repo_path,
        since=since,
        warnings=warnings,
    )

    file_sources = [s for s in sources if s.path is not None]
    mem_sources = [s for s in sources if s.path is None]

    used_rg = False
    if file_sources:
        file_paths = [s.path for s in file_sources if s.path is not None]
        if not no_rg:
            rg_matched, used_rg = prefilter_with_rg(file_paths, terms, warnings)
            if rg_matched is None:
                matched_paths = prefilter_python(file_paths, terms)
                used_rg = False
            else:
                matched_paths = rg_matched
        else:
            matched_paths = prefilter_python(file_paths, terms)
    else:
        matched_paths = set()

    terms_cf = [t.casefold() for t in terms if t]
    candidate_sources: list[SourceSpec] = []
    for spec in file_sources:
        if spec.path is not None:
            norm = os.path.normcase(os.path.abspath(str(spec.path)))
            if norm in matched_paths:
                candidate_sources.append(spec)
    for spec in mem_sources:
        cf = spec.raw_text.casefold()
        if any(t in cf for t in terms_cf):
            candidate_sources.append(spec)

    turns_by_key: dict[str, list[TurnEntry]] = {}
    windows_by_key: dict[tuple[str, int], list[WindowCandidate]] = defaultdict(list)
    all_windows: list[WindowCandidate] = []

    for spec in candidate_sources:
        if spec.kind == "transcript" and spec.path is not None:
            turns = load_transcript_turns(
                spec.path,
                spec.conv_id,
                include_thinking=include_thinking,
                terms_cf=terms_cf,
                warnings=warnings,
            )
            key_id = spec.conv_id
        else:
            turns = load_document_turn(spec, warnings)
            # transcript と重複しないよう source_key で隔離しつつ conv_id は実 ID を保つ
            key_id = spec.source_id
        if not turns:
            continue
        for t in turns:
            t.source_key = key_id
        turns_by_key[key_id] = turns

        for turn in turns:
            for l_idx, raw_line_text in turn.lines:
                if not raw_line_text:
                    continue
                if not any(t in raw_line_text.casefold() for t in terms_cf):
                    continue
                # 窓分割・スコア計算・抜粋抽出のすべてに先立ち必ずシークレットをマスクする
                masked_line = apply_mask(raw_line_text)
                for w_idx, w_text in enumerate(split_windows(masked_line)):
                    w_toks = tokenize(w_text)
                    if not w_toks:
                        continue
                    win_cand = WindowCandidate(
                        conv_id=turn.conv_id,
                        turn_idx=turn.turn_idx,
                        line_idx=l_idx,
                        window_idx=w_idx,
                        line_text=masked_line,
                        window_text=w_text,
                        created_at=turn.created_at,
                        tokens=w_toks,
                        source_key=key_id,
                    )
                    all_windows.append(win_cand)
                    windows_by_key[(key_id, turn.turn_idx)].append(win_cand)

    scored_windows = score_windows_bm25(all_windows, terms)
    selected, fallback, total_tokens = select_and_restore_turns(
        scored_windows,
        turns_by_key,
        terms_cf,
        windows_by_key=windows_by_key,
        max_primary=max_primary,
        max_turns=max_turns,
        budget_tokens=budget_tokens,
        warnings=warnings,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    return {
        "terms": list(terms),
        "elapsed_ms": elapsed_ms,
        "candidate_count": len(sources),
        "matched_count": len(candidate_sources),
        "window_count": len(all_windows),
        "selected": selected,
        "fallback": fallback,
        "total_tokens": total_tokens,
        "used_rg": used_rg,
        "warnings": warnings,
    }


def _bounded_int(min_val: int, max_val: int | None = None):
    def _parse(raw: str) -> int:
        val = int(raw)
        if val < min_val or (max_val is not None and val > max_val):
            upper = str(max_val) if max_val is not None else "∞"
            raise argparse.ArgumentTypeError(
                f"{min_val}〜{upper} の範囲で指定してください: {raw}"
            )
        return val

    return _parse


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="過去の Antigravity セッションログとアーティファクトを高速検索する"
    )
    parser.add_argument(
        "terms",
        nargs="+",
        help="検索語（1〜12 個。ハイフン始まりの語は -- の後ろに指定）",
    )
    parser.add_argument(
        "--app-data-dir",
        default=str(Path.home() / ".gemini" / "antigravity"),
        help="Antigravity の App Data Directory（既定: ~/.gemini/antigravity）",
    )
    parser.add_argument(
        "--conversation-id",
        action="append",
        default=[],
        help="検索対象に含める conversation ID（複数指定可）",
    )
    parser.add_argument(
        "--exclude-conversation-id",
        action="append",
        default=[],
        help="検索対象から除外する conversation ID（複数指定可）",
    )
    parser.add_argument(
        "--repo",
        default=None,
        help="docs/*.md と git log を検索対象に含めるリポジトリパス",
    )
    parser.add_argument(
        "--since",
        default=None,
        help="対象ファイルの更新日時下限 (YYYY-MM-DD)",
    )
    parser.add_argument(
        "--max-primary",
        type=_bounded_int(1, MAX_PRIMARY_UPPER),
        default=DEFAULT_MAX_PRIMARY,
        help=f"主ヒットの最大確保ターン数（1〜{MAX_PRIMARY_UPPER}、既定: {DEFAULT_MAX_PRIMARY}）",
    )
    parser.add_argument(
        "--max-turns",
        type=_bounded_int(1),
        default=DEFAULT_MAX_TURNS,
        help=f"復元する合計最大ターン数（既定: {DEFAULT_MAX_TURNS}）",
    )
    parser.add_argument(
        "--budget-tokens",
        type=_bounded_int(100),
        default=DEFAULT_BUDGET_TOKENS,
        help=f"出力の最大推定トークン予算（既定: {DEFAULT_BUDGET_TOKENS}）",
    )
    parser.add_argument(
        "--include-thinking",
        action="store_true",
        help="PLANNER_RESPONSE の thinking フィールドも索引対象に含める",
    )
    parser.add_argument(
        "--no-rg",
        action="store_true",
        help="ripgrep を使わず Python ストリーミング走査のみで事前フィルタする",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="出力形式（既定: markdown）",
    )
    parser.add_argument(
        "--stats-only",
        action="store_true",
        help="本文を出さず件数・経過時間・先頭 ID のみ出力する",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    decision_hygiene.configure_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    terms = [t for t in args.terms if t]
    if not terms or len(terms) > MAX_TERMS:
        print(
            f"エラー: 検索語は 1〜{MAX_TERMS} 個で指定してください（指定数: {len(terms)}）。",
            file=sys.stderr,
        )
        return 2

    app_data_dir = Path(args.app_data_dir).expanduser()
    repo_path = Path(args.repo).expanduser() if args.repo else None
    if repo_path is not None and not repo_path.is_dir():
        print(
            f"エラー: --repo ディレクトリが見つかりません: {repo_path}",
            file=sys.stderr,
        )
        return 2

    try:
        res = run_search(
            terms=terms,
            app_data_dir=app_data_dir,
            conversation_ids=args.conversation_id,
            exclude_conversation_ids=args.exclude_conversation_id,
            repo_path=repo_path,
            since=args.since,
            max_primary=args.max_primary,
            max_turns=args.max_turns,
            budget_tokens=args.budget_tokens,
            include_thinking=args.include_thinking,
            no_rg=args.no_rg,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"エラー: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(
            render_json(
                terms=res["terms"],
                elapsed_ms=res["elapsed_ms"],
                candidate_count=res["candidate_count"],
                matched_count=res["matched_count"],
                window_count=res["window_count"],
                selected=res["selected"],
                fallback=res["fallback"],
                total_tokens=res["total_tokens"],
                used_rg=res["used_rg"],
                warnings=res["warnings"],
                stats_only=args.stats_only,
            )
        )
    else:
        print(
            render_markdown(
                terms=res["terms"],
                elapsed_ms=res["elapsed_ms"],
                candidate_count=res["candidate_count"],
                matched_count=res["matched_count"],
                window_count=res["window_count"],
                selected=res["selected"],
                fallback=res["fallback"],
                total_tokens=res["total_tokens"],
                used_rg=res["used_rg"],
                warnings=res["warnings"],
                stats_only=args.stats_only,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
