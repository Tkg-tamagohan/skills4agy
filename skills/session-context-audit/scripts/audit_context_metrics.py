#!/usr/bin/env python3
"""Antigravity 過去セッションログ（transcript.jsonl）の効果測定・コンテキスト監査 CLI。

ローカルに蓄積された全セッションのトークン消費、キャッシュヒット率、
コンテキスト制御ルールの遵守状況、および品質非退行の代理指標を
Python 標準ライブラリのみで決定論的に集計する。
オプトイン（--classify-decision1）で Gemini Decision 1 を用いた
タスク種別層別・文脈不足兆候・完了状態のゼロ出力トークン一括分類を行える。
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
import sys
from typing import Any, Callable

_DECISIONS_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "gemini-decisions-api" / "scripts"
if str(_DECISIONS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_DECISIONS_SCRIPTS_DIR))

import decision_hygiene  # noqa: E402
import run_decisions  # noqa: E402

DEFAULT_APP_DATA_DIR = Path.home() / ".gemini" / "antigravity"
LARGE_LINE_THRESHOLD = 200
LARGE_CMD_OUTPUT_BYTES = 10_240
PARALLEL_READ_BURST_MIN = 4
LOW_SAMPLE_THRESHOLD = 5
DEFAULT_CHUNK_SIZE = 100
MAX_SESSIONS_PER_CHUNK = 200
DEFAULT_MAX_CHUNKS = 10
DEFAULT_MIN_CONFIDENCE = 0.70
DEFAULT_TASK_TYPE_MIN_CONFIDENCE = 0.70
MAX_CHARS_PER_CHUNK = 160_000
MAX_PAYLOAD_CHARS_PER_CHUNK = 280_000
MAX_BISECT_DEPTH = 2
MIN_BISECT_CHUNK = 10

SWARM_TOOLS: frozenset[str] = frozenset({"read_board", "post_message", "swarm_wait"})
EDIT_TOOLS: frozenset[str] = frozenset({"edit_file", "write_file"})
SUBAGENT_CLASSES: tuple[str, ...] = (
    "parent",
    "swarm_coordinator",
    "subagent",
    "swarm_worker",
    "orphan_or_empty",
)

EDIT_CATEGORY_ORDER: tuple[str, ...] = ("code", "test", "doc", "cfg")
CMD_CATEGORY_ORDER: tuple[str, ...] = ("test_run", "pr_gh", "git_write", "lint_check")

LOCK_BASENAMES: frozenset[str] = frozenset(
    {
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "cargo.lock",
        "poetry.lock",
        "uv.lock",
        "composer.lock",
        "gemfile.lock",
    }
)
LOCK_SUFFIXES: tuple[str, ...] = (".min.js", ".min.css", ".map", ".pb.go")

EXEMPT_BASENAMES: frozenset[str] = frozenset({"agents.md", "gemini.md", "skill.md"})
EXEMPT_SUFFIXES: tuple[str, ...] = (
    ".md",
    ".mdx",
    ".txt",
    ".rst",
    ".json",
    ".jsonc",
    ".toml",
    ".yaml",
    ".yml",
    ".xml",
    ".ini",
    ".cfg",
    ".conf",
    ".schema",
    ".env.example",
    ".env.sample",
    ".env.template",
)

DOC_EDIT_SUFFIXES: tuple[str, ...] = (".md", ".mdx", ".txt", ".rst", ".adoc")
CFG_EDIT_SUFFIXES: tuple[str, ...] = (
    ".json",
    ".jsonc",
    ".toml",
    ".yaml",
    ".yml",
    ".xml",
    ".ini",
    ".cfg",
    ".conf",
    ".schema",
    ".env.example",
    ".env.sample",
    ".env.template",
    ".properties",
    ".lock",
)
CFG_EDIT_BASENAMES: frozenset[str] = frozenset(
    {"dockerfile", "makefile", ".gitignore", ".editorconfig", ".eslintrc", ".prettierrc"}
)
TEST_DIR_NAMES: frozenset[str] = frozenset({"test", "tests", "__tests__", "spec", "specs", "e2e"})
TEST_FILE_RE = re.compile(
    r"(?:^test_.*|_test\.(?:py|go|rs)$|\.(?:test|spec)\.|_spec\.|tests?\.(?:py|ts|tsx|js|jsx|go|rs|java|kt|cs|rb|php|cpp|cc|c)$)"
)
URL_RE = re.compile(r"(?:https?|file)://\S+", re.IGNORECASE)
SLASH_CMD_WHITELIST: frozenset[str] = frozenset(
    {
        "/goal",
        "/compact",
        "/schedule",
        "/browser",
        "/plan",
        "/grill-me",
        "/teamwork",
        "/learn",
        "/boost",
        "/swarm",
        "/plugin",
        "/automation",
        "/handoff",
        "/review",
        "/audit",
        "/pr",
        "/commit",
    }
)
SLASH_CMD_RE = re.compile(
    r"(?:^|[\s「『（(【\[])(/[a-z][a-z0-9-]{1,20})(?=$|[\s」』）)】\].,。、!！?？:：])",
    re.IGNORECASE,
)
CMD_TEST_RUN_RE = re.compile(
    r"(?i)(?:^|[;&|(\s])(?:pytest|vitest|jest|mocha|rspec|phpunit|ctest)\b"
    r"|\bpython(?:3)?\s+-m\s+unittest\b|\brun_all_tests\.py\b"
    r"|\b(?:cargo|go|dotnet|mvn|gradle)\s+test\b"
    r"|\b(?:npm|pnpm|yarn|bun)(?:\.cmd)?\s+(?:run\s+)?test\b"
)
CMD_PR_GH_RE = re.compile(r"(?i)(?:^|[;&|(\s])gh\s+(?:pr|issue|api|review|run)\b")
CMD_GIT_WRITE_RE = re.compile(
    r"(?i)(?:^|[;&|(\s])git\s+(?:commit|push|merge|rebase|cherry-pick|revert|tag|am)\b"
)
CMD_LINT_CHECK_RE = re.compile(
    r"(?i)(?:^|[;&|(\s])(?:ruff|flake8|mypy|pyright|eslint|prettier|tsc|biome|golangci-lint|shellcheck)\b"
    r"|\b(?:slop_lint|check_plugin)\.py\b|\bnode\s+--check\b|\bpy_compile\b"
    r"|\bcargo\s+(?:check|clippy|fmt)\b"
    r"|\b(?:npm|pnpm|yarn|bun)(?:\.cmd)?\s+(?:run\s+)?(?:lint|typecheck|check|build)\b"
)
HANDOFF_PREAMBLE_RE = re.compile(
    r"^\s*(?:/[a-z][a-z0-9-]{1,20}\s+)*"
    r"(?:(?:以下|次)の(?:引き継ぎ|引継ぎ|ハンドオフ)(?:メモ|内容|情報)?を[^\n。.]*[。.\n]\s*"
    r"|対象外のファイル読み込み[^\n。.]*[。.\n]\s*"
    r"|不要な再調査[^\n。.]*[。.\n]\s*"
    r"|指定されたファイル範囲[^\n。.]*[。.\n]\s*"
    r"|Read the handoff[^\n.]*[.\n]\s*"
    r"|Continue from the handoff[^\n.]*[.\n]\s*)+",
    re.IGNORECASE,
)
HANDOFF_HEADER_RE = re.compile(r"(?im)^#+\s*Handoff\s*[:：]\s*")

TASK_TYPE_CRITERIA: dict[str, str] = {
    "review_or_audit": (
        "PR レビュー指摘のトリアージ・修正対応、コードやリポジトリの監査（repo-drift-audit）、"
        "不要テスト棚卸し（test-suite-pruning）が主目的の作業（監査・整理計画の策定やレビュー指摘修正の編集を含む。"
        "新機能実装や設計書作成の付随工程で /spec-cold-review・gh pr create・恒久ルール昇格を行う場合は含めない）"
    ),
    "research_or_plan": (
        "技術質問への回答（仕組み・挙動・設定方法・検証環境の問い合わせ）、調査、原因分析、要件定義、"
        "設計書・手順書・プロンプト・実装計画の作成が主目的の作業（edits=none または文書・計画のみの編集。"
        "付随して /spec-cold-review を使う場合も含む）"
    ),
    "feature_or_refactor": (
        "新機能・新規スキル・CI ワークフロー・コード署名・恒久ルールや検査機構の実装、仕様拡張、"
        "または複数ファイルのリファクタリング・構造移行が主目的の作業（タイブレーク目安：code/test の編集が 3 ファイル以上、"
        "または明確な機能追加・仕組み導入。付随して /spec-cold-review や PR 作成を行う場合も含む）"
    ),
    "bugfix_or_small_edit": (
        "既存コードのバグ修正、エラー・ブロッカー・テスト失敗の解消、設定や既存ルール文面の局所修正が主目的の作業"
        "（タイブレーク目安：code/test の編集が 1〜2 ファイル中心で、新機能導入やレビュー指摘トリアージに該当しない）"
    ),
    "other": (
        "進捗確認・進捗報告・作業状況の問い合わせ、ローカルブランチやワークツリーの整理、プロセス停止などの単発環境操作・雑務、"
        "または依頼内容が空で主目的が読み取れないもの（技術仕様や仕組みの質問は research_or_plan に分類する）"
    ),
}

OUTCOME_CRITERIA: dict[str, str] = {
    "completed": (
        "【最優先：[FINAL_ASSISTANT] 本文で完了・回答・報告・検証結果が示されている】依頼された実装、修正、調査、"
        "回答、または計画作成が区切りまで完了している（ended_with=assistant_text かつ未解決の停止・ユーザー回答待ちではない。"
        "任意の補足提案や次ステップ案の併記だけでは未完了にしない）"
    ),
    "partial_or_blocked": (
        "【途中停止・未完了・回答待ち】[FINAL_ASSISTANT] 本文に未完了・中断・エラー未解決・ブロック・ユーザー確認や選択待ちが"
        "明示されている、または ended_with が no_assistant_response / tool_error / ask_question_tool / tool_only である、"
        "あるいは trailing_q=1 で処理続行のための確認質問で終わっている"
    ),
    "other": "完了とも未完了とも分類できない特殊な状態（空セッションや非定型ログで判断材料が一切ない場合のみ）",
}

SHOWING_LINES_RE = re.compile(r"Showing lines (\d+)-(\d+) of (\d+)")
SEARCH_CMD_RE = re.compile(r"(?i)(?:^|[;&|(\s])(?:rg|git\s+grep|select-string)\b")
PIPE_TRUNCATE_RE = re.compile(
    r"(?i)(?:\b(?:select-object|select)\b[^|;&]*\s-first\b|\|\s*head\b)"
)
NONZERO_EXIT_RE = re.compile(r"Command exited with code ([1-9]\d*)")
USER_REQUEST_RE = re.compile(r"<USER_REQUEST>(.*?)</USER_REQUEST>", re.DOTALL)
TRUNCATED_MARKER_RE = re.compile(r"<truncated\s+\d+\s+bytes>", re.IGNORECASE)
ORPHAN_META_CLOSE_TAGS: tuple[tuple[str, str], ...] = (
    ("</ADDITIONAL_METADATA>", "<ADDITIONAL_METADATA>"),
    ("</ORCHESTRATOR>", "<ORCHESTRATOR>"),
    ("</PLAN>", "<PLAN>"),
    ("</USER_SETTINGS_CHANGE>", "<USER_SETTINGS_CHANGE>"),
)
STRIP_TAG_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<ADDITIONAL_METADATA>.*?</ADDITIONAL_METADATA>", re.DOTALL),
    re.compile(r"<USER_SETTINGS_CHANGE>.*?</USER_SETTINGS_CHANGE>", re.DOTALL),
    re.compile(r"<PLAN>.*?</PLAN>", re.DOTALL),
    re.compile(r"<ORCHESTRATOR>.*?</ORCHESTRATOR>", re.DOTALL),
)
FILE_URI_RE = re.compile(r"file:///[^\s\"'`<>)\]]+", re.IGNORECASE)
WIN_ABS_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"'`<>|]+")
POSIX_ABS_PATH_RE = re.compile(r"(?<![A-Za-z0-9:/])/(?:Users|home|var|etc|tmp|opt)/[^\s\"'`<>]+")


@dataclass
class SessionMetrics:
    """1 セッション分の決定論的解析結果と適応型ダイジェスト素材。"""

    session_id: str
    session_class: str
    primary_model: str
    first_created_at: datetime | None
    last_created_at: datetime | None
    has_edits: bool
    planner_turns: int
    total_input_tokens: int
    total_cache_read_tokens: int
    total_output_tokens: int
    valid_token_steps: int
    peak_context_tokens: int | None
    pre_edit_context_tokens: int | None
    pre_edit_new_input_tokens: int | None
    turns_to_first_edit: int | None
    seconds_to_first_edit: float | None
    read_file_calls: int
    code_read_calls: int
    large_code_reads: int
    blind_large_code_reads: int
    large_exempt_reads: int
    blind_large_exempt_reads: int
    large_lock_reads: int
    blind_large_lock_reads: int
    oversized_range_reads: int
    redundant_rereads: int
    parallel_read_burst_turns: int
    parallel_read_burst_all_turns: int
    search_before_read: bool | None
    run_command_calls: int
    large_cmd_outputs: int
    cmd_errors: int
    pipe_truncate_violations: int
    pipe_truncate_errors: int
    edit_file_calls: int
    edit_errors: int
    subagent_spawns: int
    subagent_types: Counter[str] = field(default_factory=Counter)
    checkpoint_count: int = 0
    malformed_lines: int = 0
    unpaired_tool_calls: int = 0
    full_lookup_misses: int = 0
    first_user_excerpt: str = ""
    last_turn_excerpt: str = ""
    mid_anomaly_excerpt: str = ""
    user_input_count: int = 0
    last_user_excerpt: str = ""
    final_assistant_excerpt: str = ""
    edit_file_counts: dict[str, int] = field(default_factory=dict)
    ended_with: str = "no_assistant_response"
    trailing_q: bool = False
    slash_commands: list[str] = field(default_factory=list)
    cmd_categories: list[str] = field(default_factory=list)
    subagent_type: str | None = None

    @property
    def cache_hit_rate(self) -> float | None:
        denom = self.total_input_tokens + self.total_cache_read_tokens
        if denom <= 0:
            return None
        return self.total_cache_read_tokens / denom

    @property
    def blind_large_code_read_rate(self) -> float | None:
        if self.large_code_reads <= 0:
            return None
        return self.blind_large_code_reads / self.large_code_reads

    @property
    def large_cmd_output_rate(self) -> float | None:
        if self.run_command_calls <= 0:
            return None
        return self.large_cmd_outputs / self.run_command_calls

    @property
    def edit_error_rate(self) -> float | None:
        if self.edit_file_calls <= 0:
            return None
        return self.edit_errors / self.edit_file_calls

    @property
    def cmd_error_rate(self) -> float | None:
        if self.run_command_calls <= 0:
            return None
        return self.cmd_errors / self.run_command_calls


def parse_iso_datetime(value: str) -> datetime:
    """タイムゾーン付き ISO 8601 文字列を UTC datetime へ変換する。"""
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        raise ValueError(f"タイムゾーン指定が必要です: {value}")
    return dt.astimezone(timezone.utc)


def try_parse_datetime(value: Any) -> datetime | None:
    """ログ中の created_at 文字列を安全に UTC datetime へ変換する。"""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def decode_tool_arg(value: Any) -> Any:
    """JSON エンコード済み文字列として格納されたツール引数を安全にデコードする。"""
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    if not stripped:
        return value
    if (stripped[0] == '"' and stripped[-1] == '"') or stripped[0] in ("{", "[", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "-", "t", "f", "n"):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            return value
    return value


def parse_optional_int(value: Any) -> int | None:
    """ツール引数（StartLine / EndLine 等）を整数へ変換する。"""
    decoded = decode_tool_arg(value)
    if decoded is None or decoded == "" or isinstance(decoded, bool):
        return None
    if isinstance(decoded, (int, float)):
        return int(decoded)
    if isinstance(decoded, str):
        try:
            return int(decoded.strip())
        except ValueError:
            return None
    return None


def normalize_file_path(path_value: Any) -> str:
    """比較・重複判定向けにファイルパスを小文字・スラッシュ統一へ正規化する。"""
    decoded = decode_tool_arg(path_value)
    text = str(decoded or "").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ('"', "'"):
        text = text[1:-1]
    text = text.replace("\\", "/").lower()
    text = re.sub(r"/+", "/", text)
    if text.startswith("./"):
        text = text[2:]
    return text


def classify_file_path(path_value: Any) -> str:
    """ファイルを lock_or_generated / exempt_doc_config / code の 3 区分へ分類する。"""
    norm = normalize_file_path(path_value)
    basename = norm.rsplit("/", 1)[-1]
    if (
        basename in LOCK_BASENAMES
        or basename.endswith(LOCK_SUFFIXES)
        or ".generated." in basename
    ):
        return "lock_or_generated"
    if (
        basename in EXEMPT_BASENAMES
        or basename.startswith(("readme", "license"))
        or basename.endswith(EXEMPT_SUFFIXES)
    ):
        return "exempt_doc_config"
    return "code"


def classify_edit_file_category(path_value: Any) -> str:
    """編集対象ファイルを doc / cfg / test / code の 4 区分へ分類する。"""
    norm = normalize_file_path(path_value)
    parts = [p for p in norm.split("/") if p]
    basename = parts[-1] if parts else ""
    if basename.endswith(DOC_EDIT_SUFFIXES):
        return "doc"
    if basename in CFG_EDIT_BASENAMES or basename.endswith(CFG_EDIT_SUFFIXES):
        return "cfg"
    if any(p in TEST_DIR_NAMES for p in parts[:-1]) or bool(TEST_FILE_RE.search(basename)):
        return "test"
    return "code"


def extract_slash_commands(text: str, existing: list[str], *, limit: int = 3) -> None:
    """ユーザー発話からホワイトリスト該当のスラッシュコマンドを出現順ユニークで抽出する。"""
    if len(existing) >= limit or not text:
        return
    for match in SLASH_CMD_RE.finditer(text):
        cmd = match.group(1).lower()
        if cmd in SLASH_CMD_WHITELIST and cmd not in existing:
            existing.append(cmd)
            if len(existing) >= limit:
                break


def detect_cmd_categories(cmd_str: str) -> set[str]:
    """run_command のコマンドライン文字列から行動カテゴリ集合を判定する。"""
    if not cmd_str:
        return set()
    cats: set[str] = set()
    if CMD_TEST_RUN_RE.search(cmd_str):
        cats.add("test_run")
    if CMD_PR_GH_RE.search(cmd_str):
        cats.add("pr_gh")
    if CMD_GIT_WRITE_RE.search(cmd_str):
        cats.add("git_write")
    if CMD_LINT_CHECK_RE.search(cmd_str):
        cats.add("lint_check")
    return cats


def has_trailing_question(text: str) -> bool:
    """URL を除外した末尾 80 文字以内に疑問符が含まれるかを返す。"""
    if not text or not text.strip():
        return False
    cleaned = URL_RE.sub("", text).strip()
    if not cleaned:
        return False
    tail = cleaned[-80:]
    return "?" in tail or "？" in tail


def strip_handoff_boilerplate(text: str) -> str:
    """引き継ぎプロンプト先頭の定型前置き文と Handoff 見出し記号を除去する。"""
    if not text or not text.strip():
        return text
    stripped = HANDOFF_PREAMBLE_RE.sub("", text).strip()
    stripped = HANDOFF_HEADER_RE.sub("", stripped).strip()
    return stripped if stripped else text


def _strip_system_tags(text: str) -> str:
    cleaned = text
    for pattern in STRIP_TAG_PATTERNS:
        cleaned = pattern.sub("", cleaned)
    return re.sub(r"</?USER_REQUEST>", "", cleaned).strip()


def extract_user_text(content: str) -> str:
    """USER_INPUT 本文から定型メタデータタグと切り詰め由来の孤立閉じタグを除いた依頼テキストを抽出する。"""
    match = USER_REQUEST_RE.search(content)
    if match:
        cleaned = _strip_system_tags(match.group(1))
        if cleaned:
            return cleaned
        fallback = _strip_system_tags(content)
        if fallback:
            return fallback
        return match.group(1).strip()

    if "<USER_REQUEST>" in content and "</USER_REQUEST>" not in content:
        for m_trunc in reversed(list(TRUNCATED_MARKER_RE.finditer(content))):
            before_trunc = content[: m_trunc.start()]
            after_trunc = content[m_trunc.end() :]
            if any(
                close_tag in after_trunc and open_tag not in after_trunc and open_tag not in before_trunc
                for close_tag, open_tag in ORPHAN_META_CLOSE_TAGS
            ):
                candidate = _strip_system_tags(before_trunc)
                if candidate:
                    return candidate
                break

    cleaned = _strip_system_tags(content)
    return cleaned if cleaned else content.strip()


def validate_confidence_value(value: float, flag_name: str) -> None:
    """信頼度閾値が 0.0〜1.0 の有限値であるか検証する。"""
    if not math.isfinite(value) or not (0.0 <= value <= 1.0):
        raise ValueError(f"{flag_name} は 0.0〜1.0 の有限な数値で指定してください。")


def resolve_confidence_thresholds(
    min_confidence: float | None,
    task_type_min_confidence: float | None,
) -> tuple[float, float]:
    """--min-confidence と --task-type-min-confidence の優先規則（案 B）を解決する。"""
    if min_confidence is not None:
        validate_confidence_value(min_confidence, "--min-confidence")
    if task_type_min_confidence is not None:
        validate_confidence_value(task_type_min_confidence, "--task-type-min-confidence")

    eff_min = DEFAULT_MIN_CONFIDENCE if min_confidence is None else min_confidence
    if task_type_min_confidence is not None:
        eff_tt = task_type_min_confidence
    elif min_confidence is not None:
        eff_tt = min_confidence
    else:
        eff_tt = DEFAULT_TASK_TYPE_MIN_CONFIDENCE
    return eff_min, eff_tt


def sanitize_digest_text(
    text: str,
    max_chars: int | None = None,
    *,
    mode: str = "head",
) -> tuple[str, int]:
    """全文を先にマスク・エスケープしてから指定文字数・モードで丸める。"""
    collapsed = re.sub(r"\s+", " ", text).strip()
    masked = decision_hygiene.mask_secrets(
        collapsed,
        extra_patterns=(decision_hygiene.BEARER_TOKEN_RE,),
    )
    redactions = masked.count("[REDACTED]") - collapsed.count("[REDACTED]")
    masked = FILE_URI_RE.sub("[PATH]", masked)
    masked = WIN_ABS_PATH_RE.sub("[PATH]", masked)
    masked = POSIX_ABS_PATH_RE.sub("[PATH]", masked)
    masked = masked.replace("</SESSION", "<\\/SESSION")
    if max_chars is not None and len(masked) > max_chars:
        if mode == "tail":
            keep = max(1, max_chars - 3)
            masked = "..." + masked[-keep:].lstrip()
        elif mode == "head_tail":
            sep = " ... "
            avail = max_chars - len(sep)
            if avail >= 4:
                head_len = max(1, int(avail * 0.65))
                tail_len = max(1, avail - head_len)
                masked = masked[:head_len].rstrip() + sep + masked[-tail_len:].lstrip()
            else:
                masked = masked[: max(1, max_chars - 3)].rstrip() + "..."
        else:
            masked = masked[: max(1, max_chars - 3)].rstrip() + "..."
    return masked, max(0, redactions)


def collect_subagent_types(brain_dir: Path) -> dict[str, str]:
    """全親セッションの .system_generated/subagents/*.json から子セッション ID → 種別名マップを収集する。"""
    sub_types: dict[str, str] = {}
    for json_path in brain_dir.glob("*/.system_generated/subagents/*.json"):
        type_name = "unknown"
        cid_val: str | None = None
        try:
            data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            data = None
        if isinstance(data, dict):
            cid = data.get("conversationId")
            if isinstance(cid, str) and cid.strip():
                cid_val = cid.strip()
            desc = data.get("subagentDescriptor")
            if isinstance(desc, dict):
                raw_t = desc.get("typeName")
                if isinstance(raw_t, str) and raw_t.strip():
                    type_name = raw_t.strip()
        sub_types[json_path.stem] = type_name
        if cid_val:
            sub_types[cid_val] = type_name
    return sub_types


def collect_subagent_ids(brain_dir: Path) -> set[str]:
    """全親セッションの .system_generated/subagents/*.json から子セッション ID 集合を収集する。"""
    sub_ids: set[str] = set()
    for json_path in brain_dir.glob("*/.system_generated/subagents/*.json"):
        sub_ids.add(json_path.stem)
        try:
            data = json.loads(json_path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict):
            cid = data.get("conversationId")
            if isinstance(cid, str) and cid.strip():
                sub_ids.add(cid.strip())
    return sub_ids


def discover_session_transcripts(app_data_dir: Path) -> tuple[list[tuple[str, Path]], set[str]]:
    """brain 配下の (session_id, transcript_path) 一覧と子セッション ID 集合を返す。"""
    brain_dir = app_data_dir / "brain"
    if not app_data_dir.is_dir() or not brain_dir.is_dir():
        raise FileNotFoundError(f"対象ディレクトリが見つかりません: {brain_dir}")
    sub_ids = collect_subagent_ids(brain_dir)
    sessions: list[tuple[str, Path]] = []
    for entry in sorted(brain_dir.iterdir(), key=lambda p: p.name):
        if not entry.is_dir():
            continue
        t_path = entry / ".system_generated" / "logs" / "transcript.jsonl"
        if t_path.is_file():
            sessions.append((entry.name, t_path))
    return sessions, sub_ids


def _lookup_full_command_sizes(
    full_path: Path,
    pending: dict[int, tuple[int, int]],
) -> tuple[dict[int, int], int]:
    """transcript_full.jsonl を 1 パス走査し、対象行だけの実 UTF-8 バイト数を返す。"""
    resolved: dict[int, int] = {}
    if not pending:
        return resolved, 0
    if not full_path.is_file():
        return {cmd_idx: fb for cmd_idx, fb in pending.values()}, len(pending)

    target_lines = set(pending.keys())
    max_line = max(target_lines)
    try:
        with full_path.open("r", encoding="utf-8", errors="replace") as fh:
            for idx, line in enumerate(fh):
                if idx > max_line:
                    break
                if idx not in target_lines:
                    continue
                cmd_idx, fallback_bytes = pending[idx]
                try:
                    obj = json.loads(line)
                    content = obj.get("content")
                    resolved[cmd_idx] = len((content if isinstance(content, str) else "").encode("utf-8"))
                except json.JSONDecodeError:
                    resolved[cmd_idx] = fallback_bytes
    except OSError:
        return {cmd_idx: fb for cmd_idx, fb in pending.values()}, len(pending)

    misses = 0
    for line_idx, (cmd_idx, fallback_bytes) in pending.items():
        if cmd_idx not in resolved:
            resolved[cmd_idx] = fallback_bytes
            misses += 1
    return resolved, misses


def _has_redundant_reread(
    seen_ranges: list[tuple[int, int]],
    r_start: int,
    r_end: int,
) -> bool:
    """既読範囲との実質重複がある再読を判定する。"""
    for prev_s, prev_e in seen_ranges:
        if max(prev_s, r_start) <= min(prev_e, r_end):
            return True
    return False


def _choose_primary_model(
    model_counts: Counter[str],
    model_input_tokens: Counter[str],
) -> str:
    """最頻出モデル（同数時は総入力トークン最大）を代表モデルとして返す。"""
    if not model_counts:
        return "unknown"
    return max(
        model_counts.keys(),
        key=lambda m: (model_counts[m], model_input_tokens[m], m),
    )


def analyze_session(
    session_id: str,
    transcript_path: Path,
    *,
    is_subagent: bool,
    subagent_type: str | None = None,
    lookup_full: bool = True,
) -> SessionMetrics:
    """1 セッションの transcript.jsonl を 1 パスストリーミング解析する。"""
    malformed_lines = 0
    unpaired_tool_calls = 0
    user_input_count = 0
    has_swarm_tool = False
    first_dt: datetime | None = None
    last_dt: datetime | None = None

    planner_turns = 0
    total_input_tokens = 0
    total_cache_read_tokens = 0
    total_output_tokens = 0
    valid_token_steps = 0
    peak_context_tokens: int | None = None
    model_counts: Counter[str] = Counter()
    model_input_tokens: Counter[str] = Counter()

    has_edits = False
    pre_edit_context_tokens: int | None = None
    pre_edit_new_input_tokens: int | None = None
    turns_to_first_edit: int | None = None
    seconds_to_first_edit: float | None = None

    read_file_calls = 0
    code_read_calls = 0
    large_code_reads = 0
    blind_large_code_reads = 0
    large_exempt_reads = 0
    blind_large_exempt_reads = 0
    large_lock_reads = 0
    blind_large_lock_reads = 0
    oversized_range_reads = 0
    redundant_rereads = 0
    parallel_read_burst_turns = 0
    parallel_read_burst_all_turns = 0
    first_search_turn: int | None = None
    first_read_turn: int | None = None

    run_command_calls = 0
    cmd_byte_sizes: dict[int, int] = {}
    pending_full_lookups: dict[int, tuple[int, int]] = {}
    cmd_errors = 0
    pipe_truncate_violations = 0
    pipe_truncate_errors = 0
    edit_file_calls = 0
    edit_errors = 0
    subagent_spawns = 0
    subagent_types: Counter[str] = Counter()
    checkpoint_count = 0

    first_user_raw = ""
    last_user_raw = ""
    last_planner_raw = ""
    mid_anomaly_raw = ""
    seen_code_ranges: dict[str, list[tuple[int, int]]] = defaultdict(list)

    edited_paths_by_cat: dict[str, set[str]] = {k: set() for k in EDIT_CATEGORY_ORDER}
    unknown_edit_seq = 0
    slash_commands: list[str] = []
    cmd_categories_set: set[str] = set()
    last_event_was_unanswered_user = False
    last_turn_had_tool_error = False
    last_turn_had_ask_question = False
    last_turn_has_text = False
    last_turn_has_tools = False

    # 直前 PLANNER_RESPONSE のツール呼び出し列を保持し、後続 GENERIC と 1:1 ペアリングする
    pending_calls: list[tuple[str, dict[str, Any]]] = []
    pending_idx = 0

    with transcript_path.open("r", encoding="utf-8", errors="replace") as fh:
        for raw_line_idx, raw_line in enumerate(fh):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                malformed_lines += 1
                continue
            if not isinstance(obj, dict):
                malformed_lines += 1
                continue

            step_dt = try_parse_datetime(obj.get("created_at"))
            if step_dt is not None:
                if first_dt is None:
                    first_dt = step_dt
                last_dt = step_dt

            step_type = obj.get("type")
            content = obj.get("content")
            content_str = content if isinstance(content, str) else ""

            if step_type != "GENERIC" and pending_idx < len(pending_calls):
                unpaired_tool_calls += len(pending_calls) - pending_idx
                pending_calls = []
                pending_idx = 0

            if step_type == "USER_INPUT":
                user_input_count += 1
                extracted = extract_user_text(content_str)
                extract_slash_commands(extracted, slash_commands, limit=3)
                last_event_was_unanswered_user = True
                last_turn_had_tool_error = False
                last_turn_had_ask_question = False
                last_turn_has_text = False
                last_turn_has_tools = False
                if user_input_count == 1:
                    first_user_raw = extracted
                else:
                    if not mid_anomaly_raw and extracted:
                        mid_anomaly_raw = f"follow-up user request: {extracted}"
                if extracted:
                    last_user_raw = extracted

            elif step_type == "CHECKPOINT":
                checkpoint_count += 1
                if not mid_anomaly_raw:
                    mid_anomaly_raw = "checkpoint triggered"

            elif step_type == "PLANNER_RESPONSE":
                planner_turns += 1
                last_event_was_unanswered_user = False
                last_turn_had_tool_error = False
                last_turn_had_ask_question = False
                last_turn_has_text = bool(content_str.strip())
                last_turn_has_tools = False
                if content_str.strip():
                    last_planner_raw = content_str

                inp = obj.get("input_tokens")
                cac = obj.get("cache_read_tokens")
                out = obj.get("output_tokens")
                step_ctx: int | None = None
                if isinstance(inp, (int, float)) and isinstance(cac, (int, float)):
                    inp_i = int(inp)
                    cac_i = int(cac)
                    out_i = int(out) if isinstance(out, (int, float)) else 0
                    total_input_tokens += inp_i
                    total_cache_read_tokens += cac_i
                    total_output_tokens += out_i
                    valid_token_steps += 1
                    step_ctx = inp_i + cac_i
                    if peak_context_tokens is None or step_ctx > peak_context_tokens:
                        peak_context_tokens = step_ctx

                model_val = obj.get("model")
                if isinstance(model_val, str) and model_val.strip():
                    m_name = model_val.strip()
                    model_counts[m_name] += 1
                    if isinstance(inp, (int, float)):
                        model_input_tokens[m_name] += int(inp)

                tcs = obj.get("tool_calls") or []
                if isinstance(tcs, list):
                    turn_unscoped_reads = 0
                    turn_all_reads = 0
                    new_pending: list[tuple[str, dict[str, Any]]] = []
                    for tc in tcs:
                        if not isinstance(tc, dict):
                            continue
                        last_turn_has_tools = True
                        tc_name = str(tc.get("name") or "")
                        tc_args = tc.get("args") if isinstance(tc.get("args"), dict) else {}
                        new_pending.append((tc_name, tc_args))

                        if tc_name in SWARM_TOOLS:
                            has_swarm_tool = True

                        if tc_name == "ask_question":
                            last_turn_had_ask_question = True

                        if tc_name in EDIT_TOOLS:
                            if not has_edits:
                                has_edits = True
                                turns_to_first_edit = planner_turns
                                pre_edit_context_tokens = step_ctx
                                pre_edit_new_input_tokens = total_input_tokens if valid_token_steps > 0 else None
                                if first_dt is not None and step_dt is not None:
                                    seconds_to_first_edit = max(0.0, (step_dt - first_dt).total_seconds())
                            raw_edit_path = tc_args.get("Path")
                            norm_edit_path = normalize_file_path(raw_edit_path)
                            if norm_edit_path:
                                edit_cat = classify_edit_file_category(raw_edit_path)
                                edited_paths_by_cat[edit_cat].add(norm_edit_path)
                            else:
                                unknown_edit_seq += 1
                                edited_paths_by_cat["code"].add(f"<unknown:{unknown_edit_seq}>")

                        if tc_name == "edit_file":
                            edit_file_calls += 1
                        elif tc_name == "read_file":
                            turn_all_reads += 1
                            if first_read_turn is None:
                                first_read_turn = planner_turns
                            s_line = parse_optional_int(tc_args.get("StartLine"))
                            e_line = parse_optional_int(tc_args.get("EndLine"))
                            if s_line is None and e_line is None:
                                turn_unscoped_reads += 1
                        elif tc_name == "run_command":
                            cmd_str = str(decode_tool_arg(tc_args.get("CommandLine")) or "")
                            cmd_categories_set.update(detect_cmd_categories(cmd_str))
                            if SEARCH_CMD_RE.search(cmd_str) and first_search_turn is None:
                                first_search_turn = planner_turns
                        elif tc_name == "invoke_subagent":
                            subagent_spawns += 1
                            t_type = str(decode_tool_arg(tc_args.get("TypeName")) or "unknown").strip() or "unknown"
                            subagent_types[t_type] += 1

                    if turn_unscoped_reads >= PARALLEL_READ_BURST_MIN:
                        parallel_read_burst_turns += 1
                    if turn_all_reads >= PARALLEL_READ_BURST_MIN:
                        parallel_read_burst_all_turns += 1
                    pending_calls = new_pending
                    pending_idx = 0

            elif step_type == "GENERIC":
                if pending_idx >= len(pending_calls):
                    continue
                tc_name, tc_args = pending_calls[pending_idx]
                pending_idx += 1

                is_tool_err = (
                    obj.get("status") == "ERROR"
                    or bool(obj.get("error"))
                    or (tc_name == "run_command" and bool(NONZERO_EXIT_RE.search(content_str)))
                )
                if is_tool_err:
                    last_turn_had_tool_error = True

                if tc_name == "read_file":
                    read_file_calls += 1
                    raw_path = tc_args.get("Path")
                    norm_path = normalize_file_path(raw_path)
                    file_cat = classify_file_path(raw_path)
                    s_line = parse_optional_int(tc_args.get("StartLine"))
                    e_line = parse_optional_int(tc_args.get("EndLine"))

                    m_show = SHOWING_LINES_RE.search(content_str)
                    obs_end: int | None = None
                    total_lines: int | None = None
                    if m_show:
                        obs_end = int(m_show.group(2))
                        total_lines = int(m_show.group(3))

                    is_unscoped = s_line is None and e_line is None
                    is_oversized = (
                        (s_line is None) != (e_line is None)
                        or (s_line is not None and e_line is not None and (e_line - s_line + 1) > LARGE_LINE_THRESHOLD)
                    )

                    if total_lines is not None and total_lines > LARGE_LINE_THRESHOLD:
                        if file_cat == "code":
                            large_code_reads += 1
                            if is_unscoped:
                                blind_large_code_reads += 1
                            elif is_oversized:
                                oversized_range_reads += 1
                        elif file_cat == "exempt_doc_config":
                            large_exempt_reads += 1
                            if is_unscoped:
                                blind_large_exempt_reads += 1
                        else:
                            large_lock_reads += 1
                            if is_unscoped:
                                blind_large_lock_reads += 1

                    if file_cat == "code":
                        code_read_calls += 1
                        r_start = s_line if s_line is not None else 1
                        if e_line is not None:
                            r_end = e_line
                        elif obs_end is not None:
                            r_end = obs_end
                        elif total_lines is not None:
                            r_end = total_lines
                        else:
                            r_end = 10**9
                        if _has_redundant_reread(seen_code_ranges[norm_path], r_start, r_end):
                            redundant_rereads += 1
                            if not mid_anomaly_raw:
                                mid_anomaly_raw = f"redundant_reread on code file (lines {r_start}-{r_end})"
                        seen_code_ranges[norm_path].append((r_start, r_end))

                elif tc_name == "run_command":
                    cmd_idx = run_command_calls
                    run_command_calls += 1
                    cmd_str = str(decode_tool_arg(tc_args.get("CommandLine")) or "")
                    has_pipe_violation = bool(PIPE_TRUNCATE_RE.search(cmd_str))
                    if has_pipe_violation:
                        pipe_truncate_violations += 1
                    has_nonzero = bool(NONZERO_EXIT_RE.search(content_str))
                    if has_nonzero and has_pipe_violation:
                        pipe_truncate_errors += 1
                    if has_nonzero or obj.get("status") == "ERROR" or bool(obj.get("error")):
                        cmd_errors += 1

                    fallback_bytes = len(content_str.encode("utf-8"))
                    t_fields = obj.get("truncated_fields")
                    if lookup_full and isinstance(t_fields, list) and "content" in t_fields:
                        pending_full_lookups[raw_line_idx] = (cmd_idx, fallback_bytes)
                    else:
                        cmd_byte_sizes[cmd_idx] = fallback_bytes

                elif tc_name in ("edit_file", "write_file"):
                    if tc_name == "edit_file" and (obj.get("status") == "ERROR" or bool(obj.get("error"))):
                        edit_errors += 1
                        if not mid_anomaly_raw:
                            mid_anomaly_raw = "edit_file error encountered"
                    if not is_tool_err:
                        norm_path = normalize_file_path(tc_args.get("Path"))
                        if norm_path:
                            seen_code_ranges[norm_path].clear()

    if pending_idx < len(pending_calls):
        unpaired_tool_calls += len(pending_calls) - pending_idx

    full_lookup_misses = 0
    if pending_full_lookups:
        resolved, full_lookup_misses = _lookup_full_command_sizes(
            transcript_path.with_name("transcript_full.jsonl"),
            pending_full_lookups,
        )
        cmd_byte_sizes.update(resolved)

    large_cmd_outputs = sum(1 for sz in cmd_byte_sizes.values() if sz > LARGE_CMD_OUTPUT_BYTES)

    if is_subagent:
        session_class = "swarm_worker" if has_swarm_tool else "subagent"
    elif user_input_count >= 1:
        session_class = "swarm_coordinator" if has_swarm_tool else "parent"
    else:
        session_class = "orphan_or_empty"

    search_before_read: bool | None = None
    if read_file_calls > 0:
        search_before_read = first_search_turn is not None and first_read_turn is not None and first_search_turn <= first_read_turn

    if planner_turns == 0 or last_event_was_unanswered_user or (not last_turn_has_text and not last_turn_has_tools):
        ended_with = "no_assistant_response"
    elif last_turn_had_tool_error:
        ended_with = "tool_error"
    elif last_turn_had_ask_question:
        ended_with = "ask_question_tool"
    elif last_turn_has_text:
        ended_with = "assistant_text"
    else:
        ended_with = "tool_only"

    trailing_q = has_trailing_question(last_planner_raw)
    edit_file_counts = {k: len(edited_paths_by_cat[k]) for k in EDIT_CATEGORY_ORDER if edited_paths_by_cat[k]}
    cmd_categories = [c for c in CMD_CATEGORY_ORDER if c in cmd_categories_set]
    last_turn_raw = last_planner_raw or last_user_raw

    return SessionMetrics(
        session_id=session_id,
        session_class=session_class,
        primary_model=_choose_primary_model(model_counts, model_input_tokens),
        first_created_at=first_dt,
        last_created_at=last_dt,
        has_edits=has_edits,
        planner_turns=planner_turns,
        total_input_tokens=total_input_tokens,
        total_cache_read_tokens=total_cache_read_tokens,
        total_output_tokens=total_output_tokens,
        valid_token_steps=valid_token_steps,
        peak_context_tokens=peak_context_tokens,
        pre_edit_context_tokens=pre_edit_context_tokens,
        pre_edit_new_input_tokens=pre_edit_new_input_tokens,
        turns_to_first_edit=turns_to_first_edit,
        seconds_to_first_edit=seconds_to_first_edit,
        read_file_calls=read_file_calls,
        code_read_calls=code_read_calls,
        large_code_reads=large_code_reads,
        blind_large_code_reads=blind_large_code_reads,
        large_exempt_reads=large_exempt_reads,
        blind_large_exempt_reads=blind_large_exempt_reads,
        large_lock_reads=large_lock_reads,
        blind_large_lock_reads=blind_large_lock_reads,
        oversized_range_reads=oversized_range_reads,
        redundant_rereads=redundant_rereads,
        parallel_read_burst_turns=parallel_read_burst_turns,
        parallel_read_burst_all_turns=parallel_read_burst_all_turns,
        search_before_read=search_before_read,
        run_command_calls=run_command_calls,
        large_cmd_outputs=large_cmd_outputs,
        cmd_errors=cmd_errors,
        pipe_truncate_violations=pipe_truncate_violations,
        pipe_truncate_errors=pipe_truncate_errors,
        edit_file_calls=edit_file_calls,
        edit_errors=edit_errors,
        subagent_spawns=subagent_spawns,
        subagent_types=subagent_types,
        checkpoint_count=checkpoint_count,
        malformed_lines=malformed_lines,
        unpaired_tool_calls=unpaired_tool_calls,
        full_lookup_misses=full_lookup_misses,
        first_user_excerpt=first_user_raw,
        last_turn_excerpt=last_turn_raw,
        mid_anomaly_excerpt=mid_anomaly_raw,
        user_input_count=user_input_count,
        last_user_excerpt=last_user_raw,
        final_assistant_excerpt=last_planner_raw,
        edit_file_counts=edit_file_counts,
        ended_with=ended_with,
        trailing_q=trailing_q,
        slash_commands=slash_commands,
        cmd_categories=cmd_categories,
        subagent_type=(subagent_type.strip() if subagent_type and subagent_type.strip() else "unknown")
        if is_subagent
        else None,
    )


def _percentile(sorted_vals: list[float], q: float) -> float:
    """ソート済み非空配列から線形補間パーセンタイルを返す（常に単調非減少）。"""
    if len(sorted_vals) == 1:
        return float(sorted_vals[0])
    pos = (len(sorted_vals) - 1) * q
    lo = int(math.floor(pos))
    hi = int(math.ceil(pos))
    if lo == hi:
        return float(sorted_vals[lo])
    frac = pos - lo
    return float(sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac)


def summarize_numeric(values: list[float | int | None]) -> dict[str, Any]:
    """数値配列から n, p50, p90, mean を算出する（有効値 0 件時は None）。"""
    clean = sorted(float(v) for v in values if v is not None)
    if not clean:
        return {"n": 0, "p50": None, "p90": None, "mean": None}
    return {
        "n": len(clean),
        "p50": round(_percentile(clean, 0.50), 4),
        "p90": round(_percentile(clean, 0.90), 4),
        "mean": round(sum(clean) / len(clean), 4),
    }


def aggregate_cohort(sessions: list[SessionMetrics]) -> dict[str, Any]:
    """セッション群から 3 軸指標の分布統計と加重率を集計する。"""
    if not sessions:
        return {"n": 0, "with_edits_n": 0, "metrics": {}, "aggregates": {}, "subagent_types": {}}

    metrics = {
        "pre_edit_context_tokens": summarize_numeric([s.pre_edit_context_tokens for s in sessions if s.has_edits]),
        "pre_edit_new_input_tokens": summarize_numeric([s.pre_edit_new_input_tokens for s in sessions if s.has_edits]),
        "peak_context_tokens": summarize_numeric([s.peak_context_tokens for s in sessions]),
        "total_new_input_tokens": summarize_numeric([s.total_input_tokens if s.valid_token_steps > 0 else None for s in sessions]),
        "total_output_tokens": summarize_numeric([s.total_output_tokens if s.valid_token_steps > 0 else None for s in sessions]),
        "cache_hit_rate": summarize_numeric([s.cache_hit_rate for s in sessions]),
        "blind_large_code_read_rate": summarize_numeric([s.blind_large_code_read_rate for s in sessions]),
        "oversized_range_reads": summarize_numeric([s.oversized_range_reads for s in sessions]),
        "lock_blind_reads": summarize_numeric([s.blind_large_lock_reads for s in sessions]),
        "exempt_large_doc_reads": summarize_numeric([s.large_exempt_reads for s in sessions]),
        "parallel_read_burst_turns": summarize_numeric([s.parallel_read_burst_turns for s in sessions]),
        "parallel_read_burst_all_turns": summarize_numeric([s.parallel_read_burst_all_turns for s in sessions]),
        "search_before_read_rate": summarize_numeric(
            [1.0 if s.search_before_read else 0.0 for s in sessions if s.search_before_read is not None]
        ),
        "pipe_truncate_violations": summarize_numeric([s.pipe_truncate_violations for s in sessions]),
        "pipe_truncate_errors": summarize_numeric([s.pipe_truncate_errors for s in sessions]),
        "large_cmd_output_rate": summarize_numeric([s.large_cmd_output_rate for s in sessions]),
        "subagent_spawns_per_session": summarize_numeric([s.subagent_spawns for s in sessions]),
        "turns_to_first_edit": summarize_numeric([s.turns_to_first_edit for s in sessions if s.has_edits]),
        "seconds_to_first_edit": summarize_numeric([s.seconds_to_first_edit for s in sessions if s.has_edits]),
        "total_planner_turns": summarize_numeric([s.planner_turns for s in sessions]),
        "redundant_reread_rate": summarize_numeric([1.0 if s.redundant_rereads > 0 else 0.0 for s in sessions]),
        "redundant_rereads": summarize_numeric([s.redundant_rereads for s in sessions]),
        "edit_error_rate": summarize_numeric([s.edit_error_rate for s in sessions]),
        "cmd_error_rate": summarize_numeric([s.cmd_error_rate for s in sessions]),
        "checkpoint_rate": summarize_numeric([1.0 if s.checkpoint_count > 0 else 0.0 for s in sessions]),
    }

    sum_inp = sum(s.total_input_tokens for s in sessions)
    sum_cac = sum(s.total_cache_read_tokens for s in sessions)
    sum_large_code = sum(s.large_code_reads for s in sessions)
    sum_blind_code = sum(s.blind_large_code_reads for s in sessions)
    sum_cmd = sum(s.run_command_calls for s in sessions)
    sum_large_cmd = sum(s.large_cmd_outputs for s in sessions)
    sum_edit = sum(s.edit_file_calls for s in sessions)
    sum_edit_err = sum(s.edit_errors for s in sessions)
    sum_cmd_err = sum(s.cmd_errors for s in sessions)

    sub_types: Counter[str] = Counter()
    for s in sessions:
        sub_types.update(s.subagent_types)

    aggregates = {
        "weighted_cache_hit_rate": round(sum_cac / (sum_inp + sum_cac), 4) if (sum_inp + sum_cac) > 0 else None,
        "aggregate_blind_large_code_read_rate": round(sum_blind_code / sum_large_code, 4) if sum_large_code > 0 else None,
        "aggregate_large_cmd_output_rate": round(sum_large_cmd / sum_cmd, 4) if sum_cmd > 0 else None,
        "aggregate_edit_error_rate": round(sum_edit_err / sum_edit, 4) if sum_edit > 0 else None,
        "aggregate_cmd_error_rate": round(sum_cmd_err / sum_cmd, 4) if sum_cmd > 0 else None,
        "total_large_code_reads": sum_large_code,
        "total_blind_large_code_reads": sum_blind_code,
        "total_pipe_truncate_violations": sum(s.pipe_truncate_violations for s in sessions),
        "total_pipe_truncate_errors": sum(s.pipe_truncate_errors for s in sessions),
        "total_lock_blind_reads": sum(s.blind_large_lock_reads for s in sessions),
        "total_oversized_range_reads": sum(s.oversized_range_reads for s in sessions),
    }

    return {
        "n": len(sessions),
        "with_edits_n": sum(1 for s in sessions if s.has_edits),
        "metrics": metrics,
        "aggregates": aggregates,
        "subagent_types": dict(sorted(sub_types.items())),
    }


def compute_delta_pct(before_metrics: dict[str, Any], after_metrics: dict[str, Any]) -> dict[str, dict[str, float | None]]:
    """Before/After 間の P50・mean 増減率（%）を算出する。Before=0 時は None。"""
    deltas: dict[str, dict[str, float | None]] = {}
    for key, b_stat in before_metrics.items():
        a_stat = after_metrics.get(key) or {}
        row: dict[str, float | None] = {}
        for field_name in ("p50", "p90", "mean"):
            b_val = b_stat.get(field_name)
            a_val = a_stat.get(field_name)
            if b_val is None or a_val is None or b_val == 0:
                row[field_name] = None
            else:
                row[field_name] = round((a_val - b_val) / b_val * 100.0, 2)
        deltas[key] = row
    return deltas


def build_session_digest(session: SessionMetrics) -> tuple[str, int]:
    """Decision 1 送信用の適応型ダイジェスト（サニタイズ先行・構造化タグ付き）を組み立てる。"""
    user_start_src = (
        strip_handoff_boilerplate(session.first_user_excerpt)
        if session.first_user_excerpt.strip()
        else "(empty)"
    )
    first_u, r1 = sanitize_digest_text(user_start_src, 360, mode="head_tail")
    redactions = r1
    parts = [f"[USER_START] {first_u}"]

    if session.user_input_count >= 2 and session.last_user_excerpt.strip():
        last_u, r_lu = sanitize_digest_text(session.last_user_excerpt, 120, mode="head")
        redactions += r_lu
        parts.append(f"[LAST_USER] {last_u}")

    if session.mid_anomaly_excerpt:
        mid_t, r_mid = sanitize_digest_text(session.mid_anomaly_excerpt, 160, mode="head")
        redactions += r_mid
        parts.append(f"[MID_EVENT] {mid_t}")

    if session.final_assistant_excerpt.strip():
        final_a, r_fa = sanitize_digest_text(session.final_assistant_excerpt, 240, mode="tail")
        redactions += r_fa
    else:
        final_a = "(none)"
    parts.append(f"[FINAL_ASSISTANT] {final_a}")

    edit_items = [
        f"{k}:{session.edit_file_counts[k]}"
        for k in EDIT_CATEGORY_ORDER
        if session.edit_file_counts.get(k, 0) > 0
    ]
    edits_str = ",".join(edit_items) if edit_items else ("code:1" if session.has_edits else "none")
    stat_tokens = [
        f"edits={edits_str}",
        f"ended_with={session.ended_with}",
        f"trailing_q={1 if session.trailing_q else 0}",
    ]
    if session.slash_commands:
        stat_tokens.append("slash=" + ",".join(session.slash_commands[:3]))
    if session.cmd_categories:
        stat_tokens.append("cmd=" + ",".join(session.cmd_categories))
    stat_tokens.extend(
        [
            f"turns={session.planner_turns}",
            f"blind_code={session.blind_large_code_reads}",
            f"reread={session.redundant_rereads}",
            f"edit_err={session.edit_errors}",
            f"cmd_err={session.cmd_errors}",
            f"checkpoint={session.checkpoint_count}",
        ]
    )
    parts.append("[STATS] " + " ".join(stat_tokens))
    return "\n".join(parts), redactions


def _estimate_question_overhead_chars() -> int:
    """1 セッション分の questions JSON 定義文字数を推定する。"""
    dummy_q = build_decision_payload([("s0001", None, "x")])["questions"]  # type: ignore[list-item]
    return len(json.dumps(dummy_q, ensure_ascii=False)) + 16


def chunk_digest_records(
    records: list[tuple[str, SessionMetrics, str]],
    *,
    max_sessions: int = DEFAULT_CHUNK_SIZE,
    max_chars: int = MAX_CHARS_PER_CHUNK,
    max_payload_chars: int = MAX_PAYLOAD_CHARS_PER_CHUNK,
    per_session_question_chars: int | None = None,
) -> list[list[tuple[str, SessionMetrics, str]]]:
    """セッションダイジェストを文字数上限・質問数上限・総ペイロード上限でチャンク分割する。"""
    q_chars = _estimate_question_overhead_chars() if per_session_question_chars is None else per_session_question_chars
    chunks: list[list[tuple[str, SessionMetrics, str]]] = []
    current: list[tuple[str, SessionMetrics, str]] = []
    current_chars = 0
    current_payload_chars = 0
    for rec in records:
        _, _, block = rec
        block_len = len(block) + 2
        if current and (
            len(current) >= max_sessions
            or current_chars + block_len > max_chars
            or current_payload_chars + block_len + q_chars > max_payload_chars
        ):
            chunks.append(current)
            current = []
            current_chars = 0
            current_payload_chars = 0
        current.append(rec)
        current_chars += block_len
        current_payload_chars += block_len + q_chars
    if current:
        chunks.append(current)
    return chunks


def build_decision_payload(
    chunk: list[tuple[str, SessionMetrics, str]],
    *,
    model: str = run_decisions.DEFAULT_MODEL,
) -> dict[str, Any]:
    """1 チャンク分の Decisions API リクエストペイロードを構築する。"""
    input_text = "\n\n".join(block for _, _, block in chunk)
    questions: dict[str, Any] = {}
    for prefix, _, _ in chunk:
        questions[f"{prefix}_task_type"] = {
            "type": "choice",
            "instructions": (
                f'セッション "{prefix}" の主目的（[USER_START] 冒頭の依頼と実際の編集内容）に最も合致するタスク種別を 1 つ選んでください。'
                "主目的が同等に拮抗して迷う場合のみ、優先順 "
                "(review_or_audit → research_or_plan → feature_or_refactor → bugfix_or_small_edit → other) "
                "および edits 件数をタイブレーク目安として決定してください。"
            ),
            "criteria": dict(TASK_TYPE_CRITERIA),
        }
        questions[f"{prefix}_context_starvation"] = {
            "type": "noul",
            "instructions": (
                f'セッション "{prefix}" において、コンテキスト不足やファイルの細切れ読み込みが原因で'
                "見落とし・誤解・やり直しが発生した明確な兆候がありますか？"
            ),
            "criteria": {
                "true_description": "コンテキスト不足や分割読み込みが原因の見落とし・誤解・やり直しが明確に見られる",
                "false_description": "文脈不足による見落としややり直しの明確な兆候はない",
            },
        }
        questions[f"{prefix}_outcome"] = {
            "type": "choice",
            "instructions": (
                f'セッション "{prefix}" の最終的な完了状態を、[FINAL_ASSISTANT] 本文を最優先とし、'
                "ended_with と trailing_q を補助シグナルにして 1 つ選んでください。"
            ),
            "criteria": dict(OUTCOME_CRITERIA),
        }
    return {"model": model, "input": input_text, "questions": questions}


def _extract_chunk_classifications(
    chunk: list[tuple[str, SessionMetrics, str]],
    enriched: dict[str, Any],
    *,
    min_confidence: float,
    task_type_min_confidence: float | None = None,
) -> dict[str, dict[str, Any]]:
    """Decision 1 応答から各セッションのタスク種別・文脈不足・完了状態を抽出する。"""
    tt_min_conf = min_confidence if task_type_min_confidence is None else task_type_min_confidence
    answers = enriched.get("answers", {})
    out: dict[str, dict[str, Any]] = {}
    for prefix, sess, _ in chunk:
        tt_ans = answers.get(f"{prefix}_task_type") if isinstance(answers, dict) else None
        cs_ans = answers.get(f"{prefix}_context_starvation") if isinstance(answers, dict) else None
        oc_ans = answers.get(f"{prefix}_outcome") if isinstance(answers, dict) else None

        if isinstance(tt_ans, dict):
            tt_conf = float(tt_ans.get("confidence") or 0.0)
            task_type = str(tt_ans.get("choice") or "other") if tt_conf >= tt_min_conf else "uncertain"
        else:
            task_type = "uncertain"

        if isinstance(cs_ans, dict) and isinstance(cs_ans.get("noul"), (int, float)):
            p_true = float(cs_ans["noul"])
            cs_conf = float(
                cs_ans["confidence"]
                if isinstance(cs_ans.get("confidence"), (int, float))
                else max(p_true, 1.0 - p_true)
            )
            if cs_conf >= min_confidence:
                starvation: str | bool = p_true >= 0.5
            else:
                starvation = "uncertain"
        else:
            starvation = "uncertain"

        if isinstance(oc_ans, dict):
            oc_conf = float(oc_ans.get("confidence") or 0.0)
            outcome = str(oc_ans.get("choice") or "other") if oc_conf >= min_confidence else "uncertain"
        else:
            outcome = "uncertain"

        out[sess.session_id] = {
            "task_type": task_type,
            "context_starvation": starvation,
            "outcome": outcome,
        }
    return out


def _execute_chunk_with_bisect(
    chunk: list[tuple[str, SessionMetrics, str]],
    *,
    api_key: str,
    endpoint: str,
    timeout: float,
    min_confidence: float,
    task_type_min_confidence: float | None = None,
    opener: Callable[..., Any] | None,
    depth: int,
    state: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """1 チャンクを実行し、SafetyBlockError 時のみ最大深さ 2 で二分再送する。"""
    if state["requests_used"] >= state["max_requests"]:
        state["had_error"] = True
        state["warnings"].append("Decision 1 総リクエスト上限に達したため一部チャンクを未分類としました。")
        return {
            sess.session_id: {"task_type": "unclassified", "context_starvation": "unclassified", "outcome": "unclassified"}
            for _, sess, _ in chunk
        }

    payload = build_decision_payload(chunk)
    errors = run_decisions.validate_payload(payload)
    if errors:
        raise ValueError("; ".join(errors))

    state["requests_used"] += 1
    try:
        raw = run_decisions.call_decisions_api(
            payload,
            api_key=api_key,
            endpoint=endpoint,
            timeout=timeout,
            opener=opener,
        )
        enriched = run_decisions.enrich_response(raw, min_confidence=min_confidence)
        return _extract_chunk_classifications(
            chunk,
            enriched,
            min_confidence=min_confidence,
            task_type_min_confidence=task_type_min_confidence,
        )
    except run_decisions.SafetyBlockError as exc:
        min_leaf = int(state.get("min_leaf", MIN_BISECT_CHUNK))
        if depth < MAX_BISECT_DEPTH and len(chunk) >= min_leaf * 2:
            mid = len(chunk) // 2
            left = _execute_chunk_with_bisect(
                chunk[:mid],
                api_key=api_key,
                endpoint=endpoint,
                timeout=timeout,
                min_confidence=min_confidence,
                task_type_min_confidence=task_type_min_confidence,
                opener=opener,
                depth=depth + 1,
                state=state,
            )
            right = _execute_chunk_with_bisect(
                chunk[mid:],
                api_key=api_key,
                endpoint=endpoint,
                timeout=timeout,
                min_confidence=min_confidence,
                task_type_min_confidence=task_type_min_confidence,
                opener=opener,
                depth=depth + 1,
                state=state,
            )
            left.update(right)
            return left
        state["had_block"] = True
        state["warnings"].append(f"安全フィルタ遮断により {len(chunk)} セッションを隔離しました ({exc.source}:{exc.code})。")
        return {
            sess.session_id: {"task_type": "blocked", "context_starvation": "blocked", "outcome": "blocked"}
            for _, sess, _ in chunk
        }
    except run_decisions.ApiRequestError as exc:
        state["had_error"] = True
        state["warnings"].append(f"Decision 1 API 呼び出し失敗のためフォールバックしました: {exc}")
        return {
            sess.session_id: {"task_type": "unclassified", "context_starvation": "unclassified", "outcome": "unclassified"}
            for _, sess, _ in chunk
        }


def run_decision1_stage(
    sessions: list[SessionMetrics],
    *,
    dry_run: bool,
    min_confidence: float,
    max_chunks: int,
    timeout: float,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    task_type_min_confidence: float | None = None,
    api_key: str | None = None,
    endpoint: str = run_decisions.DEFAULT_ENDPOINT,
    opener: Callable[..., Any] | None = None,
) -> tuple[str, dict[str, Any], dict[str, dict[str, Any]], list[str], int]:
    """第 2 段 Decision 1 分類を実行し、(status, summary, classifications, warnings, exit_code) を返す。"""
    validate_confidence_value(min_confidence, "--min-confidence")
    if task_type_min_confidence is not None:
        validate_confidence_value(task_type_min_confidence, "--task-type-min-confidence")
    eff_tt_conf = min_confidence if task_type_min_confidence is None else task_type_min_confidence

    if not (1 <= chunk_size <= MAX_SESSIONS_PER_CHUNK):
        raise ValueError(f"--chunk-size は 1〜{MAX_SESSIONS_PER_CHUNK} の範囲で指定してください: {chunk_size}")

    if not sessions:
        return (
            "ok" if not dry_run else "dry_run",
            {
                "chunks": 0,
                "chunk_size": chunk_size,
                "min_confidence": min_confidence,
                "task_type_min_confidence": eff_tt_conf,
                "questions": 0,
                "total_chars": 0,
                "redactions": 0,
                "uncertain_counts": {},
                "blocked_sessions": 0,
            },
            {},
            [],
            0,
        )

    records: list[tuple[str, SessionMetrics, str]] = []
    total_redactions = 0
    for idx, sess in enumerate(sessions, start=1):
        prefix = f"s{idx:04d}"
        digest_body, redactions = build_session_digest(sess)
        total_redactions += redactions
        block = f'<SESSION id="{prefix}">\n{digest_body}\n</SESSION>'
        records.append((prefix, sess, block))

    chunks = chunk_digest_records(records, max_sessions=chunk_size)
    if len(chunks) > max_chunks:
        raise ValueError(
            f"必要チャンク数 ({len(chunks)}) が --max-chunks ({max_chunks}) を超えています。"
            " --max-chunks を増やすか --since/--until で対象期間を絞ってください。"
        )

    total_questions = len(records) * 3
    total_chars = sum(len(block) for _, _, block in records)

    if dry_run:
        for chunk in chunks:
            payload = build_decision_payload(chunk)
            errors = run_decisions.validate_payload(payload)
            if errors:
                raise ValueError("; ".join(errors))
        summary = {
            "chunks": len(chunks),
            "chunk_size": chunk_size,
            "min_confidence": min_confidence,
            "task_type_min_confidence": eff_tt_conf,
            "questions": total_questions,
            "total_chars": total_chars,
            "redactions": total_redactions,
            "uncertain_counts": {},
            "blocked_sessions": 0,
        }
        return "dry_run", summary, {}, [], 0

    resolved_key = api_key if api_key is not None else os.environ.get("GEMINI_API_KEY", "").strip()
    if not resolved_key:
        warn = "GEMINI_API_KEY が未設定のため、第 2 段をスキップし第 1 段レポートへフォールバックしました。"
        summary = {
            "chunks": len(chunks),
            "chunk_size": chunk_size,
            "min_confidence": min_confidence,
            "task_type_min_confidence": eff_tt_conf,
            "questions": total_questions,
            "total_chars": total_chars,
            "redactions": total_redactions,
            "uncertain_counts": {},
            "blocked_sessions": 0,
        }
        return "fallback", summary, {}, [warn], 3

    min_leaf = min(MIN_BISECT_CHUNK, max(1, chunk_size // 2))
    state: dict[str, Any] = {
        "requests_used": 0,
        "max_requests": max_chunks * 3,
        "min_leaf": min_leaf,
        "had_block": False,
        "had_error": False,
        "warnings": [],
    }
    classifications: dict[str, dict[str, Any]] = {}
    for chunk in chunks:
        res = _execute_chunk_with_bisect(
            chunk,
            api_key=resolved_key,
            endpoint=endpoint,
            timeout=timeout,
            min_confidence=min_confidence,
            task_type_min_confidence=eff_tt_conf,
            opener=opener,
            depth=0,
            state=state,
        )
        classifications.update(res)

    uncertain_counts = {
        "task_type": sum(1 for v in classifications.values() if v["task_type"] == "uncertain"),
        "context_starvation": sum(1 for v in classifications.values() if v["context_starvation"] == "uncertain"),
        "outcome": sum(1 for v in classifications.values() if v["outcome"] == "uncertain"),
    }
    blocked_sessions = sum(1 for v in classifications.values() if v["task_type"] == "blocked")
    unclassified_sessions = sum(1 for v in classifications.values() if v["task_type"] == "unclassified")

    if unclassified_sessions == len(sessions):
        status = "fallback"
        exit_code = 3
    elif state["had_error"] or state["had_block"]:
        status = "partial"
        exit_code = 3
    else:
        status = "ok"
        exit_code = 0

    summary = {
        "chunks": len(chunks),
        "chunk_size": chunk_size,
        "min_confidence": min_confidence,
        "task_type_min_confidence": eff_tt_conf,
        "requests_used": state["requests_used"],
        "questions": total_questions,
        "total_chars": total_chars,
        "redactions": total_redactions,
        "uncertain_counts": uncertain_counts,
        "blocked_sessions": blocked_sessions,
        "unclassified_sessions": unclassified_sessions,
        "starvation_true": sum(1 for v in classifications.values() if v["context_starvation"] is True),
        "starvation_false": sum(1 for v in classifications.values() if v["context_starvation"] is False),
        "outcomes": dict(Counter(str(v["outcome"]) for v in classifications.values())),
    }
    return status, summary, classifications, state["warnings"], exit_code


def _group_before_after_by_key(
    before_sessions: list[SessionMetrics],
    after_sessions: list[SessionMetrics],
    key_fn: Callable[[SessionMetrics], str | None],
) -> dict[str, Any]:
    """任意の層別キー（モデル名またはタスク種別）で Before/After 比較辞書を構築する。"""
    b_groups: dict[str, list[SessionMetrics]] = defaultdict(list)
    a_groups: dict[str, list[SessionMetrics]] = defaultdict(list)
    for s in before_sessions:
        k = key_fn(s)
        if k is not None:
            b_groups[k].append(s)
    for s in after_sessions:
        k = key_fn(s)
        if k is not None:
            a_groups[k].append(s)

    all_keys = sorted(
        set(b_groups.keys()) | set(a_groups.keys()),
        key=lambda k: (-(len(b_groups[k]) + len(a_groups[k])), k),
    )
    out: dict[str, Any] = {}
    for k in all_keys:
        b_agg = aggregate_cohort(b_groups[k])
        a_agg = aggregate_cohort(a_groups[k])
        out[k] = {
            "before": b_agg,
            "after": a_agg,
            "delta_pct": compute_delta_pct(b_agg.get("metrics", {}), a_agg.get("metrics", {})),
            "low_sample": b_agg["n"] < LOW_SAMPLE_THRESHOLD or a_agg["n"] < LOW_SAMPLE_THRESHOLD,
        }
    return out


def aggregate_by_subagent_type(sessions: list[SessionMetrics]) -> dict[str, dict[str, Any]]:
    """サブエージェント／Swarmワーカーの消費実績を種別ごとに集計する。"""
    sub_sessions = [s for s in sessions if s.session_class in {"subagent", "swarm_worker"}]
    if not sub_sessions:
        return {}

    groups: dict[str, list[SessionMetrics]] = defaultdict(list)
    for s in sub_sessions:
        groups[s.subagent_type or "unknown"].append(s)

    grand_total_tokens = sum(s.total_input_tokens + s.total_cache_read_tokens for s in sub_sessions)
    items: list[tuple[str, dict[str, Any]]] = []
    for t_name, grp in groups.items():
        in_sum = sum(s.total_input_tokens for s in grp)
        cache_sum = sum(s.total_cache_read_tokens for s in grp)
        tot = in_sum + cache_sum
        peaks = sorted(s.peak_context_tokens for s in grp if s.peak_context_tokens is not None)
        p50_peak = round(_percentile([float(v) for v in peaks], 0.50), 4) if peaks else None
        items.append(
            (
                t_name,
                {
                    "n": len(grp),
                    "with_edits": sum(1 for s in grp if s.has_edits),
                    "total_input_tokens": in_sum,
                    "total_cache_read_tokens": cache_sum,
                    "total_tokens": tot,
                    "token_share": (tot / grand_total_tokens) if grand_total_tokens > 0 else None,
                    "weighted_cache_hit_rate": (cache_sum / tot) if tot > 0 else None,
                    "peak_context_tokens_p50": p50_peak,
                },
            )
        )

    items.sort(key=lambda kv: (-kv[1]["total_tokens"], kv[0]))
    return dict(items)


def build_report_data(
    *,
    app_data_dir: Path,
    scope: str,
    cutoff_dt: datetime | None,
    cutoff_str: str | None,
    since_dt: datetime | None,
    until_dt: datetime | None,
    only_with_edits: bool,
    model_prefix: str | None,
    session_id_filter: str | None,
    top_offenders_n: int,
    all_sessions: list[SessionMetrics],
    included_sessions: list[SessionMetrics],
    decision1_status: str,
    decision1_summary: dict[str, Any],
    classifications: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """レポート出力用の正規化データ構造（JSON 互換）を組み立てる。"""
    class_counts = {cls: 0 for cls in SUBAGENT_CLASSES}
    for s in all_sessions:
        class_counts[s.session_class] = class_counts.get(s.session_class, 0) + 1

    cutoff_spanning = 0
    if cutoff_dt is not None:
        for s in included_sessions:
            if s.first_created_at and s.last_created_at and s.first_created_at < cutoff_dt <= s.last_created_at:
                cutoff_spanning += 1

    meta = {
        "app_data_dir": str(app_data_dir),
        "scope": scope,
        "cutoff": cutoff_str,
        "since": since_dt.isoformat() if since_dt else None,
        "until": until_dt.isoformat() if until_dt else None,
        "only_with_edits": only_with_edits,
        "model_filter": model_prefix,
        "session_id": session_id_filter,
        "total_scanned": len(all_sessions),
        "included_sessions": len(included_sessions),
        "class_counts": class_counts,
        "cutoff_spanning_sessions": cutoff_spanning,
        "malformed_lines": sum(s.malformed_lines for s in all_sessions),
        "unpaired_tool_calls": sum(s.unpaired_tool_calls for s in all_sessions),
        "full_lookup_misses": sum(s.full_lookup_misses for s in all_sessions),
        "decision1_status": decision1_status,
    }

    overall = aggregate_cohort(included_sessions)
    comparison: dict[str, Any] = {}
    if cutoff_dt is not None:
        before = [s for s in included_sessions if s.first_created_at is not None and s.first_created_at < cutoff_dt]
        after = [s for s in included_sessions if s.first_created_at is not None and s.first_created_at >= cutoff_dt]
        b_agg = aggregate_cohort(before)
        a_agg = aggregate_cohort(after)
        b_edit = aggregate_cohort([s for s in before if s.has_edits])
        a_edit = aggregate_cohort([s for s in after if s.has_edits])

        def task_key_fn(s: SessionMetrics) -> str | None:
            info = classifications.get(s.session_id)
            if not info:
                return None
            tt = str(info["task_type"])
            if tt in {"uncertain", "blocked", "unclassified"}:
                return None
            return tt

        by_task_type = (
            _group_before_after_by_key(before, after, task_key_fn)
            if classifications
            else {}
        )
        comparison = {
            "before": b_agg,
            "after": a_agg,
            "delta_pct": compute_delta_pct(b_agg.get("metrics", {}), a_agg.get("metrics", {})),
            "before_with_edits": b_edit,
            "after_with_edits": a_edit,
            "delta_pct_with_edits": compute_delta_pct(b_edit.get("metrics", {}), a_edit.get("metrics", {})),
            "by_model": _group_before_after_by_key(before, after, lambda s: s.primary_model),
            "by_task_type": by_task_type,
        }

    def cohort_label(s: SessionMetrics) -> str:
        if cutoff_dt is None or s.first_created_at is None:
            return "overall"
        return "before" if s.first_created_at < cutoff_dt else "after"

    ranked = sorted(
        included_sessions,
        key=lambda s: (-(s.peak_context_tokens or 0), -s.blind_large_code_reads, s.session_id),
    )
    top_offenders = [
        {
            "session_id": s.session_id[:8],
            "cohort": cohort_label(s),
            "model": s.primary_model,
            "peak_context_tokens": s.peak_context_tokens,
            "blind_large_code_reads": s.blind_large_code_reads,
            "redundant_rereads": s.redundant_rereads,
            "large_cmd_outputs": s.large_cmd_outputs,
            "turns_to_first_edit": s.turns_to_first_edit,
        }
        for s in ranked[:top_offenders_n]
    ]

    return {
        "meta": meta,
        "overall": overall,
        "by_subagent_type": aggregate_by_subagent_type(included_sessions),
        "comparison": comparison,
        "decision1": decision1_summary,
        "top_offenders": top_offenders,
    }


def _fmt_num(val: Any, *, is_pct: bool = False) -> str:
    if val is None:
        return "N/A"
    if is_pct:
        return f"{float(val) * 100:.1f}%"
    f = float(val)
    if f.is_integer():
        return f"{int(f):,}"
    return f"{f:,.2f}"


def _fmt_delta(val: float | None) -> str:
    if val is None:
        return "N/A"
    sign = "+" if val > 0 else ""
    return f"{sign}{val:.1f}%"


def _append_subagent_type_table(lines: list[str], by_sub: dict[str, Any]) -> None:
    """サブエージェント種別内訳テーブルを Markdown 出力へ追記する。"""
    if not by_sub:
        return
    lines.extend(
        [
            "",
            "### サブエージェント種別内訳（by_subagent_type）",
            "| 種別 | n | 編集あり | 新規入力 | キャッシュ読込 | 総トークン比率 | 加重キャッシュ率 | ピーク P50 |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for t_name, st in by_sub.items():
        lines.append(
            f"| `{t_name}` | {st['n']} | {st['with_edits']} | {_fmt_num(st['total_input_tokens'])} | {_fmt_num(st['total_cache_read_tokens'])} | {_fmt_num(st['token_share'], is_pct=True)} | {_fmt_num(st['weighted_cache_hit_rate'], is_pct=True)} | {_fmt_num(st['peak_context_tokens_p50'])} |"
        )


def render_markdown(report: dict[str, Any]) -> str:
    """正規化レポート辞書を Markdown 表形式へ整形する。"""
    meta = report["meta"]
    overall = report["overall"]
    comp = report.get("comparison") or {}
    d1 = report.get("decision1") or {}

    lines: list[str] = [
        "# Antigravity セッション効果測定レポート",
        "",
        "## 1. 実行条件とデータ内訳",
        f"- 対象スコープ: `{meta['scope']}`（全走査 {meta['total_scanned']} 件 / 対象 {meta['included_sessions']} 件）",
        "- クラス内訳: "
        + ", ".join(f"{k}={v}" for k, v in meta["class_counts"].items()),
        f"- データ衛生: 破損行={meta['malformed_lines']}, 非1:1ツール={meta['unpaired_tool_calls']}, full参照フォールバック={meta['full_lookup_misses']}",
        f"- Decision 1 状態: `{meta['decision1_status']}`",
    ]
    if meta["cutoff"]:
        lines.append(
            f"- カットオフ基準: `{meta['cutoff']}`（跨ぎセッション={meta['cutoff_spanning_sessions']} 件）"
        )
    if meta["session_id"]:
        lines.append(f"- 単一セッション指定: `{meta['session_id'][:8]}`")

    metric_specs: list[tuple[str, str, bool]] = [
        ("pre_edit_context_tokens", "初回編集前コンテキスト", False),
        ("pre_edit_new_input_tokens", "初回編集前新規入力", False),
        ("peak_context_tokens", "ピークコンテキスト", False),
        ("cache_hit_rate", "キャッシュヒット率（セッション別）", True),
        ("blind_large_code_read_rate", "200行超コード盲目読込率", True),
        ("search_before_read_rate", "検索先行率", True),
        ("parallel_read_burst_turns", "並列読込バーストターン数", False),
        ("large_cmd_output_rate", "10KB超コマンド出力率", True),
        ("pipe_truncate_violations", "パイプ打ち切り違反数", False),
        ("subagent_spawns_per_session", "サブエージェント起動回数", False),
        ("turns_to_first_edit", "初回編集までターン数", False),
        ("seconds_to_first_edit", "初回編集まで秒数", False),
        ("redundant_reread_rate", "重複再読セッション率", True),
        ("edit_error_rate", "edit_file 失敗率", True),
        ("cmd_error_rate", "コマンド非ゼロ終了率", True),
        ("checkpoint_rate", "チェックポイント発生率", True),
    ]

    if comp:
        b = comp["before"]
        a = comp["after"]
        d = comp["delta_pct"]
        lines.extend(
            [
                "",
                f"## 2. Before vs After 3 軸比較（Before n={b['n']}, After n={a['n']}）",
                "| 指標 | Before P50 (P90 / n) | After P50 (P90 / n) | P50 変化 | Mean 変化 |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for key, label, is_pct in metric_specs:
            bs = (b.get("metrics") or {}).get(key) or {}
            as_ = (a.get("metrics") or {}).get(key) or {}
            ds = d.get(key) or {}
            b_cell = f"{_fmt_num(bs.get('p50'), is_pct=is_pct)} ({_fmt_num(bs.get('p90'), is_pct=is_pct)} / {bs.get('n', 0)})"
            a_cell = f"{_fmt_num(as_.get('p50'), is_pct=is_pct)} ({_fmt_num(as_.get('p90'), is_pct=is_pct)} / {as_.get('n', 0)})"
            if is_pct and key in ("search_before_read_rate", "redundant_reread_rate", "checkpoint_rate"):
                b_cell = f"{_fmt_num(bs.get('mean'), is_pct=True)} (n={bs.get('n', 0)})"
                a_cell = f"{_fmt_num(as_.get('mean'), is_pct=True)} (n={as_.get('n', 0)})"
            lines.append(
                f"| {label} | {b_cell} | {a_cell} | {_fmt_delta(ds.get('p50'))} | {_fmt_delta(ds.get('mean'))} |"
            )
        ba = b.get("aggregates") or {}
        aa = a.get("aggregates") or {}
        lines.append(
            f"- 全体トークン加重キャッシュヒット率: Before {_fmt_num(ba.get('weighted_cache_hit_rate'), is_pct=True)} → After {_fmt_num(aa.get('weighted_cache_hit_rate'), is_pct=True)}"
        )
        lines.append(
            f"- 総計200行超コード盲目読込率: Before {_fmt_num(ba.get('aggregate_blind_large_code_read_rate'), is_pct=True)} ({ba.get('total_blind_large_code_reads', 0)}/{ba.get('total_large_code_reads', 0)}) → After {_fmt_num(aa.get('aggregate_blind_large_code_read_rate'), is_pct=True)} ({aa.get('total_blind_large_code_reads', 0)}/{aa.get('total_large_code_reads', 0)})"
        )

        be = comp["before_with_edits"]
        ae = comp["after_with_edits"]
        de = comp["delta_pct_with_edits"]
        lines.extend(
            [
                "",
                f"### 編集ありセッション限定（Before n={be['n']}, After n={ae['n']}）",
                "| 指標 | Before P50 (P90) | After P50 (P90) | P50 変化 |",
                "| --- | --- | --- | --- |",
            ]
        )
        for key, label, is_pct in metric_specs[:6] + metric_specs[10:14]:
            bs = (be.get("metrics") or {}).get(key) or {}
            as_ = (ae.get("metrics") or {}).get(key) or {}
            ds = de.get(key) or {}
            b_val = bs.get("mean") if key in ("search_before_read_rate", "redundant_reread_rate") else bs.get("p50")
            a_val = as_.get("mean") if key in ("search_before_read_rate", "redundant_reread_rate") else as_.get("p50")
            lines.append(
                f"| {label} | {_fmt_num(b_val, is_pct=is_pct)} ({_fmt_num(bs.get('p90'), is_pct=is_pct)}) | {_fmt_num(a_val, is_pct=is_pct)} ({_fmt_num(as_.get('p90'), is_pct=is_pct)}) | {_fmt_delta(ds.get('p50'))} |"
            )

        _append_subagent_type_table(lines, report.get("by_subagent_type") or {})

        by_model = comp.get("by_model") or {}
        if by_model:
            lines.extend(
                [
                    "",
                    "## 3. 主要モデル別比較（ピーク / 初回編集前 P50）",
                    "| モデル | Before n | After n | ピーク P50 変化 | 初回編集前 P50 変化 | 加重キャッシュ率 (B→A) |",
                    "| --- | --- | --- | --- | --- | --- |",
                ]
            )
            for model_name, grp in by_model.items():
                tag = " [low-n]" if grp.get("low_sample") else ""
                bm = grp["before"]
                am = grp["after"]
                dm = grp["delta_pct"]
                bc = _fmt_num((bm.get("aggregates") or {}).get("weighted_cache_hit_rate"), is_pct=True)
                ac = _fmt_num((am.get("aggregates") or {}).get("weighted_cache_hit_rate"), is_pct=True)
                lines.append(
                    f"| `{model_name}`{tag} | {bm['n']} | {am['n']} | {_fmt_delta((dm.get('peak_context_tokens') or {}).get('p50'))} | {_fmt_delta((dm.get('pre_edit_context_tokens') or {}).get('p50'))} | {bc} → {ac} |"
                )

        by_task = comp.get("by_task_type") or {}
        if by_task:
            lines.extend(
                [
                    "",
                    "## 4. Decision 1 タスク種別層別比較",
                    "| タスク種別 | Before n | After n | ピーク P50 変化 | 初回編集前 P50 変化 |",
                    "| --- | --- | --- | --- | --- |",
                ]
            )
            for t_name, grp in by_task.items():
                tag = " [low-n]" if grp.get("low_sample") else ""
                bm = grp["before"]
                am = grp["after"]
                dm = grp["delta_pct"]
                lines.append(
                    f"| `{t_name}`{tag} | {bm['n']} | {am['n']} | {_fmt_delta((dm.get('peak_context_tokens') or {}).get('p50'))} | {_fmt_delta((dm.get('pre_edit_context_tokens') or {}).get('p50'))} |"
                )
    else:
        lines.extend(
            [
                "",
                f"## 2. 全体サマリ（n={overall['n']}, 編集あり={overall['with_edits_n']}）",
                "| 指標 | n | P50 | P90 | Mean |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for key, label, is_pct in metric_specs:
            st = (overall.get("metrics") or {}).get(key) or {}
            lines.append(
                f"| {label} | {st.get('n', 0)} | {_fmt_num(st.get('p50'), is_pct=is_pct)} | {_fmt_num(st.get('p90'), is_pct=is_pct)} | {_fmt_num(st.get('mean'), is_pct=is_pct)} |"
            )

        _append_subagent_type_table(lines, report.get("by_subagent_type") or {})

    if d1 and d1.get("questions", 0) > 0:
        lines.extend(
            [
                "",
                "## Decision 1 概要",
                f"- チャンク数={d1.get('chunks', 0)}, 質問数={d1.get('questions', 0)}, 文字数={d1.get('total_chars', 0)}, マスク置換={d1.get('redactions', 0)}, 遮断={d1.get('blocked_sessions', 0)}",
            ]
        )
        if d1.get("min_confidence") is not None and d1.get("task_type_min_confidence") is not None:
            lines.append(
                f"- 採用信頼度閾値: task_type={d1['task_type_min_confidence']}, 他={d1['min_confidence']}"
            )
        if d1.get("uncertain_counts"):
            lines.append(
                "- 低信頼度（uncertain）件数: "
                + ", ".join(f"{k}={v}" for k, v in d1["uncertain_counts"].items())
            )

    offenders = report.get("top_offenders") or []
    if offenders:
        lines.extend(
            [
                "",
                "## 5. 上位改善対象セッション（top_offenders）",
                "| セッション | 区分 | モデル | ピークコンテキスト | 盲目コード大読込 | 重複再読 | 大出力コマンド | 初回編集ターン |",
                "| --- | --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for off in offenders:
            lines.append(
                f"| `{off['session_id']}` | {off['cohort']} | `{off['model']}` | {_fmt_num(off['peak_context_tokens'])} | {off['blind_large_code_reads']} | {off['redundant_rereads']} | {off['large_cmd_outputs']} | {_fmt_num(off['turns_to_first_edit'])} |"
            )

    return "\n".join(lines) + "\n"


def build_arg_parser() -> argparse.ArgumentParser:
    """CLI 引数パーサを構築する。"""
    parser = argparse.ArgumentParser(
        description="Antigravity 過去セッションログの効果測定・コンテキスト監査 CLI"
    )
    parser.add_argument(
        "--app-data-dir",
        type=Path,
        default=DEFAULT_APP_DATA_DIR,
        help="brain/ を含む Antigravity データディレクトリ（既定: ~/.gemini/antigravity）",
    )
    parser.add_argument(
        "--scope",
        choices=("parent", "subagent", "all"),
        default="parent",
        help="集計対象スコープ（既定: parent）",
    )
    parser.add_argument("--cutoff", default=None, help="Before/After 分割時刻（TZ 付き ISO 8601）")
    parser.add_argument("--since", default=None, help="集計開始時刻（含む、TZ 付き ISO 8601）")
    parser.add_argument("--until", default=None, help="集計終了時刻（含まない、TZ 付き ISO 8601）")
    parser.add_argument("--only-with-edits", action="store_true", help="編集を含むセッションのみ集計")
    parser.add_argument("--model", default=None, help="代表モデルの前方一致フィルタ")
    parser.add_argument("--session-id", default=None, help="特定セッション ID（他フィルタより優先）")
    parser.add_argument("--top-offenders", type=int, default=5, help="上位改善対象セッション表示件数（既定: 5）")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown", help="出力形式（既定: markdown）")
    parser.add_argument("--no-full-lookup", action="store_true", help="transcript_full.jsonl 遅延参照を無効化")
    parser.add_argument("--classify-decision1", action="store_true", help="Gemini Decision 1 でタスク・文脈不足を一括分類")
    parser.add_argument("--dry-run", action="store_true", help="API 送信なしで Decision 1 ペイロードを検証")
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=None,
        help=(
            f"Decision 1 採用信頼度閾値（0.0〜1.0、未指定時は task_type={DEFAULT_TASK_TYPE_MIN_CONFIDENCE}・"
            f"他={DEFAULT_MIN_CONFIDENCE}、単独明示時は全指標へ適用）"
        ),
    )
    parser.add_argument(
        "--task-type-min-confidence",
        type=float,
        default=None,
        help=f"Decision 1 の task_type（5 択）専用信頼度閾値（0.0〜1.0、両方未指定時は {DEFAULT_TASK_TYPE_MIN_CONFIDENCE}）",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help=f"Decision 1 の 1 チャンクあたり最大セッション数（1〜{MAX_SESSIONS_PER_CHUNK}、既定: {DEFAULT_CHUNK_SIZE}）",
    )
    parser.add_argument(
        "--max-chunks",
        type=int,
        default=DEFAULT_MAX_CHUNKS,
        help=f"Decision 1 最大チャンク数（既定: {DEFAULT_MAX_CHUNKS}）",
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="Decision 1 API タイムアウト秒（既定: 30.0）")
    return parser


def _filter_sessions(
    all_sessions: list[SessionMetrics],
    *,
    scope: str,
    since_dt: datetime | None,
    until_dt: datetime | None,
    only_with_edits: bool,
    model_prefix: str | None,
    session_id: str | None,
) -> list[SessionMetrics]:
    """フィルタ条件に従って対象セッションを絞り込む。"""
    if session_id:
        return [s for s in all_sessions if s.session_id == session_id]

    if scope == "parent":
        allowed = {"parent", "swarm_coordinator"}
    elif scope == "subagent":
        allowed = {"subagent", "swarm_worker"}
    else:
        allowed = set(SUBAGENT_CLASSES)

    out: list[SessionMetrics] = []
    for s in all_sessions:
        if s.session_class not in allowed:
            continue
        if since_dt is not None:
            if s.first_created_at is None or s.first_created_at < since_dt:
                continue
        if until_dt is not None:
            if s.first_created_at is None or s.first_created_at >= until_dt:
                continue
        if only_with_edits and not s.has_edits:
            continue
        if model_prefix and not s.primary_model.startswith(model_prefix):
            continue
        out.append(s)
    return out


def main(
    argv: list[str] | None = None,
    *,
    opener: Callable[..., Any] | None = None,
    api_key: str | None = None,
) -> int:
    """CLI エントリーポイント。終了コード 0/1/2/3 を返す。"""
    decision_hygiene.configure_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        cutoff_dt = parse_iso_datetime(args.cutoff) if args.cutoff else None
        since_dt = parse_iso_datetime(args.since) if args.since else None
        until_dt = parse_iso_datetime(args.until) if args.until else None
    except ValueError as exc:
        print(f"日時引数エラー: {exc}", file=sys.stderr)
        return 2

    if args.top_offenders < 0:
        print("引数エラー: --top-offenders は 0 以上を指定してください。", file=sys.stderr)
        return 2
    try:
        eff_min_conf, eff_tt_conf = resolve_confidence_thresholds(
            args.min_confidence,
            args.task_type_min_confidence,
        )
    except ValueError as exc:
        print(f"引数エラー: {exc}", file=sys.stderr)
        return 2
    if not (1 <= args.chunk_size <= MAX_SESSIONS_PER_CHUNK):
        print(f"引数エラー: --chunk-size は 1〜{MAX_SESSIONS_PER_CHUNK} の範囲で指定してください。", file=sys.stderr)
        return 2
    if args.max_chunks < 1:
        print("引数エラー: --max-chunks は 1 以上を指定してください。", file=sys.stderr)
        return 2
    if args.timeout <= 0:
        print("引数エラー: --timeout は正の数を指定してください。", file=sys.stderr)
        return 2

    try:
        discovered, sub_ids = discover_session_transcripts(args.app_data_dir)
        sub_types = collect_subagent_types(args.app_data_dir / "brain")
    except OSError as exc:
        print(f"ディレクトリ読込エラー: {exc}", file=sys.stderr)
        return 1

    all_sessions: list[SessionMetrics] = []
    for cid, t_path in discovered:
        if args.session_id and cid != args.session_id:
            continue
        try:
            sess = analyze_session(
                cid,
                t_path,
                is_subagent=(cid in sub_ids),
                subagent_type=sub_types.get(cid),
                lookup_full=not args.no_full_lookup,
            )
            all_sessions.append(sess)
        except OSError as exc:
            print(f"警告: セッション {cid[:8]} の読込をスキップしました: {exc}", file=sys.stderr)

    included = _filter_sessions(
        all_sessions,
        scope=args.scope,
        since_dt=since_dt,
        until_dt=until_dt,
        only_with_edits=args.only_with_edits,
        model_prefix=args.model,
        session_id=args.session_id,
    )

    decision1_status = "disabled"
    decision1_summary: dict[str, Any] = {}
    classifications: dict[str, dict[str, Any]] = {}
    exit_code = 0

    if args.classify_decision1:
        try:
            decision1_status, decision1_summary, classifications, warnings, exit_code = run_decision1_stage(
                included,
                dry_run=args.dry_run,
                min_confidence=eff_min_conf,
                max_chunks=args.max_chunks,
                timeout=args.timeout,
                chunk_size=args.chunk_size,
                task_type_min_confidence=eff_tt_conf,
                api_key=api_key,
                opener=opener,
            )
        except ValueError as exc:
            print(f"Decision 1 入力検証エラー: {exc}", file=sys.stderr)
            return 2
        for w in warnings:
            print(f"警告: {w}", file=sys.stderr)

    report = build_report_data(
        app_data_dir=args.app_data_dir,
        scope=args.scope,
        cutoff_dt=cutoff_dt,
        cutoff_str=args.cutoff,
        since_dt=since_dt,
        until_dt=until_dt,
        only_with_edits=args.only_with_edits,
        model_prefix=args.model,
        session_id_filter=args.session_id,
        top_offenders_n=args.top_offenders,
        all_sessions=all_sessions,
        included_sessions=included,
        decision1_status=decision1_status,
        decision1_summary=decision1_summary,
        classifications=classifications,
    )

    if args.format == "json":
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(render_markdown(report), end="")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
