#!/usr/bin/env python3
"""Gemini Decision 1 を用いた Antigravity transcript.jsonl 重要ステップ一括選別 CLI。

長大セッションの会話ログ（transcript.jsonl）をローカルで正規化・シークレットマスクし、
1 回の Decisions API 呼び出し（出力トークン 0）で各ステップを 4 区分へ一括分類する。
session-handoff の引き継ぎメモ作成素材や /compact 実行前の重要事項抽出に使用する。
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
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

DEFAULT_MODEL = run_decisions.DEFAULT_MODEL
DEFAULT_ENDPOINT = run_decisions.DEFAULT_ENDPOINT
DEFAULT_KEEP_RECENT = 6
DEFAULT_MIN_CONFIDENCE = 0.65
DEFAULT_MAX_CHARS = 240_000
DEFAULT_MAX_CHUNKS = 4
DEFAULT_MAX_STEP_CHARS = 1_200
DEFAULT_GENERIC_NORMAL_CHARS = 360
DEFAULT_GENERIC_ERROR_CHARS = 800
DEFAULT_THINKING_CHARS = 300
DEFAULT_RENDER_EXCERPT_CHARS = 1_200
DEFAULT_RENDER_COMPACT_CHARS = 400
DEFAULT_FULL_ERROR_CHARS = 2_000
DEFAULT_TIMEOUT = 30.0
MAX_QUESTIONS_PER_REQUEST = 1_000
LINE_IDX_KEY = "_line_idx"

STEP_CHOICE_CRITERIA: dict[str, str] = {
    "drop_noise": (
        "重複するファイル読み込み、完了済みの定型出力、結論に影響しなかった途中探索など、"
        "次セッションへ引き継ぐ必要がないステップ（採用判断の根拠となった却下案や比較検討を含むステップは除く）"
    ),
    "keep_decision": (
        "確定した設計方針、要件、仕様、制約、ユーザーとの合意事項、"
        "および採用判断の根拠となった却下案と却下理由を含むステップ"
    ),
    "keep_gotcha": (
        "失敗した試行、エラー原因、環境固有の制約、再発防止の教訓を含むステップ"
    ),
    "keep_state": (
        "未完了タスク、変更済みファイル、ブランチや PR の基準点、次の一手を含むステップ"
    ),
}

USER_REQUEST_RE = re.compile(r"<USER_REQUEST>(.*?)</USER_REQUEST>", re.DOTALL)
STRIP_TAG_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<ADDITIONAL_METADATA>.*?</ADDITIONAL_METADATA>", re.DOTALL),
    re.compile(r"<USER_SETTINGS_CHANGE>.*?</USER_SETTINGS_CHANGE>", re.DOTALL),
    re.compile(r"<PLAN>.*?</PLAN>", re.DOTALL),
)
TIMESTAMP_HEADER_RE = re.compile(r"^(?:Created At|Completed At):[^\n]*\n?", re.MULTILINE)

ERROR_SIGNAL_RE = re.compile(
    r"(?:Command exited with code [1-9]\d*|Traceback \(most recent call last\)|"
    r"\bFAILED\b|\bERROR:|error:|AssertionError|Exception:|PermissionError|SyntaxError)"
)

PRIVATE_KEY_BLOCK_RE = decision_hygiene.PRIVATE_KEY_BLOCK_RE
PRIVATE_KEY_HEADER_RE = decision_hygiene.PRIVATE_KEY_HEADER_RE
URL_CREDENTIAL_RE = re.compile(r"(?<=://)[^\s/?#@:]+:[^\s/?#@]+(?=@)")
SECRET_REPLACE_PATTERNS: tuple[re.Pattern[str], ...] = (
    decision_hygiene.SECRET_REDACT_PATTERNS
    + (decision_hygiene.BEARER_TOKEN_RE, URL_CREDENTIAL_RE)
)

PRIORITY_ARG_KEYS: tuple[str, ...] = (
    "Path",
    "CommandLine",
    "Target",
    "query",
    "Action",
    "Role",
    "Prompt",
    "TaskId",
)


@dataclass
class TranscriptStep:
    """正規化済みの会話ステップ 1 件。"""

    step_index: int
    source: str
    step_type: str
    status: str
    created_at: str
    is_error_signal: bool
    normalized_text: str
    raw_content: str = ""
    tool_summary: str = ""
    thinking_excerpt: str = ""
    line_idx: int = -1
    truncated_fields: tuple[str, ...] = ()
    full_excerpt: str = ""

    @property
    def label(self) -> str:
        if self.line_idx >= 0:
            return f"STEP {self.step_index:04d} L{self.line_idx:05d}"
        return f"STEP {self.step_index:04d}"

    @property
    def question_key(self) -> str:
        if self.line_idx < 0:
            return f"step_{self.step_index:04d}"
        return f"step_{self.step_index:04d}_l{self.line_idx:05d}"


@dataclass
class ClassifiedStep:
    """Decision 1 による分類結果付きのステップ。"""

    step: TranscriptStep
    choice: str
    confidence: float
    probabilities: dict[str, float] = field(default_factory=dict)
    is_borderline: bool = False


def mask_secrets(text: str, secret: str | None = None) -> str:
    """外部 API 送信前およびエラー出力向けに既知のシークレット・秘密鍵・API キー実値をマスクする。"""
    return decision_hygiene.mask_secrets(
        text,
        secrets=(secret,) if secret else (),
        extra_patterns=(decision_hygiene.BEARER_TOKEN_RE, URL_CREDENTIAL_RE),
    )


def truncate_head_tail(text: str, max_chars: int, head_ratio: float = 0.65) -> str:
    """長文を先頭と末尾の抜粋へ圧縮する。"""
    cleaned = text.strip()
    if max_chars <= 0 or len(cleaned) <= max_chars:
        return cleaned
    marker = "\n...[省略]...\n"
    budget = max_chars - len(marker)
    if budget <= 20:
        return cleaned[:max_chars]
    head_len = max(1, int(budget * head_ratio))
    tail_len = max(1, budget - head_len)
    return f"{cleaned[:head_len].rstrip()}{marker}{cleaned[-tail_len:].lstrip()}"


def _clean_arg_value(value: Any, max_len: int = 100) -> str:
    text = str(value).strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        try:
            decoded = json.loads(text)
            if isinstance(decoded, str):
                text = decoded
        except json.JSONDecodeError:
            text = text[1:-1]
    text = mask_secrets(text)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def summarize_tool_calls(tool_calls: Any) -> str:
    """tool_calls 配列を簡潔な 1 行リストへ要約する。"""
    if not isinstance(tool_calls, list) or not tool_calls:
        return ""
    items: list[str] = []
    for call in tool_calls:
        if not isinstance(call, dict):
            continue
        name = str(call.get("name") or "unknown")
        args = call.get("args")
        arg_preview = ""
        if isinstance(args, dict) and args:
            chosen_key: str | None = None
            for key in PRIORITY_ARG_KEYS:
                if key in args and args[key] not in (None, ""):
                    chosen_key = key
                    break
            if chosen_key is None:
                chosen_key = next(iter(args.keys()))
            arg_preview = f"{chosen_key}={_clean_arg_value(args[chosen_key])}"
        items.append(f"{name}({arg_preview})" if arg_preview else f"{name}()")
    return ", ".join(items)


def extract_user_input_text(content: str) -> str:
    """USER_INPUT から本質的なユーザー依頼本文を抽出し、定型タグを除去する。"""
    match = USER_REQUEST_RE.search(content)
    if match:
        body = match.group(1).strip()
        if body:
            return body
    stripped = content
    for pattern in STRIP_TAG_PATTERNS:
        stripped = pattern.sub("", stripped)
    stripped = re.sub(r"</?USER_REQUEST>", "", stripped)
    return stripped.strip()


def normalize_step(
    raw: dict[str, Any],
    *,
    max_step_chars: int = DEFAULT_MAX_STEP_CHARS,
    generic_normal_chars: int = DEFAULT_GENERIC_NORMAL_CHARS,
    generic_error_chars: int = DEFAULT_GENERIC_ERROR_CHARS,
    include_thinking: bool = False,
) -> TranscriptStep | None:
    """transcript.jsonl の 1 行を正規化し、空ステップなら None を返す。"""
    step_index_val = raw.get("step_index")
    if not isinstance(step_index_val, int):
        return None
    source = str(raw.get("source") or "")
    step_type = str(raw.get("type") or "UNKNOWN")
    status = str(raw.get("status") or "")
    created_at = str(raw.get("created_at") or "")
    raw_content_orig = str(raw.get("content") or "")
    is_error_signal = status.upper() == "ERROR" or bool(ERROR_SIGNAL_RE.search(raw_content_orig))

    # truncate_head_tail で秘密鍵の END 行等が欠落する前に必ずマスクを実行する
    raw_content = mask_secrets(raw_content_orig)
    tool_summary = mask_secrets(summarize_tool_calls(raw.get("tool_calls")))
    thinking_raw = mask_secrets(str(raw.get("thinking") or ""))
    thinking_excerpt = (
        truncate_head_tail(thinking_raw, DEFAULT_THINKING_CHARS, head_ratio=0.7)
        if include_thinking and thinking_raw.strip()
        else ""
    )

    parts: list[str] = []
    if step_type == "USER_INPUT":
        user_text = extract_user_input_text(raw_content)
        if user_text:
            parts.append(truncate_head_tail(user_text, max_step_chars, head_ratio=0.7))
    elif step_type == "PLANNER_RESPONSE":
        if raw_content.strip():
            parts.append(truncate_head_tail(raw_content, max_step_chars, head_ratio=0.7))
        if tool_summary:
            parts.append(f"[tools] {truncate_head_tail(tool_summary, 400, head_ratio=0.8)}")
        if thinking_excerpt:
            parts.append(f"[thinking] {thinking_excerpt}")
    else:
        cleaned = TIMESTAMP_HEADER_RE.sub("", raw_content).strip()
        if cleaned:
            limit = generic_error_chars if is_error_signal else generic_normal_chars
            head_ratio = 0.5 if is_error_signal else 0.65
            parts.append(truncate_head_tail(cleaned, limit, head_ratio=head_ratio))
        if tool_summary:
            parts.append(f"[tools] {truncate_head_tail(tool_summary, 300, head_ratio=0.8)}")

    if not parts:
        return None

    line_idx_val = raw.get(LINE_IDX_KEY)
    line_idx = line_idx_val if isinstance(line_idx_val, int) else -1
    raw_truncated = raw.get("truncated_fields")
    truncated_fields = (
        tuple(str(item) for item in raw_truncated)
        if isinstance(raw_truncated, list)
        else ()
    )

    body = mask_secrets("\n".join(parts))
    return TranscriptStep(
        step_index=step_index_val,
        source=source,
        step_type=step_type,
        status=status,
        created_at=created_at,
        is_error_signal=is_error_signal,
        normalized_text=body,
        raw_content=raw_content,
        tool_summary=tool_summary,
        thinking_excerpt=thinking_excerpt,
        line_idx=line_idx,
        truncated_fields=truncated_fields,
    )


def load_transcript_raw_rows(path: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """transcript.jsonl を読み込み、正常な JSON オブジェクト行と警告一覧を返す。"""
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line_no, raw_line in enumerate(fh, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                warnings.append(f"L{line_no}: JSON パースに失敗した行をスキップしました ({exc.msg})")
                continue
            if not isinstance(obj, dict):
                warnings.append(f"L{line_no}: JSON オブジェクトではない行をスキップしました")
                continue
            obj[LINE_IDX_KEY] = line_no - 1
            rows.append(obj)
    return rows, warnings


def resolve_transcript_path(
    *,
    transcript: str | None,
    conversation_id: str | None,
    latest: bool,
    app_data_dir: Path,
) -> Path:
    """CLI 引数から対象の transcript.jsonl パスを解決する。"""
    if transcript:
        if decision_hygiene.is_blocked_env_path(transcript):
            raise ValueError(
                f"機密環境ファイル (.env) は --transcript に指定できません: {transcript}"
            )
        path = Path(transcript).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"transcript ファイルが見つかりません: {path}")
        return path

    brain_dir = app_data_dir / "brain"
    if conversation_id:
        path = brain_dir / conversation_id / ".system_generated" / "logs" / "transcript.jsonl"
        if not path.is_file():
            raise FileNotFoundError(
                f"指定された conversation-id の transcript.jsonl が見つかりません: {path}"
            )
        return path

    if latest:
        if not brain_dir.is_dir():
            raise FileNotFoundError(f"brain ディレクトリが見つかりません: {brain_dir}")
        candidates: list[tuple[float, Path]] = []
        for entry in brain_dir.iterdir():
            if not entry.is_dir():
                continue
            cand = entry / ".system_generated" / "logs" / "transcript.jsonl"
            if cand.is_file():
                try:
                    candidates.append((cand.stat().st_mtime, cand))
                except OSError:
                    continue
        if not candidates:
            raise FileNotFoundError(f"利用可能な transcript.jsonl が見つかりません: {brain_dir}")
        candidates.sort(key=lambda item: item[0], reverse=True)
        return candidates[0][1]

    raise ValueError("--transcript、--conversation-id、--latest のいずれかを指定してください。")


def format_step_block(step: TranscriptStep) -> str:
    """共有 input に含める 1 ステップ分のテキスト表現を組み立てる。"""
    err_tag = " | ERROR_SIGNAL" if step.is_error_signal else ""
    header = f"[{step.label} | {step.step_type} | {step.source}{err_tag}]"
    return f"{header}\n{step.normalized_text}"


def build_chunks(
    raw_rows: list[dict[str, Any]],
    *,
    keep_recent: int,
    max_chars: int,
    max_chunks: int,
    max_step_chars: int,
    include_thinking: bool,
) -> tuple[list[list[TranscriptStep]], list[TranscriptStep], list[str], int]:
    """ステップを正規化し、直近保護と文字数バジェット圧縮・チャンク分割を行う。

    戻り値: (評価チャンク一覧, 直近保護ステップ一覧, 警告一覧, 切り捨てた古いステップ数)
    """
    warnings: list[str] = []
    generic_tiers = (DEFAULT_GENERIC_NORMAL_CHARS, 180, 90)
    selected_steps: list[TranscriptStep] = []

    for tier_idx, generic_limit in enumerate(generic_tiers):
        steps = [
            step
            for row in raw_rows
            if (
                step := normalize_step(
                    row,
                    max_step_chars=max_step_chars,
                    generic_normal_chars=generic_limit,
                    generic_error_chars=DEFAULT_GENERIC_ERROR_CHARS,
                    include_thinking=include_thinking,
                )
            )
            is not None
        ]
        selected_steps = steps
        eval_preview = steps[:-keep_recent] if keep_recent > 0 and len(steps) > keep_recent else (
            [] if keep_recent > 0 else steps
        )
        total_chars = sum(len(format_step_block(s)) + 2 for s in eval_preview)
        if total_chars <= max_chars:
            if tier_idx > 0:
                warnings.append(
                    f"文字数バジェット内に収めるため GENERIC 通常出力の抜粋上限を {generic_limit} 文字へ圧縮しました。"
                )
            break

    if keep_recent > 0:
        recent_steps = selected_steps[-keep_recent:]
        eval_steps = selected_steps[:-keep_recent]
    else:
        recent_steps = []
        eval_steps = selected_steps

    if not eval_steps:
        return [], recent_steps, warnings, 0

    chunks: list[list[TranscriptStep]] = []
    current_chunk: list[TranscriptStep] = []
    current_chars = 0

    for step in eval_steps:
        block_len = len(format_step_block(step)) + 2
        if current_chunk and (
            current_chars + block_len > max_chars
            or len(current_chunk) >= MAX_QUESTIONS_PER_REQUEST
        ):
            chunks.append(current_chunk)
            current_chunk = []
            current_chars = 0
        current_chunk.append(step)
        current_chars += block_len

    if current_chunk:
        chunks.append(current_chunk)

    truncated_old_steps = 0
    if len(chunks) > max_chunks:
        dropped_chunks = chunks[:-max_chunks]
        truncated_old_steps = sum(len(c) for c in dropped_chunks)
        chunks = chunks[-max_chunks:]
        warnings.append(
            f"チャンク数が上限 ({max_chunks}) を超えたため、古い {truncated_old_steps} ステップを評価対象から除外しました。"
        )

    return chunks, recent_steps, warnings, truncated_old_steps


def build_decision_payload(
    chunk: list[TranscriptStep],
    *,
    model: str = DEFAULT_MODEL,
) -> dict[str, Any]:
    """1 チャンク分の Decisions API リクエストペイロードを構築する。"""
    input_text = "\n\n".join(format_step_block(step) for step in chunk)
    questions: dict[str, Any] = {}
    for step in chunk:
        questions[step.question_key] = {
            "type": "choice",
            "instructions": (
                f"[{step.label}] は次のセッションへ引き継ぐべき重要情報を含みますか？"
                "会話全体の流れを踏まえ、最も当てはまる区分を1つ選んでください。"
            ),
            "criteria": dict(STEP_CHOICE_CRITERIA),
        }
    return {
        "model": model,
        "input": input_text,
        "questions": questions,
    }


def classify_chunk_answers(
    chunk: list[TranscriptStep],
    enriched_response: dict[str, Any],
    *,
    min_confidence: float,
) -> list[ClassifiedStep]:
    """API 応答をステップごとの分類結果へマッピングする。"""
    answers = enriched_response.get("answers", {})
    results: list[ClassifiedStep] = []
    for step in chunk:
        ans = answers.get(step.question_key)
        if not isinstance(ans, dict):
            results.append(
                ClassifiedStep(
                    step=step,
                    choice="drop_noise",
                    confidence=0.0,
                    probabilities={},
                    is_borderline=True,
                )
            )
            continue
        choice = str(ans.get("choice") or "drop_noise")
        confidence = float(ans.get("confidence") or 0.0)
        raw_probs = ans.get("probabilities")
        probs = (
            {str(k): float(v) for k, v in raw_probs.items()}
            if isinstance(raw_probs, dict)
            else {}
        )
        is_borderline = choice == "drop_noise" and confidence < min_confidence
        results.append(
            ClassifiedStep(
                step=step,
                choice=choice,
                confidence=confidence,
                probabilities=probs,
                is_borderline=is_borderline,
            )
        )
    return results


def conversation_id_from_path(path: Path) -> str:
    """transcript.jsonl の格納パスから conversation_id を推定する。"""
    if (
        path.name == "transcript.jsonl"
        and len(path.parents) >= 3
        and path.parents[0].name == "logs"
        and path.parents[1].name == ".system_generated"
    ):
        return path.parents[2].name
    return ""


def load_full_contents(full_path: Path, line_idxs: set[int]) -> dict[int, str]:
    """transcript_full.jsonl から指定行番号の content のみを遅延抽出する。"""
    if not line_idxs:
        return {}
    contents: dict[int, str] = {}
    with full_path.open("r", encoding="utf-8", errors="replace") as fh:
        for idx, raw_line in enumerate(fh):
            if idx not in line_idxs:
                continue
            line = raw_line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                contents[idx] = str(obj.get("content") or "")
            if len(contents) >= len(line_idxs):
                break
    return contents


def attach_full_excerpts(
    classified: list[ClassifiedStep],
    transcript_path: Path,
    warnings: list[str],
) -> None:
    """切り詰められた重要エラー出力に限り transcript_full.jsonl から完全版の抜粋を補う。"""
    targets = [
        c.step
        for c in classified
        if c.choice in ("keep_decision", "keep_gotcha")
        and c.step.line_idx >= 0
        and c.step.is_error_signal
        and "content" in c.step.truncated_fields
    ]
    if not targets:
        return

    full_path = transcript_path.with_name("transcript_full.jsonl")
    try:
        same_file = full_path == transcript_path or (
            full_path.exists()
            and transcript_path.exists()
            and full_path.resolve() == transcript_path.resolve()
        )
    except OSError:
        same_file = full_path == transcript_path

    if same_file or not full_path.is_file():
        warnings.append(
            f"transcript_full.jsonl が参照できないため、切り詰められたエラー出力の完全版取得をスキップしました: {full_path}"
        )
        return

    try:
        full_contents = load_full_contents(full_path, {s.line_idx for s in targets})
    except (OSError, UnicodeDecodeError) as exc:
        warnings.append(
            mask_secrets(f"transcript_full.jsonl の読み込みに失敗しました ({exc})")
        )
        return

    missing: list[int] = []
    for step in targets:
        raw_text = full_contents.get(step.line_idx, "")
        if not raw_text.strip():
            missing.append(step.line_idx)
            continue
        masked = mask_secrets(raw_text)
        cleaned = TIMESTAMP_HEADER_RE.sub("", masked).strip()
        if cleaned:
            step.full_excerpt = truncate_head_tail(
                cleaned, DEFAULT_FULL_ERROR_CHARS, head_ratio=0.35
            )
        else:
            missing.append(step.line_idx)
    if missing:
        warnings.append(
            f"transcript_full.jsonl で対象行を取得できなかったため短縮版のみ出力しました: line_idx={sorted(missing)}"
        )


def render_markdown(
    *,
    transcript_path: Path,
    conv_id: str = "",
    classified: list[ClassifiedStep],
    recent_steps: list[TranscriptStep],
    warnings: list[str],
    drop_borderline: bool,
    api_calls: int,
    truncated_old_steps: int,
) -> str:
    """session-handoff 入力素材向けの構造化 Markdown を生成する。"""
    decisions = [c for c in classified if c.choice == "keep_decision"]
    gotchas = [c for c in classified if c.choice == "keep_gotcha"]
    states = [c for c in classified if c.choice == "keep_state"]
    borderlines = [c for c in classified if c.is_borderline]
    dropped = [c for c in classified if c.choice == "drop_noise" and not c.is_borderline]
    kept_total = len(decisions) + len(gotchas) + len(states)

    lines: list[str] = [
        "# Transcript Triage Result (Decision 1)",
        "",
        "## Summary",
        f"- transcript: `{transcript_path}`",
        f"- conv_id: `{conv_id}`" if conv_id else "- conv_id: 不明",
        "- 引用形式: (conv_id, line_idx, step_index)（line_idx は 0 始まり、read_file では StartLine=line_idx+1）",
        f"- 評価対象ステップ: {len(classified)} 件（API 呼び出し: {api_calls} 回）",
        f"- 保持判定: {kept_total} 件（Decisions: {len(decisions)} / Gotchas: {len(gotchas)} / Active State: {len(states)}）",
        f"- 境界候補（低信頼度 drop_noise）: {len(borderlines)} 件",
        f"- 除外判定（drop_noise）: {len(dropped)} 件",
        f"- 直近保護ステップ: {len(recent_steps)} 件",
    ]
    if truncated_old_steps > 0:
        lines.append(f"- チャンク上限超過による未評価ステップ: {truncated_old_steps} 件")
    for warn in warnings:
        lines.append(f"- 警告: {warn}")

    def format_step_tag(step: TranscriptStep) -> str:
        if step.line_idx >= 0:
            return f"[STEP {step.step_index:04d} | line_idx={step.line_idx}]"
        return f"[STEP {step.step_index:04d}]"

    def append_classified_section(
        title: str, items: list[ClassifiedStep], excerpt_chars: int
    ) -> None:
        lines.extend(["", f"## {title}"])
        if not items:
            lines.append("- 該当なし")
            return
        for item in items:
            s = item.step
            excerpt = truncate_head_tail(
                s.normalized_text, excerpt_chars, head_ratio=0.7
            ).replace("\n", "\n  ")
            entry = (
                f"- **{format_step_tag(s)}** (`{s.step_type}`, confidence={item.confidence:.2f})\n"
                f"  {excerpt}"
            )
            if s.full_excerpt:
                full_indented = s.full_excerpt.replace("\n", "\n  ")
                entry += f"\n  [transcript_full L{s.line_idx}] {full_indented}"
            lines.append(entry)

    append_classified_section(
        "Decisions（確定仕様・方針候補）", decisions, DEFAULT_RENDER_EXCERPT_CHARS
    )
    append_classified_section(
        "Gotchas（失敗・制約候補）", gotchas, DEFAULT_RENDER_EXCERPT_CHARS
    )
    append_classified_section(
        "Active State（現在地・未完了候補）", states, DEFAULT_RENDER_COMPACT_CHARS
    )
    if not drop_borderline and borderlines:
        append_classified_section(
            "Borderline（低信頼度の除外候補）", borderlines, DEFAULT_RENDER_COMPACT_CHARS
        )

    lines.extend(["", "## Recent Steps（直近保護ステップ）"])
    if not recent_steps:
        lines.append("- 該当なし")
    else:
        for s in recent_steps:
            excerpt = truncate_head_tail(
                s.normalized_text, DEFAULT_RENDER_EXCERPT_CHARS, head_ratio=0.7
            ).replace("\n", "\n  ")
            lines.append(f"- **{format_step_tag(s)}** (`{s.step_type}`)\n  {excerpt}")

    return "\n".join(lines) + "\n"


def should_skip_below_threshold(
    *,
    row_count: int,
    file_bytes: int,
    min_steps: int,
    min_bytes: int,
) -> bool:
    """--min-steps と --min-bytes の設定に基づきスキップ対象かを判定する。"""
    if min_steps <= 0 and min_bytes <= 0:
        return False
    below_steps = True if min_steps <= 0 else row_count < min_steps
    below_bytes = True if min_bytes <= 0 else file_bytes < min_bytes
    return below_steps and below_bytes


def render_skipped_markdown(
    *,
    transcript_path: Path,
    row_count: int,
    file_bytes: int,
    min_steps: int,
    min_bytes: int,
    warnings: list[str],
    dry_run: bool = False,
) -> str:
    """しきい値未満スキップ時の構造化 Markdown を生成する。"""
    step_cond = f"{min_steps} 件未満" if min_steps > 0 else "未指定"
    byte_cond = f"{min_bytes} バイト未満" if min_bytes > 0 else "未指定"
    lines: list[str] = [
        "# Transcript Triage Result (Skipped Below Threshold)",
        "",
        "## Summary",
        f"- transcript: `{transcript_path}`",
        f"- 有効ステップ数: {row_count} 件（しきい値: {step_cond}）",
        f"- ファイルサイズ: {file_bytes} バイト（しきい値: {byte_cond}）",
        "- 判定: しきい値を下回ったため Decisions API 呼び出しをスキップしました（API 呼び出し: 0 回）",
        "- 次の一手: 通常の軽量確認のみで引き継ぎメモを作成してください（コンテキスト圧縮後などで強制選別する場合は `--min-steps` と `--min-bytes` を外して再実行してください）。",
    ]
    if dry_run:
        lines.append("- dry_run: true（前処理とペイロード構築前にスキップしました）")
    for warn in warnings:
        lines.append(f"- 警告: {warn}")
    return "\n".join(lines) + "\n"


def render_json_result(
    *,
    transcript_path: Path,
    conv_id: str = "",
    classified: list[ClassifiedStep],
    recent_steps: list[TranscriptStep],
    warnings: list[str],
    drop_borderline: bool,
    api_calls: int,
    truncated_old_steps: int,
    dry_run: bool = False,
    chunk_stats: list[dict[str, Any]] | None = None,
    skipped_below_threshold: bool = False,
    transcript_steps: int | None = None,
    transcript_bytes: int | None = None,
    min_steps: int = 0,
    min_bytes: int = 0,
) -> dict[str, Any]:
    """機械処理用の構造化 JSON 辞書を生成する。"""

    def serialize_classified(item: ClassifiedStep) -> dict[str, Any]:
        data: dict[str, Any] = {
            "step_index": item.step.step_index,
            "line_idx": item.step.line_idx,
            "type": item.step.step_type,
            "source": item.step.source,
            "truncated_fields": list(item.step.truncated_fields),
            "choice": item.choice,
            "confidence": round(item.confidence, 4),
            "is_borderline": item.is_borderline,
            "probabilities": item.probabilities,
            "text": item.step.normalized_text,
        }
        if item.step.full_excerpt:
            data["full_excerpt"] = item.step.full_excerpt
        return data

    def serialize_step(step: TranscriptStep) -> dict[str, Any]:
        data: dict[str, Any] = {
            "step_index": step.step_index,
            "line_idx": step.line_idx,
            "type": step.step_type,
            "source": step.source,
            "truncated_fields": list(step.truncated_fields),
            "is_error_signal": step.is_error_signal,
            "text": step.normalized_text,
        }
        if step.full_excerpt:
            data["full_excerpt"] = step.full_excerpt
        return data

    kept = [c for c in classified if c.choice != "drop_noise"]
    borderline = [c for c in classified if c.is_borderline]
    dropped = [c for c in classified if c.choice == "drop_noise" and not c.is_borderline]

    meta: dict[str, Any] = {
        "transcript_path": str(transcript_path),
        "conv_id": conv_id,
        "dry_run": dry_run,
        "skipped_below_threshold": skipped_below_threshold,
        "api_calls": api_calls,
        "evaluated_steps": len(classified),
        "kept_steps": len(kept),
        "borderline_steps": len(borderline),
        "dropped_steps": len(dropped),
        "recent_steps": len(recent_steps),
        "truncated_old_steps": truncated_old_steps,
        "drop_borderline": drop_borderline,
        "warnings": warnings,
    }
    if transcript_steps is not None:
        meta["transcript_steps"] = transcript_steps
    if transcript_bytes is not None:
        meta["transcript_bytes"] = transcript_bytes
    if min_steps > 0 or min_bytes > 0:
        meta["min_steps"] = min_steps
        meta["min_bytes"] = min_bytes

    result: dict[str, Any] = {
        "meta": meta,
        "kept": [serialize_classified(c) for c in kept],
        "borderline": [] if drop_borderline else [serialize_classified(c) for c in borderline],
        "dropped": [serialize_classified(c) for c in dropped],
        "recent": [serialize_step(s) for s in recent_steps],
    }
    if chunk_stats is not None:
        result["chunks"] = chunk_stats
    return result


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Antigravity transcript.jsonl の重要ステップを Decision 1 で一括選別する CLI"
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--transcript", help="対象 transcript.jsonl のパス")
    src.add_argument("--conversation-id", help="Antigravity の conversationId")
    src.add_argument(
        "--latest",
        action="store_true",
        help="app-data-dir/brain 配下で最新の transcript.jsonl を自動選択する",
    )
    parser.add_argument(
        "--app-data-dir",
        default=None,
        help="Antigravity の App Data Directory（既定: ~/.gemini/antigravity）",
    )
    parser.add_argument(
        "--keep-recent",
        type=int,
        default=DEFAULT_KEEP_RECENT,
        help=f"末尾から無条件保持するステップ数（既定: {DEFAULT_KEEP_RECENT}）",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=DEFAULT_MIN_CONFIDENCE,
        help=f"drop_noise を境界候補へ残す信頼度閾値（既定: {DEFAULT_MIN_CONFIDENCE}）",
    )
    parser.add_argument(
        "--max-chars",
        type=int,
        default=DEFAULT_MAX_CHARS,
        help=f"1 チャンクあたりの共有入力最大文字数（既定: {DEFAULT_MAX_CHARS}）",
    )
    parser.add_argument(
        "--max-chunks",
        type=int,
        default=DEFAULT_MAX_CHUNKS,
        help=f"最大チャンク数（API 呼び出し上限、既定: {DEFAULT_MAX_CHUNKS}）",
    )
    parser.add_argument(
        "--max-step-chars",
        type=int,
        default=DEFAULT_MAX_STEP_CHARS,
        help=f"1 ステップあたりの抜粋上限文字数（既定: {DEFAULT_MAX_STEP_CHARS}）",
    )
    parser.add_argument(
        "--include-thinking",
        action="store_true",
        help="PLANNER_RESPONSE の thinking 抜粋も評価対象に含める",
    )
    parser.add_argument(
        "--drop-borderline",
        action="store_true",
        help="低信頼度の drop_noise（境界候補）も出力から除外する",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="出力形式（既定: markdown）",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help=f"使用する Decisions API モデル（既定: {DEFAULT_MODEL}）",
    )
    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        help=f"Decisions API エンドポイント（既定: {DEFAULT_ENDPOINT}）",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"API タイムアウト秒数（既定: {DEFAULT_TIMEOUT}）",
    )
    parser.add_argument(
        "--min-steps",
        type=int,
        default=0,
        help="評価を実行する最小有効ステップ行数（--min-bytes も未達なら API 非呼び出しでスキップ、既定: 0 で無効）",
    )
    parser.add_argument(
        "--min-bytes",
        type=int,
        default=0,
        help="評価を実行する transcript.jsonl の最小バイト数（--min-steps も未達なら API 非呼び出しでスキップ、既定: 0 で無効）",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="API 呼び出しを行わず前処理とペイロード検証のみ実行する",
    )
    return parser


def main(
    argv: list[str] | None = None,
    *,
    api_caller: Callable[..., dict[str, Any]] | None = None,
) -> int:
    decision_hygiene.configure_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()

    if args.keep_recent < 0:
        print("エラー: --keep-recent は 0 以上を指定してください。", file=sys.stderr)
        return 2
    if args.min_steps < 0 or args.min_bytes < 0:
        print("エラー: --min-steps と --min-bytes は 0 以上を指定してください。", file=sys.stderr)
        return 2
    if not (0.0 <= args.min_confidence <= 1.0):
        print("エラー: --min-confidence は 0.0 から 1.0 の範囲で指定してください。", file=sys.stderr)
        return 2
    if args.max_chars < 1000 or args.max_chunks < 1:
        print("エラー: --max-chars は 1000 以上、--max-chunks は 1 以上を指定してください。", file=sys.stderr)
        return 2

    try:
        app_data_dir = (
            Path(args.app_data_dir).expanduser()
            if args.app_data_dir
            else (Path.home() / ".gemini" / "antigravity" if not args.transcript else Path("."))
        )
        transcript_path = resolve_transcript_path(
            transcript=args.transcript,
            conversation_id=args.conversation_id,
            latest=args.latest,
            app_data_dir=app_data_dir,
        )
        file_bytes = transcript_path.stat().st_size
        conv_id = args.conversation_id or conversation_id_from_path(transcript_path)
        raw_rows, parse_warnings = load_transcript_raw_rows(transcript_path)
        json_meta_kwargs: dict[str, Any] = {
            "transcript_path": transcript_path,
            "conv_id": conv_id,
            "drop_borderline": args.drop_borderline,
            "transcript_steps": len(raw_rows),
            "transcript_bytes": file_bytes,
            "min_steps": args.min_steps,
            "min_bytes": args.min_bytes,
        }
        skip_threshold = should_skip_below_threshold(
            row_count=len(raw_rows),
            file_bytes=file_bytes,
            min_steps=args.min_steps,
            min_bytes=args.min_bytes,
        )
        chunks: list[list[TranscriptStep]] = []
        recent_steps: list[TranscriptStep] = []
        warnings: list[str] = list(parse_warnings)
        truncated_old = 0
        payloads: list[dict[str, Any]] = []
        chunk_stats: list[dict[str, Any]] = []
        if not skip_threshold:
            chunks, recent_steps, chunk_warnings, truncated_old = build_chunks(
                raw_rows,
                keep_recent=args.keep_recent,
                max_chars=args.max_chars,
                max_chunks=args.max_chunks,
                max_step_chars=args.max_step_chars,
                include_thinking=args.include_thinking,
            )
            warnings = parse_warnings + chunk_warnings
            for idx, chunk in enumerate(chunks, start=1):
                payload = build_decision_payload(chunk, model=args.model)
                validation_errors = run_decisions.validate_payload(payload)
                if validation_errors:
                    print(
                        mask_secrets(
                            f"エラー: チャンク {idx} のペイロード検証に失敗しました:\n"
                            + "\n".join(f"- {e}" for e in validation_errors),
                            secret=api_key,
                        ),
                        file=sys.stderr,
                    )
                    return 2
                payloads.append(payload)
                chunk_stats.append(
                    {
                        "chunk_index": idx,
                        "step_count": len(chunk),
                        "step_range": [chunk[0].step_index, chunk[-1].step_index],
                        "input_chars": len(payload["input"]),
                        "question_count": len(payload["questions"]),
                    }
                )
    except Exception as exc:  # noqa: BLE001
        print(mask_secrets(f"エラー: {exc}", secret=api_key), file=sys.stderr)
        return 2

    if skip_threshold:
        if args.format == "json":
            out = render_json_result(
                **json_meta_kwargs,
                classified=[],
                recent_steps=[],
                warnings=parse_warnings,
                api_calls=0,
                truncated_old_steps=0,
                dry_run=args.dry_run,
                skipped_below_threshold=True,
            )
            print(json.dumps(out, ensure_ascii=False, indent=2))
        else:
            print(
                render_skipped_markdown(
                    transcript_path=transcript_path,
                    row_count=len(raw_rows),
                    file_bytes=file_bytes,
                    min_steps=args.min_steps,
                    min_bytes=args.min_bytes,
                    warnings=parse_warnings,
                    dry_run=args.dry_run,
                ),
                end="",
            )
        return 0

    if args.dry_run:
        if args.format == "json":
            out = render_json_result(
                **json_meta_kwargs,
                classified=[],
                recent_steps=recent_steps,
                warnings=warnings,
                api_calls=0,
                truncated_old_steps=truncated_old,
                dry_run=True,
                chunk_stats=chunk_stats,
            )
            print(json.dumps(out, ensure_ascii=False, indent=2))
        else:
            total_eval = sum(c["step_count"] for c in chunk_stats)
            total_chars = sum(c["input_chars"] for c in chunk_stats)
            print("# Transcript Triage Dry-Run")
            print(f"- transcript: `{transcript_path}`")
            print(f"- 総行数（有効 JSON）: {len(raw_rows)} 件（サイズ: {file_bytes} バイト）")
            print(f"- 評価対象ステップ: {total_eval} 件（チャンク数: {len(chunk_stats)}、合計入力文字数: {total_chars}）")
            print(f"- 直近保護ステップ: {len(recent_steps)} 件")
            for stat in chunk_stats:
                print(
                    f"  - Chunk {stat['chunk_index']}: steps={stat['step_count']} "
                    f"(STEP {stat['step_range'][0]:04d}..{stat['step_range'][1]:04d}), "
                    f"input_chars={stat['input_chars']}, questions={stat['question_count']}"
                )
            for warn in warnings:
                print(f"- 警告: {warn}")
            print("- ペイロード検証: OK")
        return 0

    if not chunks:
        if args.format == "json":
            out = render_json_result(
                **json_meta_kwargs,
                classified=[],
                recent_steps=recent_steps,
                warnings=warnings,
                api_calls=0,
                truncated_old_steps=truncated_old,
            )
            print(json.dumps(out, ensure_ascii=False, indent=2))
        else:
            print(
                render_markdown(
                    transcript_path=transcript_path,
                    conv_id=conv_id,
                    classified=[],
                    recent_steps=recent_steps,
                    warnings=warnings,
                    drop_borderline=args.drop_borderline,
                    api_calls=0,
                    truncated_old_steps=truncated_old,
                ),
                end="",
            )
        return 0

    if not api_key and api_caller is None:
        print(
            "エラー: 環境変数 GEMINI_API_KEY が未設定です。従来の手動 session-handoff 手順へフォールバックしてください。",
            file=sys.stderr,
        )
        return 3

    caller = api_caller or run_decisions.call_decisions_api
    all_classified: list[ClassifiedStep] = []
    api_calls = 0

    for idx, (chunk, payload) in enumerate(zip(chunks, payloads), start=1):
        try:
            raw_resp = caller(
                payload,
                api_key=api_key,
                endpoint=args.endpoint,
                timeout=args.timeout,
            )
            enriched = run_decisions.enrich_response(raw_resp, min_confidence=args.min_confidence)
        except run_decisions.SafetyBlockError as exc:
            print(
                mask_secrets(
                    f"エラー: チャンク {idx} が安全フィルタにより遮断されました ({exc})。"
                    "従来の手動 session-handoff 手順へフォールバックしてください。",
                    secret=api_key,
                ),
                file=sys.stderr,
            )
            return 3
        except run_decisions.ApiRequestError as exc:
            print(
                mask_secrets(
                    f"エラー: チャンク {idx} の Decisions API 呼び出しに失敗しました ({exc})。"
                    "従来の手動 session-handoff 手順へフォールバックしてください。",
                    secret=api_key,
                ),
                file=sys.stderr,
            )
            return 3
        api_calls += 1
        all_classified.extend(
            classify_chunk_answers(chunk, enriched, min_confidence=args.min_confidence)
        )

    attach_full_excerpts(all_classified, transcript_path, warnings)

    if args.format == "json":
        out = render_json_result(
            **json_meta_kwargs,
            classified=all_classified,
            recent_steps=recent_steps,
            warnings=warnings,
            api_calls=api_calls,
            truncated_old_steps=truncated_old,
        )
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print(
            render_markdown(
                transcript_path=transcript_path,
                conv_id=conv_id,
                classified=all_classified,
                recent_steps=recent_steps,
                warnings=warnings,
                drop_borderline=args.drop_borderline,
                api_calls=api_calls,
                truncated_old_steps=truncated_old,
            ),
            end="",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
