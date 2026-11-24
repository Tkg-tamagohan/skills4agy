#!/usr/bin/env python3
"""pr-review-triage Stage 1 一次トリアージ CLI。

PR の未 Resolve スレッドとレビュー総評コメントを入力 JSON 配列として受け取り、
送信前の機密検出・文字数ガード・ペイロード検証を行った上で、
Gemini Decision 1（run_decisions.py 経由）で並列プリラベルする。
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
from typing import Any, Callable

_DECISIONS_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "gemini-decisions-api" / "scripts"
if str(_DECISIONS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_DECISIONS_SCRIPTS_DIR))

import decision_common  # noqa: E402
import decision_hygiene  # noqa: E402
import run_decisions  # noqa: E402

DEFAULT_MODEL = run_decisions.DEFAULT_MODEL
DEFAULT_ENDPOINT = run_decisions.DEFAULT_ENDPOINT
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_WORKERS = 4
DEFAULT_MAX_CHARS = 50_000
DEFAULT_MIN_CONFIDENCE = 0.80
DEFAULT_HUMAN_CONFIRM_THRESHOLD = 0.50

VALID_SOURCES = frozenset({"review_thread", "review_body"})

TRIAGE_BUCKET_CRITERIA: dict[str, str] = {
    "unfixed_reproduces": (
        "The issue pointed out by the review comment still reproduces in the current code and remains unfixed."
    ),
    "partial_followup": (
        "The main point has largely been addressed, but residual risk, edge cases, or follow-up work remain."
    ),
    "already_resolved": (
        "The review comment has already been completely resolved in the current code and recent commits."
    ),
    "needs_spec_decision": (
        "Addressing or dismissing the review comment requires a specification policy choice or explicit user decision."
    ),
    "other": (
        "Insufficient context to classify accurately, or none of the other categories apply."
    ),
}

NEEDS_HUMAN_CONFIRMATION_INSTRUCTIONS = (
    "Does addressing or resolving this review comment require user confirmation "
    "on specification policy or auto-resolve permission?"
)

NEEDS_HUMAN_CONFIRMATION_CRITERIA: dict[str, str] = {
    "true_description": (
        "Addressing or resolving this comment requires user confirmation on specification policy, "
        "design trade-offs, or auto-resolve permission."
    ),
    "false_description": (
        "The fix or resolution status can be verified directly from code and commits without policy confirmation."
    ),
}

SEVERITY_CRITERIA: list[str] = [
    "0: nit or style",
    "1: minor clarity or maintainability",
    "2: functional bug or edge case",
    "3: security, data loss, or concurrency defect",
]

DISPATCH_MODE_CRITERIA: dict[str, str] = {
    "single_session": (
        "Can be resolved or closed in a single focused session with small, localized edits or thread-only cleanup."
    ),
    "boost_deep": (
        "Requires deep single-thread reasoning, root-cause debugging, or delicate invariant verification across tightly coupled modules."
    ),
    "swarm_parallel": (
        "Splits cleanly into multiple independent files or modules that benefit from parallel workers with exclusive file boundaries."
    ),
    "plan_first": (
        "Requires specification alignment, design decisions, or explicit user confirmation before writing code."
    ),
    "other": (
        "Insufficient context to recommend an execution mode, or none of the above apply."
    ),
}

SECRET_PATTERNS = decision_hygiene.SECRET_DETECT_PATTERNS


class TriageError(RuntimeError):
    """トリアージ処理中の検証・実行エラー。"""

    def __init__(self, code: str, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code


def mask_secret(text: str, secret: str | None = None) -> str:
    """エラー出力等から API キーおよび秘密トークン実値をマスクする。"""
    return decision_hygiene.mask_secret(text, secret)


def scan_text_for_secrets(text: str) -> list[str]:
    """テキスト内に含まれる秘密情報パターンのラベル一覧を返す（実値は返さない）。"""
    return decision_hygiene.scan_text_for_secrets(text, patterns=SECRET_PATTERNS)


def _format_recent_commits(recent_commits: Any) -> str:
    """任意の recent_commits フィールドをテキストへ正規化する。"""
    if recent_commits is None:
        return ""
    if isinstance(recent_commits, str):
        return recent_commits.strip()
    if isinstance(recent_commits, list):
        lines: list[str] = []
        for idx, entry in enumerate(recent_commits):
            if isinstance(entry, str):
                cleaned = entry.strip()
                if cleaned:
                    lines.append(f"- {cleaned}")
            elif isinstance(entry, dict):
                lines.append(f"- {json.dumps(entry, ensure_ascii=False)}")
            else:
                raise TriageError(
                    "invalid_input_schema",
                    f"recent_commits[{idx}] は文字列またはオブジェクトである必要があります。",
                )
        return "\n".join(lines)
    raise TriageError(
        "invalid_input_schema",
        "recent_commits は文字列または配列である必要があります。",
    )


def normalize_review_items(raw_items: Any) -> list[dict[str, Any]]:
    """入力 JSON 配列を検証し、正規化済みレビュー項目リストを返す。"""
    if not isinstance(raw_items, list):
        raise TriageError(
            "invalid_input_schema",
            "入力 JSON のトップレベルはレビュー指摘の配列である必要があります。",
        )

    normalized: list[dict[str, Any]] = []
    for idx, raw in enumerate(raw_items):
        prefix = f"items[{idx}]"
        if not isinstance(raw, dict):
            raise TriageError("invalid_input_schema", f"{prefix} は JSON オブジェクトである必要があります。")

        raw_id = raw.get("id")
        if isinstance(raw_id, bool) or raw_id is None or not str(raw_id).strip():
            raise TriageError("invalid_input_schema", f"{prefix}.id は空でない文字列または整数が必要です。")
        item_id = str(raw_id).strip()

        source = raw.get("source")
        if not isinstance(source, str) or source not in VALID_SOURCES:
            raise TriageError(
                "invalid_input_schema",
                f"{prefix}.source は 'review_thread' または 'review_body' を指定してください。",
            )

        path = raw.get("path")
        if path is not None and not isinstance(path, str):
            raise TriageError("invalid_input_schema", f"{prefix}.path は文字列または null である必要があります。")

        line = raw.get("line")
        if line is not None and (isinstance(line, bool) or not isinstance(line, int) or line < 0):
            raise TriageError(
                "invalid_input_schema",
                f"{prefix}.line は 0 以上の整数または null である必要があります。",
            )

        comment_body = raw.get("comment_body")
        if not isinstance(comment_body, str) or not comment_body.strip():
            raise TriageError(
                "invalid_input_schema",
                f"{prefix}.comment_body は空でない文字列である必要があります。",
            )

        code_snippet = raw.get("code_snippet")
        if code_snippet is not None and not isinstance(code_snippet, str):
            raise TriageError(
                "invalid_input_schema",
                f"{prefix}.code_snippet は文字列または null である必要があります。",
            )

        recent_commits_text = _format_recent_commits(raw.get("recent_commits"))

        normalized.append(
            {
                "id": item_id,
                "source": source,
                "path": path.strip() if isinstance(path, str) and path.strip() else None,
                "line": line,
                "comment_body": comment_body,
                "code_snippet": code_snippet if code_snippet else None,
                "recent_commits_text": recent_commits_text,
            }
        )
    return normalized


def build_item_input_text(item: dict[str, Any]) -> str:
    """1 件のレビュー指摘から Decisions API 用の単一テキスト入力を組み立てる。"""
    parts = [
        f"Review Item ID: {item['id']}\n",
        f"Source: {item['source']}\n",
        f"Path: {item['path'] or '(none)'}\n",
        f"Line: {item['line'] if item['line'] is not None else '(none)'}\n",
        f"\nReview Comment:\n{item['comment_body']}\n",
    ]
    if item.get("code_snippet"):
        parts.append(f"\nCode Snippet:\n```\n{item['code_snippet']}\n```\n")
    if item.get("recent_commits_text"):
        parts.append(f"\nRecent Commits:\n{item['recent_commits_text']}\n")
    return "".join(parts)


def check_item_secrets(item: dict[str, Any], input_text: str) -> None:
    """送信前に各項目のフィールドと構築済みテキストの秘密情報混入を検査する。"""
    fields_to_check = (
        ("id", item["id"]),
        ("path", item.get("path") or ""),
        ("comment_body", item["comment_body"]),
        ("code_snippet", item.get("code_snippet") or ""),
        ("recent_commits", item.get("recent_commits_text") or ""),
        ("input_text", input_text),
    )
    for field_name, value in fields_to_check:
        if not value:
            continue
        labels = scan_text_for_secrets(value)
        if labels:
            joined = ", ".join(labels)
            raise TriageError(
                "secret_detected",
                f"指摘 {item['id']} の {field_name} に秘密情報パターン（{joined}）が含まれているため送信を遮断しました。",
                exit_code=2,
            )


def build_triage_questions() -> dict[str, dict[str, Any]]:
    """Stage 1 一次トリアージ用の 4 問マップを構築する。"""
    return {
        "triage_bucket": {
            "type": "choice",
            "instructions": (
                "Classify the current triage status of this PR review comment based on the "
                "comment body, current code snippet, and recent commits."
            ),
            "criteria": dict(TRIAGE_BUCKET_CRITERIA),
        },
        "needs_human_confirmation": {
            "type": "noul",
            "instructions": NEEDS_HUMAN_CONFIRMATION_INSTRUCTIONS,
            "criteria": dict(NEEDS_HUMAN_CONFIRMATION_CRITERIA),
        },
        "severity": {
            "type": "score",
            "instructions": "Evaluate the severity of the issue raised in this PR review comment.",
            "criteria": list(SEVERITY_CRITERIA),
        },
        "dispatch_mode": {
            "type": "choice",
            "instructions": (
                "Select the most appropriate execution mode to address or resolve this "
                "PR review comment based on its scope, complexity, and specification needs."
            ),
            "criteria": dict(DISPATCH_MODE_CRITERIA),
        },
    }


def build_item_payload(
    item: dict[str, Any],
    *,
    model: str = DEFAULT_MODEL,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> dict[str, Any]:
    """1 件の指摘を検証して Decisions API ペイロードを構築する。"""
    input_text = build_item_input_text(item)
    check_item_secrets(item, input_text)

    if len(input_text) > max_chars:
        raise TriageError(
            "input_size_limit_exceeded",
            (
                f"指摘 {item['id']} の入力文字数（{len(input_text):,} 文字）が上限 "
                f"{max_chars:,} 文字を超えています。code_snippet や recent_commits を絞って再実行してください。"
            ),
            exit_code=2,
        )

    payload: dict[str, Any] = {
        "model": model,
        "input": [{"type": "text", "text": input_text}],
        "questions": build_triage_questions(),
    }
    errors = run_decisions.validate_payload(payload)
    if errors:
        raise TriageError(
            "payload_validation_failed",
            "ペイロード検証に失敗しました: " + "; ".join(errors),
            exit_code=2,
        )
    return payload


_is_real_number = decision_common.is_real_number


def evaluate_item_response(
    item: dict[str, Any],
    enriched: dict[str, Any],
    *,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    human_threshold: float = DEFAULT_HUMAN_CONFIRM_THRESHOLD,
) -> dict[str, Any]:
    """enrich_response 後の応答を解釈し、信頼度分岐と深掘りフラグを付与する。"""
    answers = enriched.get("answers")
    if not isinstance(answers, dict):
        answers = {}

    bucket_ans = answers.get("triage_bucket") if isinstance(answers.get("triage_bucket"), dict) else {}
    human_ans = (
        answers.get("needs_human_confirmation")
        if isinstance(answers.get("needs_human_confirmation"), dict)
        else {}
    )
    sev_ans = answers.get("severity") if isinstance(answers.get("severity"), dict) else {}
    dispatch_ans = answers.get("dispatch_mode") if isinstance(answers.get("dispatch_mode"), dict) else {}

    bucket = bucket_ans.get("choice")
    bucket_conf_raw = bucket_ans.get("confidence")
    bucket_conf = float(bucket_conf_raw) if _is_real_number(bucket_conf_raw) else None

    human_prob_raw = human_ans.get("noul")
    human_prob = float(human_prob_raw) if _is_real_number(human_prob_raw) else None
    human_conf_raw = human_ans.get("confidence")
    human_conf = float(human_conf_raw) if _is_real_number(human_conf_raw) else None

    sev_score_raw = sev_ans.get("score")
    sev_score = float(sev_score_raw) if _is_real_number(sev_score_raw) else None
    sev_conf_raw = sev_ans.get("confidence")
    sev_conf = float(sev_conf_raw) if _is_real_number(sev_conf_raw) else None

    top_level = sev_ans.get("top_level")
    top_label = sev_ans.get("top_level_label")
    if top_label is None and isinstance(top_level, str) and top_level.isdigit():
        idx = int(top_level)
        if 0 <= idx < len(SEVERITY_CRITERIA):
            top_label = SEVERITY_CRITERIA[idx]
    norm_score = sev_ans.get("normalized_score")
    if norm_score is None and sev_score is not None and len(SEVERITY_CRITERIA) >= 2:
        norm_score = round(sev_score / (len(SEVERITY_CRITERIA) - 1), 4)

    dispatch_mode = dispatch_ans.get("choice") if isinstance(dispatch_ans.get("choice"), str) else None
    dispatch_conf_raw = dispatch_ans.get("confidence")
    dispatch_conf = float(dispatch_conf_raw) if _is_real_number(dispatch_conf_raw) else None

    escalation_reasons: list[str] = []
    if not isinstance(bucket, str) or bucket not in TRIAGE_BUCKET_CRITERIA:
        escalation_reasons.append("missing_triage_bucket")
    else:
        if bucket == "other":
            escalation_reasons.append("bucket_other")
        if bucket_conf is None:
            escalation_reasons.append("missing_confidence")
        elif bucket_conf < min_confidence:
            escalation_reasons.append("low_confidence")

    if human_prob is None:
        escalation_reasons.append("missing_human_confirmation")
    elif human_prob >= human_threshold:
        escalation_reasons.append("human_confirmation_required")

    needs_deep_review = bool(escalation_reasons)

    result: dict[str, Any] = {
        "id": item["id"],
        "source": item["source"],
        "path": item["path"],
        "line": item["line"],
        "triage_bucket": bucket,
        "triage_confidence": bucket_conf,
        "needs_human_confirmation": human_prob,
        "human_confirmation_confidence": human_conf,
        "severity": sev_score,
        "severity_top_level": top_level,
        "severity_label": top_label,
        "severity_normalized": norm_score,
        "severity_confidence": sev_conf,
        "dispatch_mode": dispatch_mode,
        "dispatch_confidence": dispatch_conf,
        "needs_deep_review": needs_deep_review,
        "escalation_reasons": escalation_reasons,
        "answers": answers,
    }
    if "usage" in enriched:
        result["usage"] = enriched["usage"]
    return result


_sanitize_cell = decision_common.escape_md_cell


def _format_location(path: str | None, line: int | None) -> str:
    if path and line is not None:
        return f"{path}:{line}"
    if path:
        return path
    return "-"


def format_triage_table(report: dict[str, Any]) -> str:
    """トリアージ結果を Markdown 表形式の UTF-8 文字列へ整形する。"""
    if report.get("status") == "dry_run":
        lines = [
            "| id | source | location | input_chars | model | questions |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for entry in report.get("items") or []:
            payload = entry.get("payload") or {}
            input_chars = sum(len(b.get("text", "")) for b in payload.get("input") or [])
            q_count = len(payload.get("questions") or {})
            loc = _format_location(entry.get("path"), entry.get("line"))
            lines.append(
                f"| {_sanitize_cell(entry.get('id'))} | {_sanitize_cell(entry.get('source'))} "
                f"| {_sanitize_cell(loc)} | {input_chars} | {_sanitize_cell(payload.get('model'))} | {q_count} |"
            )
        lines.append("")
        lines.append(f"dry_run: item_count={report.get('item_count', 0)}")
        return "\n".join(lines)

    lines = [
        "| id | source | location | triage_bucket | confidence | human_confirm | severity | dispatch | needs_deep_review | reason |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for entry in report.get("items") or []:
        loc = _format_location(entry.get("path"), entry.get("line"))
        conf = entry.get("triage_confidence")
        conf_str = f"{float(conf):.2f}" if _is_real_number(conf) else "-"
        human = entry.get("needs_human_confirmation")
        human_str = f"{float(human):.2f}" if _is_real_number(human) else "-"
        sev = entry.get("severity")
        sev_label = entry.get("severity_label")
        if _is_real_number(sev) and sev_label:
            sev_str = f"{float(sev):.2f} ({sev_label})"
        elif _is_real_number(sev):
            sev_str = f"{float(sev):.2f}"
        else:
            sev_str = "-"
        dispatch_mode = entry.get("dispatch_mode")
        dispatch_conf = entry.get("dispatch_confidence")
        if dispatch_mode and _is_real_number(dispatch_conf):
            dispatch_str = f"{dispatch_mode} ({float(dispatch_conf):.2f})"
        elif dispatch_mode:
            dispatch_str = str(dispatch_mode)
        else:
            dispatch_str = "-"
        deep_str = "true" if entry.get("needs_deep_review") else "false"
        reasons = ", ".join(entry.get("escalation_reasons") or []) or "-"
        lines.append(
            f"| {_sanitize_cell(entry.get('id'))} | {_sanitize_cell(entry.get('source'))} "
            f"| {_sanitize_cell(loc)} | {_sanitize_cell(entry.get('triage_bucket'))} "
            f"| {conf_str} | {human_str} | {_sanitize_cell(sev_str)} "
            f"| {_sanitize_cell(dispatch_str)} | {deep_str} "
            f"| {_sanitize_cell(reasons)} |"
        )

    lines.append("")
    lines.append(
        f"summary: total={report.get('item_count', 0)}, "
        f"prelabeled={report.get('prelabeled_count', 0)}, "
        f"deep_review={report.get('deep_review_count', 0)}"
    )
    return "\n".join(lines)


def triage_items_parallel(
    prepared: list[tuple[dict[str, Any], dict[str, Any]]],
    *,
    api_key: str,
    endpoint: str = DEFAULT_ENDPOINT,
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = DEFAULT_MAX_WORKERS,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    human_threshold: float = DEFAULT_HUMAN_CONFIRM_THRESHOLD,
    opener: Callable[..., Any] | None = None,
) -> list[dict[str, Any]]:
    """準備済みアイテム群を並列に Decisions API へ送信し、入力順を保持して返す。"""
    if not prepared:
        return []

    def process_one(item: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
        raw = run_decisions.call_decisions_api(
            payload,
            api_key=api_key,
            endpoint=endpoint,
            timeout=timeout,
            opener=opener,
        )
        enriched = run_decisions.enrich_response(raw, min_confidence=min_confidence)
        return evaluate_item_response(
            item,
            enriched,
            min_confidence=min_confidence,
            human_threshold=human_threshold,
        )

    worker_count = max(1, min(max_workers, len(prepared)))
    results: list[dict[str, Any] | None] = [None] * len(prepared)
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [executor.submit(process_one, item, payload) for item, payload in prepared]
        for idx, future in enumerate(futures):
            results[idx] = future.result()

    return [r for r in results if r is not None]


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PR レビュー指摘を Gemini Decision 1 で並列プリラベルする Stage 1 トリアージ CLI"
    )
    parser.add_argument("--input", default=None, help="レビュー指摘配列を格納した UTF-8 JSON ファイルパス")
    parser.add_argument("--stdin", action="store_true", help="標準入力から UTF-8 JSON 配列を読み込む")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="モデル ID（既定: gemini-decision-1）")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT, help="Decisions API エンドポイント URL")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="HTTP タイムアウト秒数（既定: 30）")
    parser.add_argument(
        "--max-workers",
        type=int,
        default=DEFAULT_MAX_WORKERS,
        help="並列実行ワーカー数上限（既定: 4）",
    )
    parser.add_argument(
        "--max-chars",
        type=int,
        default=DEFAULT_MAX_CHARS,
        help="1 件あたりの入力文字数上限（既定: 50000）",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=DEFAULT_MIN_CONFIDENCE,
        help="プリラベル確定候補の triage_bucket 信頼度下限（既定: 0.80）",
    )
    parser.add_argument(
        "--human-threshold",
        type=float,
        default=DEFAULT_HUMAN_CONFIRM_THRESHOLD,
        help="要人間確認エスカレーションの noul 閾値（既定: 0.50）",
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
        help="API 送信せず検証済みペイロード群を出力して終了する（GEMINI_API_KEY 不要）",
    )
    return parser


def _load_raw_input(args: argparse.Namespace, stdin_text: str | None) -> Any:
    if bool(args.input) == bool(args.stdin):
        raise TriageError(
            "invalid_input_source",
            "--input <path> または --stdin のどちらか一方のみを指定してください。",
            exit_code=2,
        )
    try:
        if args.input:
            if decision_hygiene.is_blocked_env_path(args.input):
                raise TriageError(
                    "secret_env_file",
                    f"機密環境ファイル (.env) は --input に指定できません: {args.input}",
                    exit_code=2,
                )
            raw_text = Path(args.input).read_text(encoding="utf-8")
        else:
            raw_text = stdin_text if stdin_text is not None else sys.stdin.read()
        return json.loads(raw_text)
    except UnicodeDecodeError as exc:
        raise TriageError(
            "invalid_input_encoding",
            f"入力ファイルは UTF-8 としてデコードできません: {exc}",
            exit_code=2,
        ) from exc
    except OSError as exc:
        raise TriageError("input_read_error", f"入力ファイルを読み込めません: {exc}", exit_code=2) from exc
    except json.JSONDecodeError as exc:
        raise TriageError("invalid_json", f"入力 JSON の構文が不正です: {exc}", exit_code=2) from exc


def main(
    argv: list[str] | None = None,
    *,
    opener: Callable[..., Any] | None = None,
    env: dict[str, str] | None = None,
    stdin_text: str | None = None,
) -> int:
    decision_hygiene.configure_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    environ = os.environ if env is None else env
    api_key = environ.get("GEMINI_API_KEY", "").strip()

    try:
        if args.max_workers < 1:
            raise TriageError("invalid_argument", "--max-workers は 1 以上を指定してください。", exit_code=2)
        if args.max_chars < 1:
            raise TriageError("invalid_argument", "--max-chars は 1 以上を指定してください。", exit_code=2)
        if args.timeout <= 0:
            raise TriageError("invalid_argument", "--timeout は 0 より大きい値を指定してください。", exit_code=2)
        if not (0.0 <= args.min_confidence <= 1.0):
            raise TriageError(
                "invalid_argument",
                "--min-confidence は 0.0 から 1.0 の範囲で指定してください。",
                exit_code=2,
            )
        if not (0.0 <= args.human_threshold <= 1.0):
            raise TriageError(
                "invalid_argument",
                "--human-threshold は 0.0 から 1.0 の範囲で指定してください。",
                exit_code=2,
            )

        raw_data = _load_raw_input(args, stdin_text)
        items = normalize_review_items(raw_data)
        prepared: list[tuple[dict[str, Any], dict[str, Any]]] = [
            (item, build_item_payload(item, model=args.model, max_chars=args.max_chars))
            for item in items
        ]

        if args.dry_run:
            dry_report = {
                "status": "dry_run",
                "model": args.model,
                "item_count": len(prepared),
                "items": [
                    {
                        "id": item["id"],
                        "source": item["source"],
                        "path": item["path"],
                        "line": item["line"],
                        "payload": payload,
                    }
                    for item, payload in prepared
                ],
            }
            if args.format == "table":
                print(format_triage_table(dry_report))
            else:
                print(json.dumps(dry_report, ensure_ascii=False, indent=2))
            return 0

        if not prepared:
            empty_report = {
                "status": "ok",
                "model": args.model,
                "item_count": 0,
                "prelabeled_count": 0,
                "deep_review_count": 0,
                "items": [],
            }
            if args.format == "table":
                print(format_triage_table(empty_report))
            else:
                print(json.dumps(empty_report, ensure_ascii=False, indent=2))
            return 0

        if not api_key:
            raise TriageError(
                "missing_api_key",
                (
                    "環境変数 GEMINI_API_KEY が設定されていません。"
                    "API キーを設定するか --dry-run を使用してください。"
                ),
                exit_code=2,
            )

        results = triage_items_parallel(
            prepared,
            api_key=api_key,
            endpoint=args.endpoint,
            timeout=args.timeout,
            max_workers=args.max_workers,
            min_confidence=args.min_confidence,
            human_threshold=args.human_threshold,
            opener=opener,
        )
        deep_count = sum(1 for r in results if r["needs_deep_review"])
        report = {
            "status": "ok",
            "model": args.model,
            "item_count": len(results),
            "prelabeled_count": len(results) - deep_count,
            "deep_review_count": deep_count,
            "items": results,
        }
        if args.format == "table":
            print(format_triage_table(report))
        else:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0

    except TriageError as exc:
        print(mask_secret(f"エラー [{exc.code}]: {exc.message}", api_key), file=sys.stderr)
        return exc.exit_code
    except run_decisions.SafetyBlockError as exc:
        blocked = exc.to_dict()
        blocked["message"] = mask_secret(str(blocked.get("message", "")), api_key)
        print(json.dumps(blocked, ensure_ascii=False, indent=2), file=sys.stderr)
        return 3
    except run_decisions.ApiRequestError as exc:
        print(mask_secret(f"API エラー: {exc.message}", api_key), file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001
        print(mask_secret(f"予期しないエラー: {exc}", api_key), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
