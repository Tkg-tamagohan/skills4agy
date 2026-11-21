#!/usr/bin/env python3
"""Gemini Decision 1 を用いた test-suite-pruning 保護対象フィルタ CLI。

テスト候補一覧 JSON（--input または --stdin）を受け取り、秘密情報混入を
送信前に遮断したうえで、各候補に対して保護対象 5 条件（noul）と区分選択
（choice）の 6 問を 1 リクエストで並列判定し、安全側バイアスの分岐ルールで
skip_keep / verify_for_prune / review_for_discussion へ振り分ける。
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import json
import os
from pathlib import Path
import sys
from typing import Any, Callable

_DECISIONS_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "gemini-decisions-api" / "scripts"
if str(_DECISIONS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_DECISIONS_SCRIPTS_DIR))

import decision_hygiene  # noqa: E402
import run_decisions  # noqa: E402

DEFAULT_MODEL = run_decisions.DEFAULT_MODEL
DEFAULT_ENDPOINT = run_decisions.DEFAULT_ENDPOINT
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_WORKERS = 4

PROTECTED_NOUL_KEEP_THRESHOLD = 0.65
PROTECTED_NOUL_PRUNE_CEILING = 0.40
KEEP_CHOICE_MIN_CONFIDENCE = 0.75
PRUNE_CHOICE_MIN_CONFIDENCE = 0.80

PROTECTION_QUESTION_KEYS: tuple[str, ...] = (
    "prot_spec_linked",
    "prot_bug_regression",
    "prot_critical_invariant",
    "prot_sole_coverage_hint",
    "prot_distinct_layer_role",
)
CATEGORY_QUESTION_KEY = "pruning_category"

SECRET_PATTERNS = decision_hygiene.SECRET_DETECT_PATTERNS


@dataclass(frozen=True)
class TestCandidate:
    """スクリーニング対象のテスト候補 1 件。"""

    id: str
    file: str
    line: int
    test_name: str
    code: str
    git_log: str | None = None
    spec_refs: str | None = None


class ScreeningError(Exception):
    """スクリーニング CLI の制御エラーを表す例外。"""

    def __init__(self, code: str, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code


def mask_secret(text: str, secret: str | None = None) -> str:
    """エラー出力から API キーや秘密情報トークンの実値をマスクする。"""
    return decision_hygiene.mask_secret(text, secret)


def _iter_string_fields(value: Any, prefix: str) -> list[tuple[str, str]]:
    """任意 JSON 値から検査対象の文字列表現とフィールド名一覧を抽出する。"""
    items: list[tuple[str, str]] = []
    if isinstance(value, str):
        items.append((prefix, value))
    elif isinstance(value, list):
        for idx, elem in enumerate(value):
            items.extend(_iter_string_fields(elem, f"{prefix}[{idx}]"))
    elif isinstance(value, dict):
        for k, v in value.items():
            items.extend(_iter_string_fields(v, f"{prefix}.{k}"))
    return items


def check_candidates_secrets(raw_items: list[Any]) -> list[str]:
    """テスト候補一覧の文字列フィールドから秘密鍵ヘッダや API トークンを検出する。"""
    findings: list[str] = []
    for idx, item in enumerate(raw_items):
        if not isinstance(item, dict):
            continue
        item_id = mask_secret(str(item.get("id") or f"index={idx}"))
        item_file = mask_secret(str(item.get("file") or "-"))
        item_line = item.get("line", "-")
        for field_name, text in _iter_string_fields(item, "candidate"):
            short_field = field_name.removeprefix("candidate.")
            labels = decision_hygiene.scan_text_for_secrets(text, patterns=SECRET_PATTERNS)
            if labels:
                findings.append(
                    f"候補 {item_id} ({item_file}:{item_line}) の {short_field} に"
                    f"秘密情報パターン（{labels[0]}）が含まれています。"
                )
    return findings


def _format_optional_text(value: Any, field_name: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value if value.strip() else None
    if isinstance(value, list):
        parts: list[str] = []
        for elem in value:
            if isinstance(elem, str):
                if elem.strip():
                    parts.append(elem)
            elif isinstance(elem, (dict, int, float)) and not isinstance(elem, bool):
                parts.append(
                    json.dumps(elem, ensure_ascii=False)
                    if isinstance(elem, dict)
                    else str(elem)
                )
            else:
                raise ScreeningError(
                    "invalid_input_schema",
                    f"{field_name} の配列要素に非対応の型が含まれています。",
                )
        return "\n".join(parts) if parts else None
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False) if value else None
    raise ScreeningError(
        "invalid_input_schema",
        f"{field_name} は文字列、配列、またはオブジェクトで指定してください。",
    )


def parse_candidates(raw_data: Any) -> list[TestCandidate]:
    """入力 JSON 配列を検証し、TestCandidate の一覧へ変換する。"""
    if not isinstance(raw_data, list):
        raise ScreeningError(
            "invalid_input_schema",
            "入力 JSON のトップレベルはテスト候補オブジェクトの配列である必要があります。",
        )

    secret_findings = check_candidates_secrets(raw_data)
    if secret_findings:
        raise ScreeningError("secret_detected", " ".join(secret_findings), exit_code=2)

    candidates: list[TestCandidate] = []
    for idx, item in enumerate(raw_data):
        if not isinstance(item, dict):
            raise ScreeningError(
                "invalid_input_schema",
                f"input[{idx}] は JSON オブジェクトである必要があります。",
            )
        for req_str in ("id", "file", "test_name"):
            val = item.get(req_str)
            if not isinstance(val, str) or not val.strip():
                raise ScreeningError(
                    "invalid_input_schema",
                    f"input[{idx}].{req_str} は空でない文字列が必要です。",
                )
        line_val = item.get("line")
        if not isinstance(line_val, int) or isinstance(line_val, bool) or line_val < 0:
            raise ScreeningError(
                "invalid_input_schema",
                f"input[{idx}].line は 0 以上の整数が必要です。",
            )
        code_val = item.get("code")
        if not isinstance(code_val, str):
            raise ScreeningError(
                "invalid_input_schema",
                f"input[{idx}].code は文字列が必要です。",
            )

        candidates.append(
            TestCandidate(
                id=item["id"].strip(),
                file=item["file"].strip(),
                line=line_val,
                test_name=item["test_name"].strip(),
                code=code_val,
                git_log=_format_optional_text(item.get("git_log"), f"input[{idx}].git_log"),
                spec_refs=_format_optional_text(item.get("spec_refs"), f"input[{idx}].spec_refs"),
            )
        )
    return candidates


def build_screening_questions() -> dict[str, dict[str, Any]]:
    """保護対象 5 条件（noul）と区分選択 1 問（choice）の質問マップを返す。"""
    return {
        "prot_spec_linked": {
            "type": "noul",
            "instructions": (
                "Does this test explicitly map to a specification, requirement, "
                "acceptance criterion, or specification ID?"
            ),
            "criteria": {
                "true_description": (
                    "The test code, test name, comments, or spec_refs explicitly reference "
                    "a specification document, requirement, acceptance criterion, or specification ID."
                ),
                "false_description": (
                    "The provided context lacks explicit linkage to a specification, "
                    "requirement, acceptance criterion, or specification ID."
                ),
            },
        },
        "prot_bug_regression": {
            "type": "noul",
            "instructions": (
                "Do the git_log, comments, or issue references substantiate that this test "
                "prevents regression of a past bug fix?"
            ),
            "criteria": {
                "true_description": (
                    "The git_log, comments, PR references, or issue numbers substantiate "
                    "that this test guards against recurrence of a past defect."
                ),
                "false_description": (
                    "The available history and comments omit evidence linking this test "
                    "to a past bug fix regression."
                ),
            },
        },
        "prot_critical_invariant": {
            "type": "noul",
            "instructions": (
                "Does this test verify a critical invariant or boundary involving security, "
                "authorization, boundary values, concurrency, shutdown ordering, "
                "or transaction consistency?"
            ),
            "criteria": {
                "true_description": (
                    "The test verifies security, authorization, boundary conditions, "
                    "concurrency, shutdown sequencing, or transaction integrity."
                ),
                "false_description": (
                    "The test targets routine behavior outside security, authorization, "
                    "boundary values, concurrency, shutdown ordering, or transaction consistency."
                ),
            },
        },
        "prot_sole_coverage_hint": {
            "type": "noul",
            "instructions": (
                "Does this test appear to be a unique test that verifies an independent "
                "production code branch or distinct failure mode?"
            ),
            "criteria": {
                "true_description": (
                    "Based on the test logic and assertions, the test appears to exercise "
                    "a distinct production branch or unique failure condition."
                ),
                "false_description": (
                    "The test appears trivial, empty, tautological, duplicated, "
                    "or limited to retired behavior."
                ),
            },
        },
        "prot_distinct_layer_role": {
            "type": "noul",
            "instructions": (
                "Does this test serve a distinct verification layer role such as "
                "fast unit feedback or failure localization?"
            ),
            "criteria": {
                "true_description": (
                    "The test provides fast, localized unit or component feedback "
                    "that complements higher-level integration tests."
                ),
                "false_description": (
                    "The test lacks a distinct fast-feedback or failure-localization role."
                ),
            },
        },
        CATEGORY_QUESTION_KEY: {
            "type": "choice",
            "instructions": (
                "Which pruning category best describes this test candidate "
                "based on the test code, metadata, and history?"
            ),
            "criteria": {
                "keep_protected": (
                    "Protected or unique test linked to specifications, bug regressions, "
                    "critical invariants, sole branch coverage, or distinct layer role."
                ),
                "auto_prune_candidate": (
                    "Clearly redundant, empty-assertion, tautological, exact duplicate, "
                    "or obsolete test for retired functionality that is safe to verify for pruning."
                ),
                "needs_discussion": (
                    "Ambiguous, tightly coupled to internals, skipped with unclear intent, "
                    "overlapping with tradeoffs, or requiring human review."
                ),
                "other": "Insufficient context or falls outside the listed categories.",
            },
        },
    }


def build_candidate_payload(
    candidate: TestCandidate,
    model: str = DEFAULT_MODEL,
) -> dict[str, Any]:
    """テスト候補 1 件分の Decisions API ペイロードを構築し、事前検証する。"""
    meta_lines = [
        f"Test ID: {candidate.id}",
        f"File: {candidate.file}",
        f"Line: {candidate.line}",
        f"Test Name: {candidate.test_name}",
    ]
    if candidate.spec_refs:
        meta_lines.append(f"Spec Refs:\n{candidate.spec_refs}")
    if candidate.git_log:
        meta_lines.append(f"Git Log:\n{candidate.git_log}")

    input_blocks = [
        {"type": "text", "text": "\n".join(meta_lines) + "\n\n"},
        {"type": "text", "text": f"Test Code:\n```\n{candidate.code}\n```\n"},
    ]
    payload: dict[str, Any] = {
        "model": model,
        "input": input_blocks,
        "questions": build_screening_questions(),
    }
    errors = run_decisions.validate_payload(payload)
    if errors:
        raise ScreeningError(
            "payload_validation_failed",
            f"候補 {candidate.id} のペイロード検証に失敗しました: " + "; ".join(errors),
            exit_code=2,
        )
    return payload


def _extract_number(mapping: Any, key: str) -> float | None:
    if not isinstance(mapping, dict):
        return None
    val = mapping.get(key)
    if isinstance(val, (int, float)) and not isinstance(val, bool):
        return float(val)
    return None


def classify_candidate_answers(answers: dict[str, Any]) -> dict[str, Any]:
    """Decisions API 応答から安全側バイアスで action と根拠情報を決定する。"""
    protection_scores: dict[str, float | None] = {}
    triggered_protections: list[str] = []
    present_scores: list[float] = []
    all_below_prune_ceiling = True

    for key in PROTECTION_QUESTION_KEYS:
        val = _extract_number(answers.get(key), "noul")
        protection_scores[key] = round(val, 4) if val is not None else None
        if val is None:
            all_below_prune_ceiling = False
            continue
        present_scores.append(val)
        if val >= PROTECTED_NOUL_KEEP_THRESHOLD:
            triggered_protections.append(key)
        if not (val < PROTECTED_NOUL_PRUNE_CEILING):
            all_below_prune_ceiling = False

    cat_ans = answers.get(CATEGORY_QUESTION_KEY)
    pruning_category: str | None = None
    if isinstance(cat_ans, dict) and isinstance(cat_ans.get("choice"), str):
        raw_choice = cat_ans["choice"].strip()
        if raw_choice:
            pruning_category = raw_choice
    cat_confidence = _extract_number(cat_ans, "confidence")

    reasons: list[str] = []
    keep_by_choice = (
        pruning_category == "keep_protected"
        and cat_confidence is not None
        and cat_confidence >= KEEP_CHOICE_MIN_CONFIDENCE
    )

    if triggered_protections or keep_by_choice:
        action = "skip_keep"
        for key in triggered_protections:
            reasons.append(f"{key}>={PROTECTED_NOUL_KEEP_THRESHOLD:.2f}")
        if keep_by_choice:
            reasons.append(
                f"pruning_category=keep_protected(confidence>={KEEP_CHOICE_MIN_CONFIDENCE:.2f})"
            )
    elif (
        pruning_category == "auto_prune_candidate"
        and all_below_prune_ceiling
        and cat_confidence is not None
        and cat_confidence >= PRUNE_CHOICE_MIN_CONFIDENCE
    ):
        action = "verify_for_prune"
        reasons.append(
            f"pruning_category=auto_prune_candidate(confidence>={PRUNE_CHOICE_MIN_CONFIDENCE:.2f})"
        )
        reasons.append(f"all_protections<{PROTECTED_NOUL_PRUNE_CEILING:.2f}")
    else:
        action = "review_for_discussion"
        if pruning_category in ("needs_discussion", "other"):
            reasons.append(f"pruning_category={pruning_category}")
        elif pruning_category is None:
            reasons.append("missing_pruning_category")
        if cat_confidence is None:
            reasons.append("missing_category_confidence")
        elif (
            pruning_category == "auto_prune_candidate"
            and cat_confidence < PRUNE_CHOICE_MIN_CONFIDENCE
        ):
            reasons.append(f"low_confidence<{PRUNE_CHOICE_MIN_CONFIDENCE:.2f}")
        elif pruning_category == "keep_protected" and cat_confidence < KEEP_CHOICE_MIN_CONFIDENCE:
            reasons.append(f"low_keep_confidence<{KEEP_CHOICE_MIN_CONFIDENCE:.2f}")
        if not all_below_prune_ceiling:
            if any(v is None for v in protection_scores.values()):
                reasons.append("incomplete_protection_scores")
            else:
                reasons.append(f"protection_borderline>={PROTECTED_NOUL_PRUNE_CEILING:.2f}")

    max_prot = round(max(present_scores), 4) if present_scores else None
    return {
        "action": action,
        "reasons": reasons,
        "pruning_category": pruning_category,
        "pruning_category_confidence": (
            round(cat_confidence, 4) if cat_confidence is not None else None
        ),
        "max_protection_noul": max_prot,
        "triggered_protections": triggered_protections,
        "protection_scores": protection_scores,
    }


def _screen_single(
    candidate: TestCandidate,
    payload: dict[str, Any],
    api_key: str,
    endpoint: str,
    timeout: float,
    opener: Callable[..., Any] | None,
) -> dict[str, Any]:
    raw_response = run_decisions.call_decisions_api(
        payload,
        api_key=api_key,
        endpoint=endpoint,
        timeout=timeout,
        opener=opener,
    )
    enriched = run_decisions.enrich_response(raw_response)
    decision = classify_candidate_answers(enriched.get("answers") or {})
    item: dict[str, Any] = {
        "id": candidate.id,
        "file": candidate.file,
        "line": candidate.line,
        "test_name": candidate.test_name,
        **decision,
    }
    usage = enriched.get("usage")
    if isinstance(usage, dict):
        item["usage"] = usage
    return item


def screen_candidates(
    candidates: list[TestCandidate],
    payloads: list[dict[str, Any]],
    api_key: str,
    *,
    endpoint: str = DEFAULT_ENDPOINT,
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = DEFAULT_MAX_WORKERS,
    opener: Callable[..., Any] | None = None,
) -> list[dict[str, Any]]:
    """テスト候補群を並列実行しつつ入力順を保持して判定結果を返す。"""
    if not candidates:
        return []
    worker_count = min(max_workers, len(candidates))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [
            executor.submit(
                _screen_single,
                candidate,
                payload,
                api_key,
                endpoint,
                timeout,
                opener,
            )
            for candidate, payload in zip(candidates, payloads)
        ]
        return [future.result() for future in futures]


def _escape_md_cell(value: Any) -> str:
    return str(value).replace("\r", " ").replace("\n", " ").replace("|", "\\|")


def _summarize_actions(results: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "skip_keep": 0,
        "verify_for_prune": 0,
        "review_for_discussion": 0,
    }
    for row in results:
        action = row.get("action")
        if action in counts:
            counts[action] += 1
    return counts


def _aggregate_usage(results: list[dict[str, Any]]) -> dict[str, int] | None:
    has_usage = False
    in_total = 0
    out_total = 0
    for row in results:
        usage = row.get("usage")
        if isinstance(usage, dict):
            has_usage = True
            if isinstance(usage.get("total_input_tokens"), int):
                in_total += usage["total_input_tokens"]
            if isinstance(usage.get("total_output_tokens"), int):
                out_total += usage["total_output_tokens"]
    if not has_usage:
        return None
    return {
        "total_input_tokens": in_total,
        "total_output_tokens": out_total,
        "total_tokens": in_total + out_total,
    }


def format_screening_table(report: dict[str, Any]) -> str:
    """スクリーニング結果を Markdown 表形式の UTF-8 文字列へ整形する。"""
    status = report.get("status", "completed")
    if status == "dry_run":
        items = report.get("items") or []
        lines = [
            "| id | location | test_name | questions | status |",
            "| --- | --- | --- | --- | --- |",
        ]
        for entry in items:
            loc = f"`{entry['file']}:{entry['line']}`"
            q_count = len((entry.get("payload") or {}).get("questions") or {})
            lines.append(
                f"| {_escape_md_cell(entry['id'])} | {_escape_md_cell(loc)} | "
                f"{_escape_md_cell(entry['test_name'])} | {q_count} | validated |"
            )
        lines.append("")
        lines.append(f"Summary: dry_run total={report.get('total', len(items))}")
        return "\n".join(lines)

    results = report.get("results") or []
    summary = report.get("summary") or _summarize_actions(results)
    lines = [
        "| id | action | category | confidence | max_prot | triggered | location | test_name |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in results:
        conf = row.get("pruning_category_confidence")
        conf_str = f"{float(conf):.2f}" if isinstance(conf, (int, float)) else "-"
        max_p = row.get("max_protection_noul")
        max_p_str = f"{float(max_p):.2f}" if isinstance(max_p, (int, float)) else "-"
        trig = ", ".join(row.get("triggered_protections") or []) or "-"
        loc = f"`{row['file']}:{row['line']}`"
        lines.append(
            f"| {_escape_md_cell(row['id'])} | {_escape_md_cell(row['action'])} | "
            f"{_escape_md_cell(row.get('pruning_category') or '-')} | {conf_str} | {max_p_str} | "
            f"{_escape_md_cell(trig)} | {_escape_md_cell(loc)} | {_escape_md_cell(row['test_name'])} |"
        )
    lines.append("")
    lines.append(
        "Summary: "
        f"total={report.get('total', len(results))}, "
        f"skip_keep={summary.get('skip_keep', 0)}, "
        f"verify_for_prune={summary.get('verify_for_prune', 0)}, "
        f"review_for_discussion={summary.get('review_for_discussion', 0)}"
    )
    usage = report.get("usage")
    if isinstance(usage, dict):
        lines.append(
            f"usage: input_tokens={usage.get('total_input_tokens')}, "
            f"output_tokens={usage.get('total_output_tokens')}"
        )
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Gemini Decision 1 で test-suite-pruning の保護対象を一次判定する CLI"
    )
    parser.add_argument("--input", help="テスト候補配列を格納した UTF-8 JSON ファイルパス")
    parser.add_argument("--stdin", action="store_true", help="標準入力から UTF-8 JSON 配列を読み込む")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="モデル ID（既定: gemini-decision-1）")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT, help="API エンドポイント URL")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="HTTP タイムアウト秒")
    parser.add_argument(
        "--max-workers",
        type=int,
        default=DEFAULT_MAX_WORKERS,
        help="並列リクエスト数上限（既定: 4、出力順序保持）",
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


def _load_raw_json(
    input_path: str | None,
    use_stdin: bool,
    stdin_text: str | None,
) -> Any:
    if bool(input_path) == bool(use_stdin):
        raise ScreeningError(
            "invalid_input_source",
            "--input <path> または --stdin のどちらか一方だけを指定してください。",
            exit_code=2,
        )
    try:
        if use_stdin:
            raw_text = stdin_text if stdin_text is not None else sys.stdin.read()
        else:
            assert input_path is not None
            if decision_hygiene.is_blocked_env_path(input_path):
                raise ScreeningError(
                    "secret_env_file",
                    f"機密環境ファイル (.env) は --input に指定できません: {input_path}",
                    exit_code=2,
                )
            raw_text = Path(input_path).read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ScreeningError(
            "invalid_input_encoding",
            f"入力ファイルは UTF-8 としてデコードできません: {exc}",
            exit_code=2,
        ) from exc
    except OSError as exc:
        raise ScreeningError("input_read_error", f"入力ファイルを読めません: {exc}", exit_code=2) from exc

    try:
        return json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ScreeningError("invalid_json", f"入力 JSON の構文が不正です: {exc}", exit_code=2) from exc


def _emit_error(
    code: str,
    message: str,
    exit_code: int,
    output_format: str,
    api_key: str,
) -> None:
    safe_msg = mask_secret(message, api_key)
    if output_format == "json":
        err_obj = {
            "status": "error",
            "exit_code": exit_code,
            "code": code,
            "error": safe_msg,
        }
        print(json.dumps(err_obj, ensure_ascii=False, indent=2), file=sys.stderr)
    else:
        print(f"ERROR [{code}]: {safe_msg}", file=sys.stderr)


def run_cli(
    argv: list[str] | None = None,
    *,
    opener: Callable[..., Any] | None = None,
    env: dict[str, str] | None = None,
    stdin_text: str | None = None,
) -> int:
    """CLI 引数を解釈し、保護対象一次判定を実行して終了コードを返す。"""
    decision_hygiene.configure_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    environ = os.environ if env is None else env
    api_key = environ.get("GEMINI_API_KEY", "").strip()

    try:
        if args.max_workers < 1:
            raise ScreeningError(
                "invalid_max_workers",
                "--max-workers は 1 以上の整数を指定してください。",
                exit_code=2,
            )
        if args.timeout <= 0:
            raise ScreeningError(
                "invalid_timeout",
                "--timeout は 0 より大きい数値を指定してください。",
                exit_code=2,
            )

        raw_data = _load_raw_json(args.input, args.stdin, stdin_text)
        candidates = parse_candidates(raw_data)
        payloads = [build_candidate_payload(c, model=args.model) for c in candidates]

        if args.dry_run:
            dry_report = {
                "status": "dry_run",
                "model": args.model,
                "total": len(candidates),
                "items": [
                    {
                        "id": c.id,
                        "file": c.file,
                        "line": c.line,
                        "test_name": c.test_name,
                        "payload": p,
                    }
                    for c, p in zip(candidates, payloads)
                ],
            }
            if args.format == "table":
                print(format_screening_table(dry_report))
            else:
                print(json.dumps(dry_report, ensure_ascii=False, indent=2))
            return 0

        if not candidates:
            empty_report = {
                "status": "skipped_empty_input",
                "model": args.model,
                "total": 0,
                "summary": _summarize_actions([]),
                "results": [],
            }
            if args.format == "table":
                print(format_screening_table(empty_report))
            else:
                print(json.dumps(empty_report, ensure_ascii=False, indent=2))
            return 0

        if not api_key:
            raise ScreeningError(
                "missing_api_key",
                "環境変数 GEMINI_API_KEY が設定されていません。"
                "API キーを設定するか --dry-run を使用してください。",
                exit_code=2,
            )

        results = screen_candidates(
            candidates,
            payloads,
            api_key,
            endpoint=args.endpoint,
            timeout=args.timeout,
            max_workers=args.max_workers,
            opener=opener,
        )
        report: dict[str, Any] = {
            "status": "completed",
            "model": args.model,
            "total": len(results),
            "summary": _summarize_actions(results),
            "results": results,
        }
        usage_summary = _aggregate_usage(results)
        if usage_summary is not None:
            report["usage"] = usage_summary

        if args.format == "table":
            print(format_screening_table(report))
        else:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0

    except ScreeningError as exc:
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
    except (run_decisions.ApiRequestError, OSError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
        msg = exc.message if isinstance(exc, run_decisions.ApiRequestError) else str(exc)
        _emit_error("api_request_failed", f"API 呼び出しエラー: {msg}", 1, args.format, api_key)
        return 1
    except Exception as exc:  # noqa: BLE001
        _emit_error("unexpected_error", str(exc), 2, args.format, api_key)
        return 2


def main(
    argv: list[str] | None = None,
    *,
    opener: Callable[..., Any] | None = None,
    env: dict[str, str] | None = None,
    stdin_text: str | None = None,
) -> int:
    """エントリーポイント。"""
    return run_cli(argv, opener=opener, env=env, stdin_text=stdin_text)


if __name__ == "__main__":
    raise SystemExit(main())
