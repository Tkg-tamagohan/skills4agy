#!/usr/bin/env python3
"""pr-review-triage PR 内再発防止策（Guardrails）抽出・生成 CLI。

GitHub PR の本文とコメント履歴からマーカー付き再発防止策ブロックを抽出し、
ID ベースの時系列マージ、`invariant-gate` 用ルール Markdown 生成、
Stage 2 ブリーフ生成、および Stage 3 追記用ブロックの検証付き生成を行う。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

_DECISIONS_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "gemini-decisions-api" / "scripts"
if str(_DECISIONS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_DECISIONS_SCRIPTS_DIR))

import decision_hygiene  # noqa: E402

MARKER_START = "<!-- pr-review-triage:guardrails:v1 -->"
MARKER_END = "<!-- /pr-review-triage:guardrails:v1 -->"

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
PRG_NUM_RE = re.compile(r"^PRG-(\d+)$")
BULLET_RE = re.compile(
    r"^\s*-\s+\[(?P<id>[A-Za-z0-9][A-Za-z0-9_-]{0,63})\]\s*(?:\((?P<status>active|retired)\)\s*)?(?P<body>.+?)\s*$"
)
FIELD_SPLIT_RE = re.compile(r"\s+\|\s+(?=(?:対象|ルール|根拠|理由)\s*[:：])")
FIELD_KV_RE = re.compile(r"^(対象|ルール|根拠|理由)\s*[:：]\s*(.*)$")
FENCE_RE = re.compile(r"^(`{3,}|~{3,})")
HEADING_LINE_RE = re.compile(r"^#{1,6}\s")
HR_LINE_RE = re.compile(r"^[-*_]{3,}$")
DETAILS_WRAPPER_RE = re.compile(
    r"^(?:</?details(?:\s+[^>]*)?>|<summary>.*</summary>)$",
    re.IGNORECASE,
)

VALID_STATUSES = frozenset({"active", "retired"})
VALID_EXTRACT_FORMATS = ("summary", "rules-md", "brief", "json")


class GuardrailError(RuntimeError):
    """再発防止策の抽出・生成中の検証および実行エラー。"""

    def __init__(self, code: str, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code


def _check_env_path(path_str: str | None, option_name: str) -> None:
    if path_str and path_str != "-" and decision_hygiene.is_blocked_env_path(path_str):
        raise GuardrailError(
            "blocked_env_path",
            f"秘密情報を含む可能性があるため .env 系ファイルを {option_name} に指定できません: {path_str}",
        )


def _read_json_input(path_str: str, option_name: str) -> Any:
    _check_env_path(path_str, option_name)
    try:
        if path_str == "-":
            raw_text = sys.stdin.read()
        else:
            raw_text = Path(path_str).read_text(encoding="utf-8")
    except OSError as exc:
        raise GuardrailError("input_read_error", f"入力を読めません ({path_str}): {exc}") from exc
    except UnicodeDecodeError as exc:
        raise GuardrailError("input_decode_error", f"入力を UTF-8 として読めません ({path_str}): {exc}") from exc

    try:
        return json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise GuardrailError("invalid_json", f"JSON パースに失敗しました ({option_name}): {exc}") from exc


def _write_output_text(text: str, output_path: str | None) -> None:
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    if not normalized.endswith("\n"):
        normalized += "\n"
    if output_path:
        _check_env_path(output_path, "--output")
        path = Path(output_path)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(normalized, encoding="utf-8", newline="\n")
        except OSError as exc:
            raise GuardrailError("output_write_error", f"出力ファイルへ書き込めません ({output_path}): {exc}") from exc
    else:
        sys.stdout.write(normalized)


def _scan_secrets_or_raise(text: str, context_label: str) -> None:
    hits = decision_hygiene.scan_text_for_secrets(text)
    if hits:
        labels = ", ".join(hits)
        raise GuardrailError(
            "secret_detected",
            f"{context_label}に秘密情報パターン（{labels}）が含まれるため処理を中断しました。",
        )


def _safe_warning_snippet(text: str, limit: int = 80) -> str:
    masked = decision_hygiene.mask_secrets(text.strip())
    if len(masked) > limit:
        return masked[:limit] + "..."
    return masked


def extract_marker_blocks(text: str) -> tuple[list[str], list[str]]:
    """フェンス付きコードブロック内を除外し、マーカーで囲まれたブロック本文を抽出する。"""
    if not text:
        return [], []

    blocks: list[str] = []
    warnings: list[str] = []
    lines = text.replace("\r\n", "\n").replace("\r", "\n").splitlines()

    in_fence = False
    fence_char = ""
    fence_len = 0
    in_block = False
    current_lines: list[str] = []

    for line_no, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()

        fence_match = FENCE_RE.match(stripped)
        if fence_match:
            marker = fence_match.group(1)
            if not in_fence:
                in_fence = True
                fence_char = marker[0]
                fence_len = len(marker)
            elif marker[0] == fence_char and len(marker) >= fence_len:
                in_fence = False
                fence_char = ""
                fence_len = 0
            if in_block:
                current_lines.append(raw_line)
            continue

        if in_fence:
            if in_block:
                current_lines.append(raw_line)
            continue

        if stripped == MARKER_START:
            if in_block:
                warnings.append(f"L{line_no}: 閉じマーカー前に新しい開始マーカーが現れました。")
                current_lines = []
            in_block = True
            current_lines = []
            continue

        if stripped == MARKER_END:
            if in_block:
                blocks.append("\n".join(current_lines))
                in_block = False
                current_lines = []
            else:
                warnings.append(f"L{line_no}: 開始マーカーに対応する前の閉じマーカーを無視しました。")
            continue

        if in_block:
            current_lines.append(raw_line)

    if in_block:
        warnings.append("閉じマーカー（<!-- /pr-review-triage:guardrails:v1 -->）が欠落しているため未完了ブロックを無視しました。")

    return blocks, warnings


def parse_guardrail_block(
    block_text: str,
    source_meta: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    """マーカー内ブロックを項目リストと警告へ解析する。"""
    items: list[dict[str, Any]] = []
    warnings: list[str] = []

    if "\ufffd" in block_text:
        warnings.append(f"{source_meta.get('kind', 'comment')}: ブロック内に置換文字 (U+FFFD) を検出しました。")

    for line_no, raw_line in enumerate(block_text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        if HEADING_LINE_RE.match(stripped) or HR_LINE_RE.match(stripped) or DETAILS_WRAPPER_RE.match(stripped):
            continue

        if not stripped.startswith("- "):
            warnings.append(
                f"{source_meta.get('kind', 'comment')} L{line_no}: 箇条書き以外の不正行を無視しました: {_safe_warning_snippet(stripped)}"
            )
            continue

        bullet_match = BULLET_RE.match(raw_line)
        if not bullet_match:
            warnings.append(
                f"{source_meta.get('kind', 'comment')} L{line_no}: 箇条書きの書式が不正です: {_safe_warning_snippet(stripped)}"
            )
            continue

        item_id = bullet_match.group("id")
        status = bullet_match.group("status") or "active"
        body = bullet_match.group("body").strip()

        parts = FIELD_SPLIT_RE.split(body)
        fields: dict[str, str] = {}
        matched_any_label = False
        unmatched_parts: list[str] = []

        for part in parts:
            kv_match = FIELD_KV_RE.match(part.strip())
            if kv_match:
                matched_any_label = True
                fields[kv_match.group(1)] = kv_match.group(2).strip()
            else:
                unmatched_parts.append(part.strip())

        if not matched_any_label:
            if status == "active":
                fields["ルール"] = body
            else:
                fields["理由"] = body
        elif unmatched_parts:
            warnings.append(
                f"{item_id}: 認識できない断片を無視しました: {_safe_warning_snippet(' | '.join(unmatched_parts))}"
            )

        scope = fields.get("対象", "")
        rule = fields.get("ルール", "")
        evidence = fields.get("根拠", "")
        reason = fields.get("理由", "")

        if status == "active" and not rule:
            warnings.append(f"{item_id}: active 項目に 'ルール:' が無いためスキップしました。")
            continue

        items.append(
            {
                "id": item_id,
                "status": status,
                "scope": scope,
                "rule": rule,
                "evidence": evidence,
                "reason": reason,
                "source": dict(source_meta),
            }
        )

    return items, warnings


def _extract_author_login(entry: dict[str, Any]) -> str:
    for key in ("author", "user"):
        actor = entry.get(key)
        if isinstance(actor, dict):
            login = actor.get("login") or actor.get("name")
            if isinstance(login, str) and login.strip():
                return login.strip()
        elif isinstance(actor, str) and actor.strip():
            return actor.strip()
    return ""


def _extract_created_at(entry: dict[str, Any]) -> str:
    for key in ("createdAt", "created_at", "submittedAt", "submitted_at"):
        val = entry.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def _unwrap_pr_root(raw_data: Any) -> Any:
    if isinstance(raw_data, dict):
        if isinstance(raw_data.get("data"), dict):
            data = raw_data["data"]
            if isinstance(data.get("repository"), dict) and isinstance(data["repository"].get("pullRequest"), dict):
                return data["repository"]["pullRequest"]
            if isinstance(data.get("pullRequest"), dict):
                return data["pullRequest"]
        if isinstance(raw_data.get("pullRequest"), dict):
            return raw_data["pullRequest"]
    return raw_data


def _extract_comment_entries(raw_comments: Any) -> list[dict[str, Any]]:
    if raw_comments is None:
        return []
    if isinstance(raw_comments, dict) and isinstance(raw_comments.get("nodes"), list):
        return [c for c in raw_comments["nodes"] if isinstance(c, dict)]
    if isinstance(raw_comments, list):
        return [c for c in raw_comments if isinstance(c, dict)]
    raise GuardrailError("invalid_input_schema", "comments は配列または nodes を持つオブジェクトである必要があります。")


def load_pr_sources(raw_data: Any, authors: list[str] | None = None) -> list[dict[str, Any]]:
    """各種 PR JSON 形式から時系列順のソース（pr_body + comments）を抽出する。"""
    root = _unwrap_pr_root(raw_data)
    allowed_authors = {a.strip().lower() for a in (authors or []) if a and a.strip()}

    def author_allowed(login: str) -> bool:
        if not allowed_authors:
            return True
        return login.lower() in allowed_authors

    sources: list[dict[str, Any]] = []

    if isinstance(root, list):
        comment_entries = [c for c in root if isinstance(c, dict)]
        if len(comment_entries) != len(root):
            raise GuardrailError("invalid_input_schema", "コメント配列の要素はすべて JSON オブジェクトである必要があります。")
    elif isinstance(root, dict):
        body_text = root.get("body")
        if isinstance(body_text, str) and body_text.strip():
            pr_author = _extract_author_login(root)
            if author_allowed(pr_author):
                sources.append(
                    {
                        "kind": "pr_body",
                        "body": body_text,
                        "author": pr_author,
                        "created_at": _extract_created_at(root),
                        "comment_id": str(root.get("id") or ""),
                        "url": str(root.get("url") or ""),
                    }
                )
        comment_entries = _extract_comment_entries(root.get("comments"))
    else:
        raise GuardrailError(
            "invalid_input_schema",
            "入力 JSON は PR オブジェクトまたはコメントオブジェクトの配列である必要があります。",
        )

    normalized_comments: list[dict[str, Any]] = []
    for entry in comment_entries:
        body_text = entry.get("body")
        if not isinstance(body_text, str) or not body_text.strip():
            continue
        author_login = _extract_author_login(entry)
        if not author_allowed(author_login):
            continue
        normalized_comments.append(
            {
                "kind": "comment",
                "body": body_text,
                "author": author_login,
                "created_at": _extract_created_at(entry),
                "comment_id": str(entry.get("id") or ""),
                "url": str(entry.get("url") or ""),
            }
        )

    if normalized_comments and all(c["created_at"] for c in normalized_comments):
        normalized_comments.sort(key=lambda c: c["created_at"])

    sources.extend(normalized_comments)
    return sources


def _id_sort_key(item: dict[str, Any]) -> tuple[int, int, str]:
    item_id = item["id"]
    match = PRG_NUM_RE.match(item_id)
    if match:
        return (0, int(match.group(1)), item_id)
    return (1, 0, item_id)


def _format_next_id(seen_ids: set[str]) -> str:
    max_num = 0
    for item_id in seen_ids:
        match = PRG_NUM_RE.match(item_id)
        if match:
            max_num = max(max_num, int(match.group(1)))
    return f"PRG-{max_num + 1:03d}"


def merge_guardrails(sources: list[dict[str, Any]]) -> dict[str, Any]:
    """時系列順のソースから再発防止策を抽出し、ID ベースで後勝ちマージする。"""
    merged_by_id: dict[str, dict[str, Any]] = {}
    seen_ids: set[str] = set()
    warnings: list[str] = []
    source_blocks_count = 0

    for src in sources:
        blocks, block_warnings = extract_marker_blocks(src.get("body", ""))
        warnings.extend(block_warnings)
        source_meta = {
            "kind": src.get("kind", "comment"),
            "author": src.get("author", ""),
            "created_at": src.get("created_at", ""),
            "comment_id": src.get("comment_id", ""),
            "url": src.get("url", ""),
        }
        for block_text in blocks:
            source_blocks_count += 1
            parsed_items, parse_warnings = parse_guardrail_block(block_text, source_meta)
            warnings.extend(parse_warnings)
            for item in parsed_items:
                combined_text = " ".join(
                    v for v in (item["scope"], item["rule"], item["evidence"], item["reason"]) if v
                )
                _scan_secrets_or_raise(combined_text, f"抽出した再発防止策 {item['id']} ")
                seen_ids.add(item["id"])
                merged_by_id[item["id"]] = item

    active_items = sorted(
        (item for item in merged_by_id.values() if item["status"] == "active"),
        key=_id_sort_key,
    )
    retired_items = sorted(
        (item for item in merged_by_id.values() if item["status"] == "retired"),
        key=_id_sort_key,
    )

    return {
        "schema_version": 1,
        "active_count": len(active_items),
        "retired_count": len(retired_items),
        "next_id": _format_next_id(seen_ids),
        "source_blocks_count": source_blocks_count,
        "active": active_items,
        "retired": retired_items,
        "warnings": warnings,
    }


def _format_source_label(source: dict[str, Any]) -> str:
    parts: list[str] = []
    if source.get("author"):
        parts.append(f"@{source['author']}")
    if source.get("created_at"):
        parts.append(source["created_at"])
    if source.get("comment_id"):
        parts.append(source["comment_id"])
    elif source.get("url"):
        parts.append(source["url"])
    return " / ".join(parts) if parts else source.get("kind", "comment")


def format_summary(result: dict[str, Any], include_retired: bool = False) -> str:
    """Stage 1 確認用の日本語サマリを整形する。"""
    lines = [
        f"PR 内再発防止策: 有効 {result['active_count']} 件 / 失効 {result['retired_count']} 件 / 次の採番 {result['next_id']}（参照ブロック {result['source_blocks_count']} 件）",
    ]
    if result["active"]:
        lines.append("")
        lines.append("### 有効項目 (active)")
        for item in result["active"]:
            scope = item["scope"] or "PR 対象全般"
            evidence = f" | 根拠: {item['evidence']}" if item["evidence"] else ""
            lines.append(
                f"- [{item['id']}] 対象: {scope} | ルール: {item['rule']}{evidence} （出典: {_format_source_label(item['source'])}）"
            )
    else:
        lines.append("")
        lines.append("- 有効な PR 内再発防止策はまだ記録されていません。")

    if include_retired and result["retired"]:
        lines.append("")
        lines.append("### 失効項目 (retired)")
        for item in result["retired"]:
            reason = item["reason"] or "理由未記載"
            lines.append(
                f"- [{item['id']}] (retired) 理由: {reason} （出典: {_format_source_label(item['source'])}）"
            )

    if result["warnings"]:
        lines.append("")
        lines.append("### 警告")
        for warn in result["warnings"]:
            lines.append(f"- {warn}")

    return "\n".join(lines)


def format_rules_markdown(result: dict[str, Any]) -> str:
    """invariant-gate の extract_rules_from_markdown() 互換 Markdown を生成する。"""
    lines = [
        "# PR 再発防止策",
        "",
        "## 有効な再発防止策",
    ]
    if result["active"]:
        lines.append("")
        for item in result["active"]:
            scope = item["scope"] or "PR 対象全般"
            evidence = f"（根拠: {item['evidence']}）" if item["evidence"] else ""
            lines.append(f"- [{item['id']}] 対象: {scope} / ルール: {item['rule']}{evidence}")
    return "\n".join(lines)


def format_brief(result: dict[str, Any]) -> str:
    """Stage 2 の計画書・再開プロンプト・Swarm ブリーフ向け Markdown を生成する。"""
    lines = [
        "### この PR で引き継ぐ再発防止策",
        "",
        "以下のルールは PR の前ラウンドで確定した再発防止策である。",
        "現行コードや最新のユーザー指示と矛盾する場合は、推測で上書きせず実物とユーザー確認を優先すること。",
        "",
    ]
    if result["active"]:
        for item in result["active"]:
            scope = item["scope"] or "PR 対象全般"
            evidence = f"（根拠: {item['evidence']}）" if item["evidence"] else ""
            lines.append(f"- [{item['id']}] 対象: {scope} / ルール: {item['rule']}{evidence}")
    else:
        lines.append("- 有効な PR 内再発防止策はありません。")
    return "\n".join(lines)


def _validate_single_line_field(value: Any, field_name: str, item_label: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise GuardrailError("invalid_item_field", f"{item_label}.{field_name} は文字列である必要があります。")
    if "\n" in value or "\r" in value:
        raise GuardrailError("multiline_field", f"{item_label}.{field_name} に改行文字は含められません。")
    if "\ufffd" in value:
        raise GuardrailError("replacement_char_detected", f"{item_label}.{field_name} に置換文字 (U+FFFD) が含まれています。")
    _scan_secrets_or_raise(value, f"{item_label}.{field_name} ")
    return value.strip()


def _collect_existing_ids(existing_result: dict[str, Any] | None) -> set[str]:
    if not existing_result:
        return set()
    ids = {item["id"] for item in existing_result.get("active", [])}
    ids.update(item["id"] for item in existing_result.get("retired", []))
    return ids


def render_guardrail_block(
    raw_items: Any,
    existing_result: dict[str, Any] | None = None,
    collapsible: bool = False,
) -> tuple[str, list[str]]:
    """入力 JSON から検証済みの Stage 3 マーカーブロックを生成する。"""
    items_list = raw_items.get("items") if isinstance(raw_items, dict) else raw_items
    if not isinstance(items_list, list) or not items_list:
        raise GuardrailError(
            "empty_items",
            "render 入力は 1 件以上の要素を含む JSON 配列（または {\"items\": [...]}）である必要があります。",
        )

    existing_ids = _collect_existing_ids(existing_result)
    used_ids: set[str] = set()
    allocated_ids: set[str] = set(existing_ids)
    warnings: list[str] = []

    explicit_ids: list[str] = []
    for idx, entry in enumerate(items_list):
        if not isinstance(entry, dict):
            raise GuardrailError("invalid_item_schema", f"items[{idx}] は JSON オブジェクトである必要があります。")
        raw_id = entry.get("id")
        if raw_id is not None:
            if not isinstance(raw_id, str) or not ID_RE.match(raw_id.strip()):
                raise GuardrailError(
                    "invalid_item_id",
                    f"items[{idx}].id は ^[A-Za-z0-9][A-Za-z0-9_-]{{0,63}}$ を満たす必要があります。",
                )
            clean_id = raw_id.strip()
            if clean_id in used_ids:
                raise GuardrailError("duplicate_item_id", f"入力内で ID {clean_id} が重複しています。")
            used_ids.add(clean_id)
            allocated_ids.add(clean_id)
            explicit_ids.append(clean_id)
        else:
            explicit_ids.append("")

    rendered_lines: list[str] = []
    for idx, entry in enumerate(items_list):
        label = f"items[{idx}]"
        status = entry.get("status", "active")
        if not isinstance(status, str) or status not in VALID_STATUSES:
            raise GuardrailError("invalid_status", f"{label}.status は 'active' または 'retired' を指定してください。")

        item_id = explicit_ids[idx]
        if status == "retired":
            if not item_id:
                raise GuardrailError("missing_retired_id", f"{label}: retired 項目には明示的な id が必須です。")
            if existing_result is not None and item_id not in existing_ids:
                warnings.append(f"{item_id}: 既存 PR コメントに存在しない ID への retired 指定です。")
        elif not item_id:
            item_id = _format_next_id(allocated_ids)
            allocated_ids.add(item_id)
            used_ids.add(item_id)

        scope = _validate_single_line_field(entry.get("scope"), "scope", label)
        rule = _validate_single_line_field(entry.get("rule"), "rule", label)
        evidence = _validate_single_line_field(entry.get("evidence"), "evidence", label)
        reason = _validate_single_line_field(entry.get("reason"), "reason", label)

        if status == "active":
            if not rule:
                raise GuardrailError("missing_rule", f"{label}: active 項目には空でない rule が必要です。")
            parts = [f"対象: {scope or 'PR 対象全般'}", f"ルール: {rule}"]
            if evidence:
                parts.append(f"根拠: {evidence}")
            rendered_lines.append(f"- [{item_id}] (active) {' | '.join(parts)}")
        else:
            parts = [f"理由: {reason or '不要化'}"]
            if evidence:
                parts.append(f"根拠: {evidence}")
            rendered_lines.append(f"- [{item_id}] (retired) {' | '.join(parts)}")

    inner_lines = ["## 再発防止策（PR 内引き継ぎ）", "", *rendered_lines]
    if collapsible:
        body_lines = [
            "<details>",
            "<summary>再発防止策（PR 内引き継ぎ）</summary>",
            "",
            *rendered_lines,
            "",
            "</details>",
        ]
    else:
        body_lines = inner_lines

    output_lines = [MARKER_START, *body_lines, MARKER_END]
    return "\n".join(output_lines), warnings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PR コメント履歴から再発防止策を抽出・統合・生成する CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    extract_p = subparsers.add_parser("extract", help="PR JSON から再発防止策を抽出して統合する")
    extract_p.add_argument("--input", required=True, help="入力 PR JSON ファイルパス（'-' で標準入力）")
    extract_p.add_argument(
        "--format",
        choices=VALID_EXTRACT_FORMATS,
        default="summary",
        help="出力形式（既定: summary）",
    )
    extract_p.add_argument("--output", help="出力先ファイルパス（UTF-8 BOM なし、省略時は標準出力）")
    extract_p.add_argument(
        "--include-retired",
        action="store_true",
        help="summary と json の出力に retired 項目を含める",
    )
    extract_p.add_argument(
        "--author",
        action="append",
        help="抽出対象の投稿者 login（大文字小文字無視、複数指定可）",
    )
    extract_p.add_argument(
        "--strict",
        action="store_true",
        help="ブロック内の不正行や U+FFFD の警告を終了コード 2 のエラーとして扱う",
    )

    render_p = subparsers.add_parser("render", help="Stage 3 PR サマリコメント用のマーカーブロックを生成する")
    render_p.add_argument("--items", required=True, help="再発防止策項目の JSON ファイルパス（'-' で標準入力）")
    render_p.add_argument("--existing", help="自動採番と既存確認に使う既存 PR JSON ファイルパス")
    render_p.add_argument("--collapsible", action="store_true", help="<details> 折りたたみ形式で生成する")
    render_p.add_argument("--output", help="出力先ファイルパス（UTF-8 BOM なし、省略時は標準出力）")

    return parser


def run_cli(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "extract":
        raw_data = _read_json_input(args.input, "--input")
        sources = load_pr_sources(raw_data, authors=args.author)
        result = merge_guardrails(sources)

        if args.strict and result["warnings"]:
            for warn in result["warnings"]:
                sys.stderr.write(f"[ERROR] {warn}\n")
            return 2

        if args.format == "summary":
            output_text = format_summary(result, include_retired=args.include_retired)
        elif args.format == "rules-md":
            output_text = format_rules_markdown(result)
        elif args.format == "brief":
            output_text = format_brief(result)
        else:
            payload = dict(result)
            if not args.include_retired:
                payload["retired"] = []
            output_text = json.dumps(payload, ensure_ascii=False, indent=2)

        _write_output_text(output_text, args.output)
        return 0

    if args.command == "render":
        raw_items = _read_json_input(args.items, "--items")
        existing_result: dict[str, Any] | None = None
        if args.existing:
            existing_raw = _read_json_input(args.existing, "--existing")
            existing_sources = load_pr_sources(existing_raw)
            existing_result = merge_guardrails(existing_sources)

        rendered, warnings = render_guardrail_block(
            raw_items,
            existing_result=existing_result,
            collapsible=args.collapsible,
        )
        for warn in warnings:
            sys.stderr.write(f"[WARN] {warn}\n")
        _write_output_text(rendered, args.output)
        return 0

    return 2


def main(argv: list[str] | None = None) -> int:
    decision_hygiene.configure_utf8_stdio()
    try:
        return run_cli(argv)
    except GuardrailError as exc:
        sys.stderr.write(f"[ERROR:{exc.code}] {decision_hygiene.mask_secrets(exc.message)}\n")
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
