#!/usr/bin/env python3
"""repo-drift-audit 向け Markdown 表整形および標準入出力・エラー出力補助モジュール。"""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

_DECISIONS_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "gemini-decisions-api" / "scripts"
if str(_DECISIONS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_DECISIONS_SCRIPTS_DIR))

import decision_common  # noqa: E402

_aggregate_usage = decision_common.aggregate_usage
_escape_md_cell = decision_common.escape_md_cell
_is_real_number = decision_common.is_real_number


def _format_flag_hints_cell(flags: Any) -> str:
    if not isinstance(flags, list) or not flags:
        return "0"
    joined = ", ".join(str(fl) for fl in flags)
    return _escape_md_cell(f"{len(flags)}: {joined}")


def _format_chunk_label_list(raw_list: Any) -> str:
    if not isinstance(raw_list, list) or not raw_list:
        return "-"
    labels: list[str] = []
    for elem in raw_list:
        if isinstance(elem, dict):
            labels.append(str(elem.get("file") or elem.get("id") or elem))
        else:
            labels.append(str(elem))
    return _escape_md_cell(", ".join(labels))


def _format_dry_run_table(report: dict[str, Any]) -> str:
    subcmd = report.get("subcommand")
    is_chunk = report.get("batch_mode") == "chunk" or (
        "chunks" in report and not report.get("items")
    )

    if subcmd == "docs":
        if is_chunk:
            chunks = report.get("chunks") or []
            lines = [
                "| chunk_index | files | missing_flags | input_chars | questions | status |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
            for chunk in chunks:
                payload = chunk.get("payload") or {}
                in_chars = sum(len(b.get("text", "")) for b in payload.get("input") or [])
                q_count = len(payload.get("questions") or {})
                files_cell = _format_chunk_label_list(chunk.get("files"))
                flags_val = chunk.get("missing_flag_hints")
                flags_cell = (
                    _format_flag_hints_cell(flags_val) if flags_val is not None else "-"
                )
                lines.append(
                    f"| {chunk.get('chunk_index', 0)} | {files_cell} | {flags_cell} | "
                    f"{in_chars} | {q_count} | validated |"
                )
            lines.append("")
            chunk_count = report.get("chunk_count", len(chunks))
            lines.append(
                f"Summary: dry_run subcommand=docs total={report.get('total', 0)}, "
                f"batch_mode=chunk, chunk_count={chunk_count}"
            )
            return "\n".join(lines)

        lines = [
            "| file | staleness_days | missing_hints | missing_flags | input_chars | questions | status |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for item in report.get("items") or []:
            payload = item.get("payload") or {}
            in_chars = sum(len(b.get("text", "")) for b in payload.get("input") or [])
            q_count = len(payload.get("questions") or {})
            stale = item.get("staleness_days")
            stale_str = str(stale) if stale is not None else "-"
            hints = len(item.get("missing_path_hints") or [])
            flags_cell = _format_flag_hints_cell(item.get("missing_flag_hints"))
            lines.append(
                f"| {_escape_md_cell(item.get('file'))} | {stale_str} | {hints} | "
                f"{flags_cell} | {in_chars} | {q_count} | validated |"
            )
        lines.append("")
        lines.append(f"Summary: dry_run subcommand=docs total={report.get('total', 0)}")
        return "\n".join(lines)

    if subcmd == "backlog":
        payload = report.get("payload") or {}
        in_chars = sum(len(b.get("text", "")) for b in payload.get("input") or [])
        q_count = len(payload.get("questions") or {})
        lines = [
            "| id | question_key | location | section | text |",
            "| --- | --- | --- | --- | --- |",
        ]
        for item in report.get("items") or []:
            loc = (
                f"{item.get('file')}:{item.get('line')}"
                if item.get("file") and item.get("line") is not None
                else (item.get("file") or "-")
            )
            lines.append(
                f"| {_escape_md_cell(item.get('id'))} | {_escape_md_cell(item.get('question_key'))} | "
                f"{_escape_md_cell(loc)} | {_escape_md_cell(item.get('section'))} | "
                f"{_escape_md_cell(item.get('text'))} |"
            )
        lines.append("")
        lines.append(
            f"Summary: dry_run subcommand=backlog total={report.get('total', 0)}, "
            f"shared_input_chars={in_chars}, questions={q_count}"
        )
        return "\n".join(lines)

    if is_chunk:
        chunks = report.get("chunks") or []
        lines = [
            "| chunk_index | candidates | input_chars | questions | status |",
            "| --- | --- | --- | --- | --- |",
        ]
        for chunk in chunks:
            payload = chunk.get("payload") or {}
            in_chars = sum(len(b.get("text", "")) for b in payload.get("input") or [])
            q_count = len(payload.get("questions") or {})
            cand_raw = (
                chunk.get("ids")
                or chunk.get("candidates")
                or chunk.get("items")
                or chunk.get("files")
            )
            lines.append(
                f"| {chunk.get('chunk_index', 0)} | {_format_chunk_label_list(cand_raw)} | "
                f"{in_chars} | {q_count} | validated |"
            )
        lines.append("")
        chunk_count = report.get("chunk_count", len(chunks))
        lines.append(
            f"Summary: dry_run subcommand=candidates total={report.get('total', 0)}, "
            f"batch_mode=chunk, chunk_count={chunk_count}"
        )
        return "\n".join(lines)

    lines = [
        "| id | category | title | input_chars | questions | status |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in report.get("items") or []:
        payload = item.get("payload") or {}
        in_chars = sum(len(b.get("text", "")) for b in payload.get("input") or [])
        q_count = len(payload.get("questions") or {})
        lines.append(
            f"| {_escape_md_cell(item.get('id'))} | {_escape_md_cell(item.get('category'))} | "
            f"{_escape_md_cell(item.get('title'))} | {in_chars} | {q_count} | validated |"
        )
    lines.append("")
    lines.append(f"Summary: dry_run subcommand=candidates total={report.get('total', 0)}")
    return "\n".join(lines)


def format_report_table(report: dict[str, Any]) -> str:
    """3 サブコマンドの実行結果またはドライラン結果を Markdown 表形式へ整形する。"""
    subcmd = report.get("subcommand")
    status = report.get("status")

    if status == "dry_run":
        return _format_dry_run_table(report)

    if subcmd == "docs":
        results = report.get("results") or []
        lines = [
            "| file | bucket | action | conf | stale | broken | mech | sev | hints | flag_hints |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
        for row in results:
            conf = row.get("action_confidence")
            stale = row.get("stale_status_or_facts")
            broken = row.get("broken_or_obsolete_refs")
            mech = row.get("mechanizable_workflow")
            sev = row.get("drift_severity")
            hints = len(row.get("missing_path_hints") or [])
            flag_hints_cell = _format_flag_hints_cell(row.get("missing_flag_hints"))
            lines.append(
                f"| {_escape_md_cell(row.get('file'))} | {_escape_md_cell(row.get('bucket'))} | "
                f"{_escape_md_cell(row.get('recommended_action'))} | "
                f"{f'{conf:.2f}' if _is_real_number(conf) else '-'} | "
                f"{f'{stale:.2f}' if _is_real_number(stale) else '-'} | "
                f"{f'{broken:.2f}' if _is_real_number(broken) else '-'} | "
                f"{f'{mech:.2f}' if _is_real_number(mech) else '-'} | "
                f"{f'{sev:.2f}' if _is_real_number(sev) else '-'} | {hints} | {flag_hints_cell} |"
            )
        summary = report.get("summary") or {}
        lines.append("")
        lines.append(
            f"Summary: total={report.get('total', 0)}, "
            f"prioritize_for_audit={summary.get('prioritize_for_audit', 0)}, "
            f"mechanization_candidate={summary.get('mechanization_candidate', 0)}, "
            f"low_priority_clean={summary.get('low_priority_clean', 0)}"
        )
        usage = report.get("usage")
        if isinstance(usage, dict):
            lines.append(
                f"usage: input_tokens={usage.get('total_input_tokens')}, "
                f"output_tokens={usage.get('total_output_tokens')}"
            )
        if report.get("note"):
            lines.append(f"Note: {report['note']}")
        return "\n".join(lines)

    if subcmd == "backlog":
        results = report.get("results") or []
        lines = [
            "| id | location | section | status_choice | conf | needs_verification | text |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ]
        for row in results:
            loc = (
                f"{row.get('file')}:{row.get('line')}"
                if row.get("file") and row.get("line") is not None
                else (row.get("file") or "-")
            )
            conf = row.get("confidence")
            lines.append(
                f"| {_escape_md_cell(row.get('id'))} | {_escape_md_cell(loc)} | "
                f"{_escape_md_cell(row.get('section'))} | "
                f"{_escape_md_cell(row.get('status_choice'))} | "
                f"{f'{conf:.2f}' if _is_real_number(conf) else '-'} | "
                f"{'true' if row.get('needs_verification') else 'false'} | "
                f"{_escape_md_cell(row.get('text'))} |"
            )
        summary = report.get("summary") or {}
        lines.append("")
        lines.append(
            f"Summary: total={report.get('total', 0)}, "
            f"needs_verification={summary.get('needs_verification', 0)}, "
            f"still_open={summary.get('still_open', 0)}"
        )
        usage = report.get("usage")
        if isinstance(usage, dict):
            lines.append(
                f"usage: input_tokens={usage.get('total_input_tokens')}, "
                f"output_tokens={usage.get('total_output_tokens')}"
            )
        return "\n".join(lines)

    results = report.get("results") or []
    lines = [
        "| id | route | conf | single_track | discuss | mech | severity | parent_review | title |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in results:
        conf = row.get("route_confidence")
        fits = row.get("fits_single_track")
        disc = row.get("needs_discussion")
        mech = row.get("deterministic_mechanizable")
        sev = row.get("impact_severity")
        lines.append(
            f"| {_escape_md_cell(row.get('id'))} | {_escape_md_cell(row.get('dispatch_route'))} | "
            f"{f'{conf:.2f}' if _is_real_number(conf) else '-'} | "
            f"{f'{fits:.2f}' if _is_real_number(fits) else '-'} | "
            f"{f'{disc:.2f}' if _is_real_number(disc) else '-'} | "
            f"{f'{mech:.2f}' if _is_real_number(mech) else '-'} | "
            f"{f'{sev:.2f}' if _is_real_number(sev) else '-'} | "
            f"{'true' if row.get('needs_parent_review') else 'false'} | "
            f"{_escape_md_cell(row.get('title'))} |"
        )
    summary = report.get("summary") or {}
    lines.append("")
    lines.append(
        f"Summary: total={report.get('total', 0)}, "
        f"needs_parent_review={summary.get('needs_parent_review', 0)}, "
        f"ready={summary.get('ready', 0)}"
    )
    usage = report.get("usage")
    if isinstance(usage, dict):
        lines.append(
            f"usage: input_tokens={usage.get('total_input_tokens')}, "
            f"output_tokens={usage.get('total_output_tokens')}"
        )
    return "\n".join(lines)


def emit_report(
    report: dict[str, Any],
    output_format: str,
    *,
    stream: Any = None,
) -> bool:
    """レポートを指定形式で標準出力へ安全に書き出し、パイプ切断時は False を返す。"""
    if output_format == "table":
        text = format_report_table(report)
    else:
        text = json.dumps(report, ensure_ascii=False, indent=2)
    return decision_common.safe_write_stdout(text, stream=stream)


def emit_error(
    code: str,
    message: str,
    exit_code: int,
    output_format: str,
    api_key: str,
    *,
    stream: Any = None,
) -> None:
    """秘密情報をマスクした上で JSON またはプレーンテキスト形式のエラーを出力する。"""
    decision_common.emit_cli_error(
        code,
        message,
        exit_code,
        output_format,
        api_key,
        stream=stream,
    )
