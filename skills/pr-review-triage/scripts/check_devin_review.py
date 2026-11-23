#!/usr/bin/env python3
"""Devin API v3 の組織スコープ pr-reviews で Devin Review の最新状態を確認・再トリガする CLI。

GitHub GraphQL だけでは判別しづらい「0 件完了 vs 解析中 vs 未実行」を機械判定する。
環境変数 DEVIN_API_KEY および DEVIN_ORG_ID のみから認証情報を読み取り、外部依存を持たない。
"""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import re
import sys
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

_DECISIONS_SCRIPTS_DIR = (
    Path(__file__).resolve().parents[2] / "gemini-decisions-api" / "scripts"
)
if str(_DECISIONS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_DECISIONS_SCRIPTS_DIR))

import decision_hygiene  # noqa: E402

DEFAULT_API_BASE_URL = "https://api.devin.ai"
DEFAULT_TIMEOUT = 20.0
USER_AGENT = "shared-skills-pr-review-triage/1.0"

EXIT_OK = 0
EXIT_INPUT_OR_CONFIG_ERROR = 2
EXIT_AUTH_ERROR = 3
EXIT_RATE_LIMITED = 4
EXIT_API_ERROR = 5

_PR_SHORTHAND_RE = re.compile(
    r"^([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)#([1-9][0-9]*)$"
)
_PR_PATH_RE = re.compile(
    r"^/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull/([1-9][0-9]*)"
    r"(?:/(?:files|commits(?:/[0-9a-fA-F]{7,40})?|checks|changes)?)?$"
)
_COMMIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class InputValidationError(ValueError):
    """CLI 引数または入力値の検証エラー。"""


def mask_text(text: str, api_key: str | None, org_id: str | None) -> str:
    """API キー、組織 ID、Bearer トークン等の機密情報を [REDACTED] へマスクする。"""
    return decision_hygiene.mask_secrets(
        text,
        secrets=(api_key, org_id),
        extra_patterns=(decision_hygiene.BEARER_TOKEN_RE,),
    )


def normalize_pr_url(raw: str) -> str:
    """GitHub PR URL または owner/repo#num 短縮記法を正規 URL へ正規化する。"""
    value = raw.strip()
    if not value:
        raise InputValidationError("--pr-url が空です。")

    shorthand = _PR_SHORTHAND_RE.match(value)
    if shorthand:
        owner, repo, number = shorthand.groups()
        return f"https://github.com/{owner}/{repo}/pull/{number}"

    parsed = urllib.parse.urlparse(value)
    if parsed.scheme.lower() != "https":
        raise InputValidationError("--pr-url は https://github.com/... 形式で指定してください。")
    if parsed.username is not None or parsed.password is not None:
        raise InputValidationError("--pr-url に認証情報を含めることはできません。")

    host = (parsed.hostname or "").lower()
    if host not in {"github.com", "www.github.com"}:
        raise InputValidationError("--pr-url のホストは github.com のみ許可されています。")
    try:
        port = parsed.port
    except ValueError as exc:
        raise InputValidationError(f"--pr-url のポート指定が不正です: {exc}") from exc
    if port is not None:
        raise InputValidationError("--pr-url にポート番号を含めることはできません。")

    match = _PR_PATH_RE.match(parsed.path)
    if not match:
        raise InputValidationError(
            "--pr-url は https://github.com/<owner>/<repo>/pull/<number> 形式で指定してください。"
        )
    owner, repo, number = match.groups()
    return f"https://github.com/{owner}/{repo}/pull/{number}"


def normalize_commit_sha(raw: str | None) -> str | None:
    """コミット SHA（7〜40 桁 16 進）を検証し小文字へ正規化する。"""
    if raw is None:
        return None
    value = raw.strip()
    if not _COMMIT_SHA_RE.match(value):
        raise InputValidationError(
            "--commit-sha は 7〜40 桁の 16 進文字列で指定してください。"
        )
    return value.lower()


def validate_api_base_url(raw: str) -> str:
    """API ベース URL を検証する。既定 URL 以外はループバックアドレスのみ許可する。"""
    value = raw.strip().rstrip("/")
    if not value:
        raise InputValidationError("--api-base-url が空です。")

    parsed = urllib.parse.urlparse(value)
    if parsed.username is not None or parsed.password is not None:
        raise InputValidationError("--api-base-url に認証情報を含めることはできません。")
    if parsed.query or parsed.fragment or parsed.path:
        raise InputValidationError("--api-base-url にパス、クエリ、フラグメントは指定できません。")

    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    try:
        port = parsed.port
    except ValueError as exc:
        raise InputValidationError(f"--api-base-url のポート指定が不正です: {exc}") from exc

    if scheme == "https" and host == "api.devin.ai" and port in (None, 443):
        return value
    if scheme in {"http", "https"} and host in _LOOPBACK_HOSTS:
        return value
    raise InputValidationError(
        "--api-base-url に既定以外の外部ホストは指定できません（ループバックのみ許可）。"
    )


def validate_timeout(raw: float) -> float:
    """タイムアウト秒数が有限かつ正の値であることを検証する。"""
    if not math.isfinite(raw) or raw <= 0:
        raise InputValidationError("--timeout は 0 より大きい有限の数値で指定してください。")
    return float(raw)


def _base_result(
    *,
    configured: bool,
    missing_env: list[str],
    action: str,
    dry_run: bool,
    pr_url: str | None,
    requested_commit_sha: str | None,
    decision: str,
    can_conclude_clean: bool = False,
    http_status: int | None = None,
    review_status: str | None = None,
    commit_sha: str | None = None,
    commit_match: bool | None = None,
    repo_path: str | None = None,
    pr_number: int | None = None,
    created_at: str | None = None,
    retry_after_seconds: int | None = None,
    error_detail: str | None = None,
) -> dict[str, Any]:
    return {
        "configured": configured,
        "missing_env": missing_env,
        "action": action,
        "dry_run": dry_run,
        "pr_url": pr_url,
        "requested_commit_sha": requested_commit_sha,
        "http_status": http_status,
        "review_status": review_status,
        "commit_sha": commit_sha,
        "commit_match": commit_match,
        "repo_path": repo_path,
        "pr_number": pr_number,
        "created_at": created_at,
        "decision": decision,
        "can_conclude_clean": can_conclude_clean,
        "retry_after_seconds": retry_after_seconds,
        "error_detail": error_detail,
    }


def _extract_error_detail(
    body_text: str,
    api_key: str | None,
    org_id: str | None,
    fallback: str,
) -> str:
    stripped = body_text.strip()
    detail = fallback
    if stripped:
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, dict):
                for key in ("detail", "message", "error", "title"):
                    val = parsed.get(key)
                    if isinstance(val, str) and val.strip():
                        detail = val.strip()
                        break
                else:
                    detail = stripped[:300]
            else:
                detail = stripped[:300]
        except json.JSONDecodeError:
            detail = stripped[:300]
    return mask_text(detail, api_key, org_id)


def _parse_retry_after(headers: Any) -> int | None:
    if headers is None:
        return None
    raw = headers.get("Retry-After")
    if not isinstance(raw, str):
        return None
    stripped = raw.strip()
    if stripped.isdigit():
        return int(stripped)
    return None


def _is_commit_match(requested_sha: str | None, response_sha: Any) -> bool | None:
    if requested_sha is None:
        return None
    if not isinstance(response_sha, str) or not response_sha.strip():
        return False
    actual = response_sha.strip().lower()
    if len(requested_sha) == 40:
        return actual == requested_sha
    return actual.startswith(requested_sha)


def _populate_review_fields(result: dict[str, Any], data: dict[str, Any]) -> None:
    if isinstance(data.get("status"), str):
        result["review_status"] = data["status"]
    if isinstance(data.get("commit_sha"), str):
        result["commit_sha"] = data["commit_sha"]
    if isinstance(data.get("repo_path"), str):
        result["repo_path"] = data["repo_path"]
    if isinstance(data.get("pr_number"), int) and not isinstance(data.get("pr_number"), bool):
        result["pr_number"] = data["pr_number"]
    if isinstance(data.get("created_at"), str):
        result["created_at"] = data["created_at"]


def _execute_get(
    *,
    api_base_url: str,
    api_key: str,
    org_id: str,
    pr_url: str,
    requested_commit_sha: str | None,
    timeout: float,
    missing_env: list[str],
) -> tuple[dict[str, Any], int]:
    params: dict[str, str] = {"pr_url": pr_url}
    if requested_commit_sha is not None:
        params["commit_sha"] = requested_commit_sha
    org_segment = urllib.parse.quote(org_id, safe="")
    url = f"{api_base_url}/v3/organizations/{org_segment}/pr-reviews?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    return _perform_request(
        req=req,
        action="get",
        api_key=api_key,
        org_id=org_id,
        pr_url=pr_url,
        requested_commit_sha=requested_commit_sha,
        timeout=timeout,
        missing_env=missing_env,
    )


def _execute_trigger(
    *,
    api_base_url: str,
    api_key: str,
    org_id: str,
    pr_url: str,
    requested_commit_sha: str | None,
    timeout: float,
    missing_env: list[str],
) -> tuple[dict[str, Any], int]:
    org_segment = urllib.parse.quote(org_id, safe="")
    url = f"{api_base_url}/v3/organizations/{org_segment}/pr-reviews"
    payload = json.dumps({"pr_url": pr_url}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        },
    )
    return _perform_request(
        req=req,
        action="trigger",
        api_key=api_key,
        org_id=org_id,
        pr_url=pr_url,
        requested_commit_sha=requested_commit_sha,
        timeout=timeout,
        missing_env=missing_env,
    )


def _perform_request(
    *,
    req: urllib.request.Request,
    action: str,
    api_key: str,
    org_id: str,
    pr_url: str,
    requested_commit_sha: str | None,
    timeout: float,
    missing_env: list[str],
) -> tuple[dict[str, Any], int]:
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status_code = int(resp.status)
            body_text = resp.read().decode("utf-8", errors="replace")
            return _handle_success_response(
                action=action,
                status_code=status_code,
                body_text=body_text,
                api_key=api_key,
                org_id=org_id,
                pr_url=pr_url,
                requested_commit_sha=requested_commit_sha,
                missing_env=missing_env,
            )
    except urllib.error.HTTPError as exc:
        status_code = int(exc.code)
        try:
            body_text = exc.read().decode("utf-8", errors="replace")
        except Exception:
            body_text = ""
        retry_after = _parse_retry_after(exc.headers)
        return _handle_http_error(
            action=action,
            status_code=status_code,
            body_text=body_text,
            retry_after=retry_after,
            api_key=api_key,
            org_id=org_id,
            pr_url=pr_url,
            requested_commit_sha=requested_commit_sha,
            missing_env=missing_env,
        )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        detail = mask_text(f"{type(exc).__name__}: {exc}", api_key, org_id)
        return (
            _base_result(
                configured=True,
                missing_env=missing_env,
                action=action,
                dry_run=False,
                pr_url=pr_url,
                requested_commit_sha=requested_commit_sha,
                decision="api_error",
                can_conclude_clean=False,
                error_detail=detail,
            ),
            EXIT_API_ERROR,
        )


def _handle_success_response(
    *,
    action: str,
    status_code: int,
    body_text: str,
    api_key: str,
    org_id: str,
    pr_url: str,
    requested_commit_sha: str | None,
    missing_env: list[str],
) -> tuple[dict[str, Any], int]:
    if action == "trigger" and status_code in (200, 202):
        result = _base_result(
            configured=True,
            missing_env=missing_env,
            action="trigger",
            dry_run=False,
            pr_url=pr_url,
            requested_commit_sha=requested_commit_sha,
            http_status=status_code,
            decision="triggered",
            can_conclude_clean=False,
        )
        if body_text.strip():
            try:
                parsed = json.loads(body_text)
                if isinstance(parsed, dict):
                    _populate_review_fields(result, parsed)
                    result["commit_match"] = _is_commit_match(
                        requested_commit_sha, result["commit_sha"]
                    )
            except json.JSONDecodeError:
                pass
        return result, EXIT_OK

    if action == "get" and status_code == 200:
        try:
            parsed = json.loads(body_text)
        except json.JSONDecodeError as exc:
            detail = mask_text(f"API 応答が不正な JSON です: {exc}", api_key, org_id)
            return (
                _base_result(
                    configured=True,
                    missing_env=missing_env,
                    action="get",
                    dry_run=False,
                    pr_url=pr_url,
                    requested_commit_sha=requested_commit_sha,
                    http_status=status_code,
                    decision="api_error",
                    can_conclude_clean=False,
                    error_detail=detail,
                ),
                EXIT_API_ERROR,
            )

        if not isinstance(parsed, dict):
            return (
                _base_result(
                    configured=True,
                    missing_env=missing_env,
                    action="get",
                    dry_run=False,
                    pr_url=pr_url,
                    requested_commit_sha=requested_commit_sha,
                    http_status=status_code,
                    decision="api_error",
                    can_conclude_clean=False,
                    error_detail="API 応答が JSON オブジェクトではありません。",
                ),
                EXIT_API_ERROR,
            )

        result = _base_result(
            configured=True,
            missing_env=missing_env,
            action="get",
            dry_run=False,
            pr_url=pr_url,
            requested_commit_sha=requested_commit_sha,
            http_status=status_code,
            decision="unknown_status",
            can_conclude_clean=False,
        )
        _populate_review_fields(result, parsed)
        commit_match = _is_commit_match(requested_commit_sha, result["commit_sha"])
        result["commit_match"] = commit_match

        raw_status = parsed.get("status")
        status_str = raw_status if isinstance(raw_status, str) and raw_status else "unknown"
        result["review_status"] = status_str

        if commit_match is False:
            result["decision"] = "stale_commit"
            result["can_conclude_clean"] = False
        elif status_str == "completed":
            result["decision"] = "completed"
            result["can_conclude_clean"] = True
        elif status_str in {"pending", "running"}:
            result["decision"] = "in_progress"
            result["can_conclude_clean"] = False
        else:
            result["decision"] = "unknown_status"
            result["can_conclude_clean"] = False
        return result, EXIT_OK

    return (
        _base_result(
            configured=True,
            missing_env=missing_env,
            action=action,
            dry_run=False,
            pr_url=pr_url,
            requested_commit_sha=requested_commit_sha,
            http_status=status_code,
            decision="api_error",
            can_conclude_clean=False,
            error_detail=f"予期しない HTTP ステータス {status_code} を受信しました。",
        ),
        EXIT_API_ERROR,
    )


def _handle_http_error(
    *,
    action: str,
    status_code: int,
    body_text: str,
    retry_after: int | None,
    api_key: str,
    org_id: str,
    pr_url: str,
    requested_commit_sha: str | None,
    missing_env: list[str],
) -> tuple[dict[str, Any], int]:
    detail = _extract_error_detail(
        body_text, api_key, org_id, fallback=f"HTTP {status_code} エラー"
    )

    if action == "get" and status_code == 404:
        return (
            _base_result(
                configured=True,
                missing_env=missing_env,
                action="get",
                dry_run=False,
                pr_url=pr_url,
                requested_commit_sha=requested_commit_sha,
                http_status=404,
                review_status="not_found",
                decision="not_found",
                can_conclude_clean=False,
                error_detail=detail,
            ),
            EXIT_OK,
        )

    if action == "trigger" and status_code == 409:
        return (
            _base_result(
                configured=True,
                missing_env=missing_env,
                action="trigger",
                dry_run=False,
                pr_url=pr_url,
                requested_commit_sha=requested_commit_sha,
                http_status=409,
                decision="already_running",
                can_conclude_clean=False,
                error_detail=detail,
            ),
            EXIT_OK,
        )

    if status_code in (401, 403):
        return (
            _base_result(
                configured=True,
                missing_env=missing_env,
                action=action,
                dry_run=False,
                pr_url=pr_url,
                requested_commit_sha=requested_commit_sha,
                http_status=status_code,
                decision="auth_error",
                can_conclude_clean=False,
                error_detail=detail,
            ),
            EXIT_AUTH_ERROR,
        )

    if status_code == 429:
        return (
            _base_result(
                configured=True,
                missing_env=missing_env,
                action=action,
                dry_run=False,
                pr_url=pr_url,
                requested_commit_sha=requested_commit_sha,
                http_status=429,
                decision="rate_limited",
                can_conclude_clean=False,
                retry_after_seconds=retry_after,
                error_detail=detail,
            ),
            EXIT_RATE_LIMITED,
        )

    return (
        _base_result(
            configured=True,
            missing_env=missing_env,
            action=action,
            dry_run=False,
            pr_url=pr_url,
            requested_commit_sha=requested_commit_sha,
            http_status=status_code,
            decision="api_error",
            can_conclude_clean=False,
            error_detail=detail,
        ),
        EXIT_API_ERROR,
    )


def format_summary(result: dict[str, Any]) -> str:
    """判定結果辞書を人間向けの短い日本語要約テキストへ整形する。"""
    lines = [
        f"decision={result['decision']} | action={result['action']} | can_conclude_clean={result['can_conclude_clean']}",
        f"pr_url={result.get('pr_url') or '-'} | configured={result['configured']}",
    ]
    if result.get("http_status") is not None or result.get("review_status") is not None:
        lines.append(
            f"http_status={result.get('http_status')} | review_status={result.get('review_status')} | commit_sha={result.get('commit_sha') or '-'} | commit_match={result.get('commit_match')}"
        )
    if result.get("retry_after_seconds") is not None:
        lines.append(f"retry_after_seconds={result['retry_after_seconds']}")
    if result.get("error_detail"):
        lines.append(f"detail={result['error_detail']}")
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Devin API v3 の組織スコープ pr-reviews で Devin Review 状態を確認・再トリガする CLI"
    )
    parser.add_argument(
        "--pr-url",
        required=True,
        help="対象 GitHub PR の URL（または owner/repo#num）",
    )
    parser.add_argument(
        "--commit-sha",
        default=None,
        help="照合対象のコミット SHA（7〜40 桁 16 進）。省略時は PR の HEAD を参照",
    )
    parser.add_argument(
        "--trigger",
        action="store_true",
        help="POST で Devin Review を手動トリガする（省略時は読み取り専用の GET）",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="外部通信を行わず、正規化済み入力と予定リクエストのみを出力する",
    )
    parser.add_argument(
        "--require-configured",
        action="store_true",
        help="GET 時も環境変数未設定をエラー（終了コード 2）として扱う",
    )
    parser.add_argument(
        "--format",
        choices=("json", "summary"),
        default="json",
        help="出力形式（既定: json）",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP タイムアウト秒数（既定: {DEFAULT_TIMEOUT}）",
    )
    parser.add_argument(
        "--api-base-url",
        default=DEFAULT_API_BASE_URL,
        help=f"Devin API ベース URL（既定: {DEFAULT_API_BASE_URL}、テスト時はループバックのみ許可）",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    decision_hygiene.configure_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    api_key = os.environ.get("DEVIN_API_KEY", "").strip() or None
    org_id = os.environ.get("DEVIN_ORG_ID", "").strip() or None
    missing_env: list[str] = []
    if not api_key:
        missing_env.append("DEVIN_API_KEY")
    if not org_id:
        missing_env.append("DEVIN_ORG_ID")
    configured = not missing_env
    action = "trigger" if args.trigger else "get"

    def emit(payload: dict[str, Any], code: int) -> int:
        if args.format == "summary":
            text = format_summary(payload)
            print(mask_text(text, api_key, org_id))
        else:
            serialized = json.dumps(payload, indent=2, ensure_ascii=False)
            print(mask_text(serialized, api_key, org_id))
        return code

    pr_url: str | None = None
    requested_commit_sha: str | None = None
    try:
        pr_url = normalize_pr_url(args.pr_url)
        requested_commit_sha = normalize_commit_sha(args.commit_sha)
        api_base_url = validate_api_base_url(args.api_base_url)
        timeout = validate_timeout(args.timeout)
    except InputValidationError as exc:
        err_result = _base_result(
            configured=configured,
            missing_env=missing_env,
            action=action,
            dry_run=bool(args.dry_run),
            pr_url=pr_url,
            requested_commit_sha=requested_commit_sha,
            decision="invalid_input",
            can_conclude_clean=False,
            error_detail=mask_text(str(exc), api_key, org_id),
        )
        return emit(err_result, EXIT_INPUT_OR_CONFIG_ERROR)

    if args.dry_run:
        endpoint_template = f"{api_base_url}/v3/organizations/[ORG_ID]/pr-reviews"
        headers_preview: dict[str, str] = {
            "Authorization": "Bearer [REDACTED]",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }
        preview: dict[str, Any] = {
            "method": "POST" if args.trigger else "GET",
            "endpoint_template": endpoint_template,
            "headers": headers_preview,
        }
        if args.trigger:
            headers_preview["Content-Type"] = "application/json"
            preview["body"] = {"pr_url": pr_url}
        else:
            query: dict[str, str] = {"pr_url": pr_url}
            if requested_commit_sha is not None:
                query["commit_sha"] = requested_commit_sha
            preview["query"] = query

        dry_result = _base_result(
            configured=configured,
            missing_env=missing_env,
            action=action,
            dry_run=True,
            pr_url=pr_url,
            requested_commit_sha=requested_commit_sha,
            decision="dry_run",
            can_conclude_clean=False,
        )
        dry_result["request_preview"] = preview
        return emit(dry_result, EXIT_OK)

    if not configured:
        if args.trigger or args.require_configured:
            cfg_err = _base_result(
                configured=False,
                missing_env=missing_env,
                action=action,
                dry_run=False,
                pr_url=pr_url,
                requested_commit_sha=requested_commit_sha,
                decision="config_error",
                can_conclude_clean=False,
                error_detail=f"必要な環境変数が未設定です: {', '.join(missing_env)}",
            )
            return emit(cfg_err, EXIT_INPUT_OR_CONFIG_ERROR)

        fallback_result = _base_result(
            configured=False,
            missing_env=missing_env,
            action="get",
            dry_run=False,
            pr_url=pr_url,
            requested_commit_sha=requested_commit_sha,
            decision="fallback_github_only",
            can_conclude_clean=False,
        )
        return emit(fallback_result, EXIT_OK)

    assert api_key is not None and org_id is not None
    if args.trigger:
        result, exit_code = _execute_trigger(
            api_base_url=api_base_url,
            api_key=api_key,
            org_id=org_id,
            pr_url=pr_url,
            requested_commit_sha=requested_commit_sha,
            timeout=timeout,
            missing_env=missing_env,
        )
    else:
        result, exit_code = _execute_get(
            api_base_url=api_base_url,
            api_key=api_key,
            org_id=org_id,
            pr_url=pr_url,
            requested_commit_sha=requested_commit_sha,
            timeout=timeout,
            missing_env=missing_env,
        )
    return emit(result, exit_code)


if __name__ == "__main__":
    sys.exit(main())
