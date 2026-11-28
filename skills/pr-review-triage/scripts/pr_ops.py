#!/usr/bin/env python3
"""PR レビュー運用（状態取得・不変条件検査・トリアージ反映・安全コミット＆push）統合 CLI。

外部依存を持たず Python 標準ライブラリのみで動作し、
全サブコマンドで秘密情報・BOM・置換文字 (U+FFFD)・想定外 ASCII 制御文字・単独 CR・保護ブランチ操作を事前検査する。
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Callable

_SCRIPTS_DIR = Path(__file__).resolve().parent
_DECISIONS_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "gemini-decisions-api" / "scripts"
_INVARIANT_SCRIPT = (
    Path(__file__).resolve().parents[2] / "invariant-gate" / "scripts" / "check_invariants_decision1.py"
)
_DEVIN_REVIEW_SCRIPT = _SCRIPTS_DIR / "check_devin_review.py"

for _dir in (_SCRIPTS_DIR, _DECISIONS_SCRIPTS_DIR):
    if str(_dir) not in sys.path:
        sys.path.insert(0, str(_dir))

import decision_hygiene  # noqa: E402
import pr_guardrails  # noqa: E402

EXIT_OK = 0
EXIT_VERIFY_FAILED = 1
EXIT_ERROR = 2

MAX_GRAPHQL_PAGES = 20
MAX_FILE_SECRET_SCAN_BYTES = 2 * 1024 * 1024

PRIVATE_KEY_EXACT_NAMES = frozenset(
    {
        "id_rsa",
        "id_ed25519",
        "id_ecdsa",
        "id_dsa",
        ".netrc",
        ".pypirc",
        ".npmrc",
    }
)
PRIVATE_KEY_EXTENSIONS = (".pem", ".key", ".p12", ".pfx", ".kdbx")
SENSITIVE_PATH_DIRS = frozenset({".ssh", ".gnupg"})

REPO_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
THREAD_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
COMMIT_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
GIT_OBJECT_SHA_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
SAFE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
DEFAULT_EXCLUDE_LOCKS = (
    "Cargo.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "uv.lock",
    "poetry.lock",
)
GITHUB_PR_URL_RE = re.compile(
    r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/pull/([1-9][0-9]*)(?:[/?#].*)?$"
)
GITHUB_REMOTE_RE = re.compile(
    r"^(?:https://github\.com/|ssh://git@github\.com/|git@github\.com:)([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)
UNEXPECTED_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\r(?!\n)")


def _find_unexpected_control_char_codes(text: str) -> list[str]:
    """想定外 ASCII 制御文字または単独 CR のコードポイントを重複なく返す。"""
    seen: set[str] = set()
    codes: list[str] = []
    for match in UNEXPECTED_CONTROL_CHAR_RE.finditer(text):
        code = f"U+{ord(match.group(0)):04X}"
        if code not in seen:
            seen.add(code)
            codes.append(code)
    return codes


def _has_unexpected_control_chars(text: str) -> bool:
    """想定外 ASCII 制御文字または単独 CR を含むか判定する。"""
    return bool(UNEXPECTED_CONTROL_CHAR_RE.search(text))

PROTECTED_BRANCHES = frozenset(
    {
        "main",
        "master",
        "develop",
        "dev",
        "trunk",
        "default",
        "prod",
        "production",
        "staging",
        "stage",
        "release",
        "gh-pages",
        "head",
        "tags",
    }
)
PROTECTED_BRANCH_PREFIXES = (
    "release/",
    "releases/",
    "prod/",
    "production/",
    "staging/",
    "stage/",
    "hotfix/",
    "tags/",
)

PLACEHOLDER_TOKENS = ("{{COMMIT_SHA}}", "{{COMMIT_SHORT}}", "<次コミットハッシュ>")

REVIEW_THREADS_QUERY = """
query($owner: String!, $repo: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      headRefOid
      reviewThreads(first: 100, after: $cursor) {
        pageInfo {
          hasNextPage
          endCursor
        }
        nodes {
          id
          isResolved
          isOutdated
          path
          line
          originalLine
          comments(first: 50) {
            pageInfo {
              hasNextPage
            }
            nodes {
              id
              author {
                login
              }
              body
              createdAt
              url
            }
          }
        }
      }
    }
  }
}
""".strip()

REVIEW_THREAD_IDS_QUERY = """
query($owner: String!, $repo: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $repo) {
    pullRequest(number: $number) {
      headRefOid
      reviewThreads(first: 100, after: $cursor) {
        pageInfo {
          hasNextPage
          endCursor
        }
        nodes {
          id
        }
      }
    }
  }
}
""".strip()

ADD_THREAD_REPLY_MUTATION = """
mutation($threadId: ID!, $body: String!) {
  addPullRequestReviewThreadReply(input: {pullRequestReviewThreadId: $threadId, body: $body}) {
    comment {
      id
      url
      body
    }
  }
}
""".strip()

RESOLVE_THREAD_MUTATION = """
mutation($threadId: ID!) {
  resolveReviewThread(input: {threadId: $threadId}) {
    thread {
      id
      isResolved
    }
  }
}
""".strip()


@dataclass
class CmdResult:
    """外部コマンド実行結果。"""

    returncode: int
    stdout: str
    stderr: str


CommandRunner = Callable[[list[str], Path, str | None], CmdResult]


class PrOpsError(RuntimeError):
    """pr_ops.py の入力検証・衛生検査・実行時エラー。"""

    def __init__(self, code: str, message: str, exit_code: int = EXIT_ERROR) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code


def _mask(text: str) -> str:
    return decision_hygiene.mask_secrets(
        text,
        extra_patterns=(decision_hygiene.BEARER_TOKEN_RE,),
    )


def _mask_json_strings(value: Any) -> Any:
    """JSON 互換構造内の全文字列値を再帰的にマスクする。"""
    if isinstance(value, str):
        return _mask(value)
    if isinstance(value, list):
        return [_mask_json_strings(elem) for elem in value]
    if isinstance(value, dict):
        return {k: _mask_json_strings(v) for k, v in value.items()}
    return value


def _default_runner(cmd: list[str], cwd: Path, input_text: str | None = None) -> CmdResult:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        input=input_text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
    )
    return CmdResult(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)


def _is_reparse_or_symlink(path: Path) -> bool:
    """パスがシンボリックリンクまたは Windows リパースポイントか判定する。"""
    try:
        if os.path.islink(path):
            return True
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if reparse_flag:
            st = os.lstat(path)
            if getattr(st, "st_file_attributes", 0) & reparse_flag:
                return True
        return False
    except OSError:
        return True


def _resolve_path_from_cwd(path_str: str, cwd: Path) -> Path:
    path = Path(path_str)
    if not path.is_absolute():
        return cwd / path
    return path


def _validate_non_secret_path(path_str: str, label: str, *, cwd: Path | None = None) -> Path:
    """機密ファイル・危険パス・シンボリックリンクを拒否し Path を返す。"""
    cleaned = (path_str or "").strip()
    if not cleaned:
        raise PrOpsError("invalid_path", f"{label} が空です。")
    if cleaned == "-":
        raise PrOpsError("invalid_path", f"{label} に '-' は指定できません。")
    if any(ord(ch) < 32 for ch in cleaned):
        raise PrOpsError("invalid_path", f"{label} に制御文字が含まれています。")

    if decision_hygiene.is_blocked_env_path(cleaned):
        raise PrOpsError("blocked_env_path", f"秘密情報を含む可能性があるため .env 系ファイルを {label} に指定できません: {cleaned}")

    norm = cleaned.replace("\\", "/")
    low_norm = norm.lower()
    parts = [p for p in low_norm.split("/") if p]
    base = parts[-1] if parts else ""

    if base in PRIVATE_KEY_EXACT_NAMES:
        raise PrOpsError("blocked_secret_path", f"秘密鍵または資格情報ファイルを {label} に指定できません: {cleaned}")
    if any(base.endswith(ext) and len(base) > len(ext) for ext in PRIVATE_KEY_EXTENSIONS):
        raise PrOpsError("blocked_secret_path", f"秘密鍵拡張子ファイルを {label} に指定できません: {cleaned}")
    if low_norm.endswith("/.aws/credentials") or low_norm == ".aws/credentials":
        raise PrOpsError("blocked_secret_path", f"AWS 資格情報ファイルを {label} に指定できません: {cleaned}")
    if any(part in SENSITIVE_PATH_DIRS for part in parts):
        raise PrOpsError("blocked_secret_path", f"機密ディレクトリ配下のファイルを {label} に指定できません: {cleaned}")

    base_cwd = cwd if cwd is not None else Path.cwd()
    target = _resolve_path_from_cwd(cleaned, base_cwd)
    if os.path.lexists(target) and _is_reparse_or_symlink(target):
        raise PrOpsError("symlink_rejected", f"シンボリックリンクまたはリパースポイントは {label} に指定できません: {cleaned}")
    return target


def _validate_text_hygiene(
    text: str,
    label: str,
    *,
    forbid_ufffd: bool = True,
    forbid_control_chars: bool = True,
) -> None:
    """秘密情報パターン、Bearer トークン、U+FFFD、想定外制御文字を検査する。"""
    hits = decision_hygiene.scan_text_for_secrets(text)
    if hits:
        raise PrOpsError(
            "secret_detected",
            f"{label} に秘密情報パターン（{', '.join(hits)}）が含まれるため処理を中断しました。",
        )
    if decision_hygiene.BEARER_TOKEN_RE.search(text):
        raise PrOpsError(
            "secret_detected",
            f"{label} に Bearer トークン形式の文字列が含まれるため処理を中断しました。",
        )
    if forbid_ufffd and "\ufffd" in text:
        raise PrOpsError(
            "replacement_char_detected",
            f"{label} に置換文字 (U+FFFD) が含まれています。",
        )
    if forbid_control_chars:
        ctrl_codes = _find_unexpected_control_char_codes(text)
        if ctrl_codes:
            raise PrOpsError(
                "control_char_detected",
                f"{label} に想定外の ASCII 制御文字または単独 CR（{', '.join(ctrl_codes)}）が含まれています。",
            )


def _read_text_file_checked(
    path_str: str,
    label: str,
    *,
    cwd: Path | None = None,
    forbid_ufffd: bool = True,
    forbid_control_chars: bool = True,
) -> str:
    """BOM なし UTF-8・リンク拒否・機密検査・U+FFFD・制御文字検査を通した上でファイルを読み込む。"""
    target = _validate_non_secret_path(path_str, label, cwd=cwd)
    if not target.exists() or not target.is_file():
        raise PrOpsError("input_not_found", f"{label} が見つかりません: {path_str}")
    try:
        raw_bytes = target.read_bytes()
    except OSError as exc:
        raise PrOpsError("input_read_error", f"{label} を読めません ({path_str}): {exc}") from exc

    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        raise PrOpsError("bom_rejected", f"{label} に UTF-8 BOM が含まれています（BOM なし UTF-8 のみ許可）: {path_str}")
    if raw_bytes.startswith((b"\xff\xfe", b"\xfe\xff")):
        raise PrOpsError("bom_rejected", f"{label} に UTF-16 BOM が含まれています（BOM なし UTF-8 のみ許可）: {path_str}")
    if b"\x00" in raw_bytes:
        raise PrOpsError("binary_rejected", f"{label} に NUL バイトが含まれています: {path_str}")

    try:
        text = raw_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PrOpsError("input_decode_error", f"{label} を UTF-8 として読めません ({path_str}): {exc}") from exc

    _validate_text_hygiene(
        text,
        label,
        forbid_ufffd=forbid_ufffd,
        forbid_control_chars=forbid_control_chars,
    )
    return text


def _read_json_file_checked(
    path_str: str,
    label: str,
    *,
    cwd: Path | None = None,
    forbid_ufffd: bool = True,
    forbid_control_chars: bool = True,
) -> Any:
    text = _read_text_file_checked(
        path_str,
        label,
        cwd=cwd,
        forbid_ufffd=forbid_ufffd,
        forbid_control_chars=forbid_control_chars,
    )
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise PrOpsError("invalid_json", f"{label} の JSON パースに失敗しました: {exc}") from exc

    for field_name, val in decision_hygiene.iter_string_fields(data, label):
        _validate_text_hygiene(
            val,
            field_name,
            forbid_ufffd=forbid_ufffd,
            forbid_control_chars=forbid_control_chars,
        )
    return data


def _write_utf8_file(target: Path, content: str) -> None:
    normalized = content.replace("\r\n", "\n").replace("\r", "\n")
    if normalized and not normalized.endswith("\n"):
        normalized += "\n"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(normalized, encoding="utf-8", newline="\n")


def _validate_branch_name(branch: str, *, allow_protected: bool = False) -> str:
    cleaned = (branch or "").strip()
    if not cleaned:
        raise PrOpsError("invalid_branch", "ブランチ名が空です（detached HEAD は不可）。")
    if not SAFE_REF_RE.fullmatch(cleaned):
        raise PrOpsError("invalid_branch", f"安全でないブランチ名です: {cleaned}")
    if cleaned.endswith(("/", ".", ".lock")) or "//" in cleaned or ".." in cleaned or "/." in cleaned or "./" in cleaned:
        raise PrOpsError("invalid_branch", f"安全でないブランチ名形式です: {cleaned}")
    if not allow_protected:
        low = cleaned.lower()
        if low in PROTECTED_BRANCHES or low.startswith(PROTECTED_BRANCH_PREFIXES):
            raise PrOpsError("protected_branch", f"保護ブランチ '{cleaned}' への操作は禁止されています。")
    return cleaned


def _validate_thread_id(thread_id: Any, label: str) -> str:
    if not isinstance(thread_id, str) or not THREAD_ID_RE.fullmatch(thread_id.strip()):
        raise PrOpsError("invalid_thread_id", f"{label} が不正な GraphQL thread ID です。")
    return thread_id.strip()


def _validate_commit_sha(raw: str | None) -> str | None:
    if raw is None:
        return None
    val = raw.strip()
    if not COMMIT_SHA_RE.fullmatch(val):
        raise PrOpsError("invalid_commit_sha", "--commit-sha は 7〜40 桁の 16 進文字列を指定してください。")
    return val.lower()


def _resolve_cwd(cwd_arg: str | None) -> Path:
    if not cwd_arg:
        return Path.cwd()
    p = Path(cwd_arg).absolute()
    if not p.exists() or not p.is_dir():
        raise PrOpsError("invalid_cwd", f"--cwd が有効なディレクトリではありません: {cwd_arg}")
    if _is_reparse_or_symlink(p):
        raise PrOpsError("symlink_rejected", f"--cwd にシンボリックリンク/リパースポイントは指定できません: {cwd_arg}")
    return p


def _parse_github_remote(url: str) -> str | None:
    m = GITHUB_REMOTE_RE.fullmatch(url.strip())
    if not m:
        return None
    owner, repo = m.groups()
    slug = f"{owner}/{repo}"
    return slug if REPO_SLUG_RE.fullmatch(slug) else None


def _resolve_repo_slug(repo_arg: str | None, cwd: Path, runner: CommandRunner) -> str:
    if repo_arg:
        cleaned = repo_arg.strip()
        if not REPO_SLUG_RE.fullmatch(cleaned):
            raise PrOpsError("invalid_repo", f"--repo は owner/repo 形式で指定してください: {repo_arg}")
        return cleaned

    res = runner(["git", "remote", "get-url", "origin"], cwd, None)
    if res.returncode == 0:
        slug = _parse_github_remote(res.stdout)
        if slug:
            return slug

    gh_res = runner(["gh", "repo", "view", "--json", "nameWithOwner"], cwd, None)
    if gh_res.returncode == 0:
        try:
            payload = json.loads(gh_res.stdout)
            slug = str(payload.get("nameWithOwner") or "").strip()
            if REPO_SLUG_RE.fullmatch(slug):
                return slug
        except json.JSONDecodeError:
            pass

    raise PrOpsError("repo_resolve_failed", "GitHub リポジトリ (owner/repo) を特定できませんでした。--repo を指定してください。")


def _resolve_repo_and_pr(
    repo_arg: str | None,
    pr_arg: int | None,
    cwd: Path,
    runner: CommandRunner,
) -> tuple[str, int]:
    """(owner/repo, pr_number) の組を一貫したリポジトリ基準で解決する。"""
    if pr_arg is not None:
        if pr_arg <= 0:
            raise PrOpsError("invalid_pr", "--pr は正の整数を指定してください。")
        return _resolve_repo_slug(repo_arg, cwd, runner), pr_arg

    if repo_arg:
        repo = _resolve_repo_slug(repo_arg, cwd, runner)
        br_res = runner(["git", "branch", "--show-current"], cwd, None)
        branch = br_res.stdout.strip() if br_res.returncode == 0 else ""
        if not branch:
            raise PrOpsError(
                "pr_resolve_failed",
                "--repo 指定時に --pr を省略するには作業ブランチが必要です（--pr を明示指定してください）。",
            )
        res = runner(["gh", "pr", "view", branch, "--repo", repo, "--json", "number"], cwd, None)
        if res.returncode != 0:
            raise PrOpsError("pr_resolve_failed", f"現在ブランチに紐づく PR を取得できませんでした: {_mask(res.stderr.strip())}")
        try:
            num = int(json.loads(res.stdout)["number"])
            if num <= 0:
                raise ValueError("non-positive")
            return repo, num
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise PrOpsError("pr_resolve_failed", f"PR 番号の解析に失敗しました: {exc}") from exc

    # --repo と --pr の両方が省略された場合は gh pr view の url から対象リポジトリと PR 番号を同時確定する
    gh_res = runner(["gh", "pr", "view", "--json", "number,url"], cwd, None)
    if gh_res.returncode == 0:
        try:
            data = json.loads(gh_res.stdout)
            num = int(data["number"])
            if num <= 0:
                raise ValueError("non-positive")
            url_val = str(data.get("url") or "").strip()
            url_m = GITHUB_PR_URL_RE.fullmatch(url_val)
            if url_m:
                return f"{url_m.group(1)}/{url_m.group(2)}", num
            return _resolve_repo_slug(None, cwd, runner), num
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            pass

    # gh pr view 単体が失敗する場合は origin + 現在ブランチへフォールバック
    repo = _resolve_repo_slug(None, cwd, runner)
    br_res = runner(["git", "branch", "--show-current"], cwd, None)
    branch = br_res.stdout.strip() if br_res.returncode == 0 else ""
    if branch:
        res = runner(["gh", "pr", "view", branch, "--repo", repo, "--json", "number"], cwd, None)
        if res.returncode == 0:
            try:
                num = int(json.loads(res.stdout)["number"])
                if num > 0:
                    return repo, num
            except (ValueError, KeyError, TypeError, json.JSONDecodeError):
                pass
    raise PrOpsError("pr_resolve_failed", f"現在ブランチに紐づく PR を取得できませんでした: {_mask(gh_res.stderr.strip())}")


def _run_gh_json(args: list[str], cwd: Path, runner: CommandRunner, *, input_obj: dict[str, Any] | None = None) -> Any:
    stdin_text = json.dumps(input_obj, ensure_ascii=False) if input_obj is not None else None
    res = runner(["gh", *args], cwd, stdin_text)
    if res.returncode != 0:
        detail = _mask(res.stderr.strip() or res.stdout.strip())
        raise PrOpsError("gh_command_failed", f"gh コマンド実行に失敗しました ({' '.join(args[:3])}): {detail}")
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError as exc:
        raise PrOpsError("gh_invalid_json", f"gh 出力の JSON パースに失敗しました: {exc}") from exc


def _fetch_pr_view(pr_num: int, repo: str, cwd: Path, runner: CommandRunner, *, fields: str) -> dict[str, Any]:
    data = _run_gh_json(["pr", "view", str(pr_num), "--repo", repo, "--json", fields], cwd, runner)
    if not isinstance(data, dict):
        raise PrOpsError("gh_invalid_json", "gh pr view の応答が JSON オブジェクトではありません。")
    return data


def _fetch_review_threads_graphql(
    owner: str,
    repo_name: str,
    pr_num: int,
    cwd: Path,
    runner: CommandRunner,
) -> tuple[str, list[dict[str, Any]]]:
    cursor: str | None = None
    threads: list[dict[str, Any]] = []
    head_oid = ""
    truncated_reason: str | None = None

    for page_idx in range(MAX_GRAPHQL_PAGES):
        variables: dict[str, Any] = {
            "owner": owner,
            "repo": repo_name,
            "number": pr_num,
            "cursor": cursor,
        }
        resp = _run_gh_json(
            ["api", "graphql", "--input", "-"],
            cwd,
            runner,
            input_obj={"query": REVIEW_THREADS_QUERY, "variables": variables},
        )
        if not isinstance(resp, dict) or resp.get("errors"):
            raise PrOpsError("graphql_error", f"GraphQL reviewThreads 取得エラー: {_mask(str(resp.get('errors') if isinstance(resp, dict) else resp))}")
        pr_node = ((resp.get("data") or {}).get("repository") or {}).get("pullRequest")
        if not isinstance(pr_node, dict):
            raise PrOpsError("graphql_error", "GraphQL 応答に pullRequest が含まれていません。")
        head_oid = str(pr_node.get("headRefOid") or head_oid)
        rt = pr_node.get("reviewThreads") or {}
        nodes = rt.get("nodes") or []
        for node in nodes:
            if not isinstance(node, dict):
                continue
            comments_conn = node.get("comments") or {}
            c_page_info = comments_conn.get("pageInfo") or {}
            if c_page_info.get("hasNextPage"):
                truncated_reason = f"スレッド {node.get('id')} のコメント件数が取得上限 (50 件) を超えました。"
            raw_comments = comments_conn.get("nodes") or []
            comments = [
                {
                    "id": c.get("id"),
                    "author": ((c.get("author") or {}).get("login") if isinstance(c.get("author"), dict) else None),
                    "body": c.get("body") or "",
                    "createdAt": c.get("createdAt") or "",
                    "url": c.get("url") or "",
                }
                for c in raw_comments
                if isinstance(c, dict)
            ]
            threads.append(
                {
                    "id": node.get("id"),
                    "isResolved": bool(node.get("isResolved")),
                    "isOutdated": bool(node.get("isOutdated")),
                    "path": node.get("path"),
                    "line": node.get("line"),
                    "originalLine": node.get("originalLine"),
                    "comments": comments,
                }
            )
        page_info = rt.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        cursor = page_info.get("endCursor")
        if not cursor or page_idx == MAX_GRAPHQL_PAGES - 1:
            truncated_reason = f"reviewThreads がページ取得上限 ({MAX_GRAPHQL_PAGES} ページ) を超えました。"
            break

    if truncated_reason is not None:
        raise PrOpsError("graphql_truncated", truncated_reason)

    return head_oid, threads


def _fetch_review_thread_ids_graphql(
    owner: str,
    repo_name: str,
    pr_num: int,
    cwd: Path,
    runner: CommandRunner,
) -> set[str]:
    """対象 PR に属する reviewThread ID 集合のみを取得する（コメント件数制限に左右されない）。"""
    cursor: str | None = None
    thread_ids: set[str] = set()
    for page_idx in range(MAX_GRAPHQL_PAGES):
        resp = _run_gh_json(
            ["api", "graphql", "--input", "-"],
            cwd,
            runner,
            input_obj={
                "query": REVIEW_THREAD_IDS_QUERY,
                "variables": {
                    "owner": owner,
                    "repo": repo_name,
                    "number": pr_num,
                    "cursor": cursor,
                },
            },
        )
        if not isinstance(resp, dict) or resp.get("errors"):
            raise PrOpsError("graphql_error", f"GraphQL reviewThreads ID 取得エラー: {_mask(str(resp.get('errors') if isinstance(resp, dict) else resp))}")
        pr_node = ((resp.get("data") or {}).get("repository") or {}).get("pullRequest")
        if not isinstance(pr_node, dict):
            raise PrOpsError("graphql_error", "GraphQL 応答に pullRequest が含まれていません。")
        rt = pr_node.get("reviewThreads") or {}
        for node in rt.get("nodes") or []:
            if isinstance(node, dict) and node.get("id"):
                thread_ids.add(str(node["id"]))
        page_info = rt.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        cursor = page_info.get("endCursor")
        if not cursor or page_idx == MAX_GRAPHQL_PAGES - 1:
            raise PrOpsError("graphql_truncated", f"reviewThreads がページ取得上限 ({MAX_GRAPHQL_PAGES} ページ) を超えました。")
    return thread_ids


def _summarize_checks(rollup: Any) -> dict[str, Any]:
    items = rollup if isinstance(rollup, list) else []
    passing: list[dict[str, str]] = []
    failing: list[dict[str, str]] = []
    pending: list[dict[str, str]] = []
    neutral: list[dict[str, str]] = []

    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("context") or "(unnamed)")
        status = str(item.get("status") or item.get("state") or "").upper()
        conclusion = str(item.get("conclusion") or "").upper()
        entry = {"name": name, "status": status, "conclusion": conclusion}
        if conclusion in {"SUCCESS"} or (not conclusion and status == "SUCCESS"):
            passing.append(entry)
        elif conclusion in {"FAILURE", "TIMED_OUT", "CANCELLED", "ACTION_REQUIRED", "STARTUP_FAILURE"} or status in {"FAILURE", "ERROR"}:
            failing.append(entry)
        elif conclusion in {"NEUTRAL", "SKIPPED"}:
            neutral.append(entry)
        else:
            pending.append(entry)

    return {
        "total": len(items),
        "passing_count": len(passing),
        "failing_count": len(failing),
        "pending_count": len(pending),
        "neutral_count": len(neutral),
        "failing": failing,
        "pending": pending,
        "passing": passing,
    }


def _run_devin_check(
    *,
    pr_url: str,
    commit_sha: str,
    trigger: bool,
    cwd: Path,
    runner: CommandRunner,
) -> tuple[dict[str, Any], int]:
    cmd = [
        sys.executable,
        str(_DEVIN_REVIEW_SCRIPT),
        "--pr-url",
        pr_url,
        "--commit-sha",
        commit_sha,
    ]
    if trigger:
        cmd.append("--trigger")
    res = runner(cmd, cwd, None)
    parsed: dict[str, Any]
    try:
        obj = json.loads(res.stdout)
        parsed = obj if isinstance(obj, dict) else {"raw_output": _mask(res.stdout)}
    except json.JSONDecodeError:
        parsed = {
            "decision": "parse_error",
            "stdout": _mask(res.stdout.strip()),
            "stderr": _mask(res.stderr.strip()),
        }
    return parsed, res.returncode


def _format_status_summary(payload: dict[str, Any]) -> str:
    pr = payload["pr"]
    threads = payload["review_threads"]
    checks = payload["checks"]
    guardrails = payload["guardrails"]
    lines = [
        f"PR #{pr['number']}: {pr['title']} ({pr['state']})",
        f"URL: {pr['url']}",
        f"Branch: {pr['headRefName']} -> {pr['baseRefName']} | HEAD: {pr['headRefOid']}",
        f"Review Threads: total={threads['total']}, unresolved={threads['unresolved_count']}, outdated={threads['outdated_count']}",
        f"Checks: total={checks['total']}, passing={checks['passing_count']}, failing={checks['failing_count']}, pending={checks['pending_count']}",
        f"Guardrails: active={guardrails['active_count']}, retired={guardrails['retired_count']}, next_id={guardrails['next_id']}",
    ]
    devin = payload.get("devin_review")
    if isinstance(devin, dict):
        lines.append(
            f"Devin Review: decision={devin.get('decision')} | can_conclude_clean={devin.get('can_conclude_clean')} | exit_code={payload.get('devin_review_exit_code')}"
        )
    if pr.get("body_control_char_found"):
        lines.append("WARNING: PR 本文に想定外の ASCII 制御文字または単独 CR が含まれています。")
    return "\n".join(lines)


def handle_status(args: argparse.Namespace, *, runner: CommandRunner) -> int:
    cwd = _resolve_cwd(args.cwd)
    out_target = _validate_non_secret_path(args.output, "--output", cwd=cwd) if args.output else None
    save_pr_target = _validate_non_secret_path(args.save_pr_json, "--save-pr-json", cwd=cwd) if args.save_pr_json else None

    repo, pr_num = _resolve_repo_and_pr(args.repo, args.pr, cwd, runner)
    owner, repo_name = repo.split("/", 1)

    pr_data = _fetch_pr_view(
        pr_num,
        repo,
        cwd,
        runner,
        fields="number,url,title,state,headRefName,headRefOid,baseRefName,body,comments,reviews,statusCheckRollup",
    )
    graphql_head, thread_nodes = _fetch_review_threads_graphql(owner, repo_name, pr_num, cwd, runner)

    sources = pr_guardrails.load_pr_sources(pr_data)
    guardrail_result = pr_guardrails.merge_guardrails(sources)
    checks_summary = _summarize_checks(pr_data.get("statusCheckRollup"))
    unresolved_threads = [t for t in thread_nodes if not t["isResolved"]]

    head_oid = str(pr_data.get("headRefOid") or graphql_head or "")
    pr_url = str(pr_data.get("url") or f"https://github.com/{repo}/pull/{pr_num}")
    body_control_char_found = _has_unexpected_control_chars(str(pr_data.get("body") or ""))

    payload: dict[str, Any] = {
        "ok": True,
        "repo": repo,
        "pr": {
            "number": int(pr_data.get("number") or pr_num),
            "url": pr_url,
            "title": str(pr_data.get("title") or ""),
            "state": str(pr_data.get("state") or ""),
            "headRefName": str(pr_data.get("headRefName") or ""),
            "headRefOid": head_oid,
            "baseRefName": str(pr_data.get("baseRefName") or ""),
            "body_control_char_found": body_control_char_found,
            "comments_count": len(pr_data.get("comments") or []) if isinstance(pr_data.get("comments"), list) else 0,
            "reviews_count": len(pr_data.get("reviews") or []) if isinstance(pr_data.get("reviews"), list) else 0,
        },
        "review_threads": {
            "total": len(thread_nodes),
            "unresolved_count": len(unresolved_threads),
            "outdated_count": sum(1 for t in thread_nodes if t["isOutdated"]),
            "unresolved": unresolved_threads,
            "nodes": thread_nodes,
        },
        "checks": checks_summary,
        "guardrails": guardrail_result,
    }

    devin_code = EXIT_OK
    if args.check_devin or args.trigger_devin:
        if not COMMIT_SHA_RE.fullmatch(head_oid):
            raise PrOpsError("invalid_head_oid", f"PR の headRefOid を取得できませんでした: {head_oid!r}")
        devin_payload, devin_code = _run_devin_check(
            pr_url=pr_url,
            commit_sha=head_oid,
            trigger=bool(args.trigger_devin),
            cwd=cwd,
            runner=runner,
        )
        payload["devin_review"] = devin_payload
        payload["devin_review_exit_code"] = devin_code

    masked_payload = _mask_json_strings(payload)

    if save_pr_target is not None:
        pr_snapshot = _mask_json_strings(
            {
                "number": masked_payload["pr"]["number"],
                "url": pr_url,
                "title": masked_payload["pr"]["title"],
                "state": masked_payload["pr"]["state"],
                "headRefName": masked_payload["pr"]["headRefName"],
                "headRefOid": head_oid,
                "baseRefName": masked_payload["pr"]["baseRefName"],
                "body": pr_data.get("body") or "",
                "comments": pr_data.get("comments") or [],
                "reviews": pr_data.get("reviews") or [],
            }
        )
        _write_utf8_file(save_pr_target, json.dumps(pr_snapshot, ensure_ascii=False, indent=2))

    rendered = (
        _format_status_summary(masked_payload)
        if args.format == "summary"
        else json.dumps(masked_payload, ensure_ascii=False, indent=2)
    )
    if out_target is not None:
        _write_utf8_file(out_target, rendered)
    sys.stdout.write(rendered + "\n")
    return devin_code


def _resolve_base_commit(base_ref: str, cwd: Path, runner: CommandRunner) -> str:
    """--base 引数のオプション注入を拒否し、Git 上の単一コミット SHA へ解決する。"""
    cleaned = (base_ref or "").strip()
    if (
        not cleaned
        or cleaned.startswith("-")
        or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in cleaned)
    ):
        raise PrOpsError("invalid_base_ref", f"安全でない --base 参照です: {base_ref}")
    res = runner(
        ["git", "rev-parse", "--verify", "--end-of-options", f"{cleaned}^{{commit}}"],
        cwd,
        None,
    )
    if res.returncode != 0 or not res.stdout.strip():
        raise PrOpsError(
            "invalid_base_ref",
            f"--base '{cleaned}' を有効なコミットとして解決できません: {_mask(res.stderr.strip())}",
        )
    resolved = res.stdout.strip()
    if not GIT_OBJECT_SHA_RE.fullmatch(resolved):
        raise PrOpsError("invalid_base_ref", f"--base の解決結果が不正です: {resolved}")
    return resolved


def _classify_untracked_for_index(rel_posix: str, file_path: Path) -> tuple[bool, str | None]:
    """未追跡ファイルを一時インデックスへ追加してよいか判定する。(include, skip_reason) を返す。"""
    base_name = rel_posix.rsplit("/", 1)[-1]
    if base_name in DEFAULT_EXCLUDE_LOCKS:
        return False, None
    if _is_reparse_or_symlink(file_path):
        return False, "symlink"
    if not file_path.is_file():
        return False, "not_regular_file"
    try:
        if file_path.stat().st_size > MAX_FILE_SECRET_SCAN_BYTES:
            return False, "exceeds_2MiB_limit"
        raw = file_path.read_bytes()
    except OSError:
        return False, "read_error"
    if b"\x00" in raw:
        return False, "binary"
    return True, None


def _run_git_env(
    cmd: list[str], cwd: Path, env: dict[str, str], input_text: str | None = None
) -> CmdResult:
    """指定環境変数（GIT_INDEX_FILE 等）で Git サブプロセスを実行する。"""
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        input=input_text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
    )
    return CmdResult(proc.returncode, proc.stdout or "", proc.stderr or "")


def _build_combined_worktree_diff(
    resolved_base_sha: str, cwd: Path, runner: CommandRunner
) -> tuple[str | None, list[str]]:
    """作業ツリーに未コミット変更がある場合、リポジトリルート基準の統合 diff（未追跡含む）とスキップ一覧を返す。"""
    top_res = runner(["git", "rev-parse", "--show-toplevel"], cwd, None)
    git_cwd = Path(top_res.stdout.strip()) if top_res.returncode == 0 and top_res.stdout.strip() else cwd
    status_res = runner(
        ["git", "-c", "core.quotePath=false", "status", "--porcelain", "--untracked-files=normal"],
        git_cwd,
        None,
    )
    if status_res.returncode != 0 or not status_res.stdout.strip():
        return None, []
    mb_res = runner(["git", "merge-base", resolved_base_sha, "HEAD"], git_cwd, None)
    diff_base = mb_res.stdout.strip() if mb_res.returncode == 0 and mb_res.stdout.strip() else resolved_base_sha
    if diff_base.startswith("-"):
        raise PrOpsError("invalid_base_ref", f"安全でない merge-base 結果です: {diff_base}")
    exclude_pathspecs = [f":(exclude,glob)**/{lock_name}" for lock_name in DEFAULT_EXCLUDE_LOCKS]

    real_git_dir: Path | None = None
    if (git_cwd / ".git").exists() or os.environ.get("GIT_DIR", "").strip():
        git_dir_res = runner(["git", "rev-parse", "--absolute-git-dir"], git_cwd, None)
        if git_dir_res.returncode == 0 and git_dir_res.stdout.strip():
            candidate_git_dir = Path(git_dir_res.stdout.strip())
            if candidate_git_dir.is_dir():
                real_git_dir = candidate_git_dir
    if real_git_dir is None:
        diff_cmd = [
            "git",
            "-c",
            "core.quotePath=false",
            "-c",
            "diff.noprefix=false",
            "-c",
            "diff.mnemonicPrefix=false",
            "diff",
            "--no-ext-diff",
            "--unified=15",
            diff_base,
            "--",
            ".",
            *exclude_pathspecs,
        ]
        diff_res = runner(diff_cmd, git_cwd, None)
        if diff_res.returncode != 0:
            return None, []
        return diff_res.stdout or "", []

    untracked_res = runner(
        ["git", "-c", "core.quotePath=false", "ls-files", "-z", "--others", "--exclude-standard", "--", "."],
        git_cwd,
        None,
    )
    untracked_paths: list[str] = []
    if untracked_res.returncode == 0 and untracked_res.stdout:
        untracked_paths = [
            raw.replace("\\", "/") for raw in untracked_res.stdout.split("\x00") if raw
        ]

    safe_untracked: list[str] = []
    skipped_untracked: list[str] = []
    for rel_posix in untracked_paths:
        include, skip_reason = _classify_untracked_for_index(rel_posix, git_cwd / rel_posix)
        if include:
            safe_untracked.append(rel_posix)
        elif skip_reason is not None:
            skipped_untracked.append(f"{rel_posix} ({skip_reason})")

    with tempfile.TemporaryDirectory(prefix="pr_ops_idx_") as tmp_dir:
        tmp_index = Path(tmp_dir) / "index"
        tmp_objects = Path(tmp_dir) / "objects"
        tmp_objects.mkdir()

        idx_res = runner(["git", "rev-parse", "--git-path", "index"], git_cwd, None)
        if idx_res.returncode == 0 and idx_res.stdout.strip():
            raw_idx = Path(idx_res.stdout.strip())
            real_index = raw_idx if raw_idx.is_absolute() else (git_cwd / raw_idx)
            if real_index.is_file():
                shutil.copy2(real_index, tmp_index)

        obj_res = runner(["git", "rev-parse", "--git-path", "objects"], git_cwd, None)
        if obj_res.returncode == 0 and obj_res.stdout.strip():
            raw_obj = Path(obj_res.stdout.strip())
            real_objects = (raw_obj if raw_obj.is_absolute() else (git_cwd / raw_obj)).resolve()
        else:
            real_objects = (real_git_dir / "objects").resolve()

        tmp_env = os.environ.copy()
        tmp_env["GIT_INDEX_FILE"] = str(tmp_index)
        tmp_env["GIT_OBJECT_DIRECTORY"] = str(tmp_objects)
        real_obj_str = str(real_objects)
        if os.pathsep in real_obj_str or '"' in real_obj_str:
            escaped_real_obj = real_obj_str.replace("\\", "\\\\").replace('"', '\\"')
            quoted_real_obj = '"' + escaped_real_obj + '"'
        else:
            quoted_real_obj = real_obj_str
        existing_alt = tmp_env.get("GIT_ALTERNATE_OBJECT_DIRECTORIES", "").strip()
        tmp_env["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = (
            f"{quoted_real_obj}{os.pathsep}{existing_alt}" if existing_alt else quoted_real_obj
        )

        if not tmp_index.exists():
            head_res = runner(["git", "rev-parse", "--verify", "--quiet", "HEAD"], git_cwd, None)
            if head_res.returncode == 0:
                rt_res = _run_git_env(["git", "read-tree", "HEAD"], git_cwd, tmp_env)
                if rt_res.returncode != 0:
                    raise PrOpsError(
                        "worktree_diff_failed",
                        f"作業ツリー統合 diff の生成に失敗しました（read-tree）: {_mask(rt_res.stderr.strip())}",
                    )

        add_u_res = _run_git_env(["git", "add", "-u"], git_cwd, tmp_env)
        if add_u_res.returncode != 0:
            raise PrOpsError(
                "worktree_diff_failed",
                f"作業ツリー統合 diff の生成に失敗しました（git add -u）: {_mask(add_u_res.stderr.strip())}",
            )

        if safe_untracked:
            add_untracked_env = {
                k: v
                for k, v in tmp_env.items()
                if k not in ("GIT_GLOB_PATHSPECS", "GIT_ICASE_PATHSPECS")
            }
            add_untracked_res = _run_git_env(
                ["git", "--literal-pathspecs", "add", "--pathspec-from-file=-", "--pathspec-file-nul"],
                git_cwd,
                add_untracked_env,
                input_text="\x00".join(safe_untracked) + "\x00",
            )
            if add_untracked_res.returncode != 0:
                raise PrOpsError(
                    "worktree_diff_failed",
                    f"作業ツリー統合 diff の生成に失敗しました（git add untracked）: {_mask(add_untracked_res.stderr.strip())}",
                )

        cached_diff_cmd = [
            "git",
            "-c",
            "core.quotePath=false",
            "-c",
            "diff.noprefix=false",
            "-c",
            "diff.mnemonicPrefix=false",
            "diff",
            "--cached",
            "--no-ext-diff",
            "--unified=15",
            diff_base,
            "--",
            ".",
            *exclude_pathspecs,
        ]
        diff_res = _run_git_env(cached_diff_cmd, git_cwd, tmp_env)
        if diff_res.returncode != 0:
            raise PrOpsError(
                "worktree_diff_failed",
                f"作業ツリー統合 diff の生成に失敗しました（git diff --cached）: {_mask(diff_res.stderr.strip())}",
            )
        return diff_res.stdout or "", skipped_untracked


def handle_invariant_check(args: argparse.Namespace, *, runner: CommandRunner) -> int:
    cwd = _resolve_cwd(args.cwd)
    for extra_rule in args.rules or []:
        _validate_non_secret_path(extra_rule, "--rules", cwd=cwd)

    top_res = runner(["git", "rev-parse", "--show-toplevel"], cwd, None)
    git_cwd = Path(top_res.stdout.strip()) if top_res.returncode == 0 and top_res.stdout.strip() else cwd
    resolved_base_sha = _resolve_base_commit(args.base, git_cwd, runner)

    if args.pr_json:
        pr_data = _read_json_file_checked(args.pr_json, "--pr-json", cwd=cwd, forbid_ufffd=False)
    else:
        repo, pr_num = _resolve_repo_and_pr(args.repo, args.pr, cwd, runner)
        pr_data = _fetch_pr_view(pr_num, repo, cwd, runner, fields="body,comments,reviews")

    sources = pr_guardrails.load_pr_sources(pr_data)
    guardrails_result = pr_guardrails.merge_guardrails(sources)
    if args.strict_guardrails and guardrails_result["warnings"]:
        raise PrOpsError(
            "guardrails_warnings",
            "再発防止策の抽出で警告が発生しました: " + "; ".join(guardrails_result["warnings"]),
        )

    combined_diff: str | None = None
    skipped_untracked: list[str] = []
    if not getattr(args, "committed_only", False):
        combined_diff, skipped_untracked = _build_combined_worktree_diff(resolved_base_sha, cwd, runner)

    if skipped_untracked:
        sys.stderr.write(
            "[WARN] 未追跡ファイルを検査対象外としました（サイズ上限超過・バイナリ・リンク等）: "
            + ", ".join(skipped_untracked)
            + "\n"
        )

    with tempfile.TemporaryDirectory(prefix="pr_ops_inv_") as tmpdir:
        cmd = [
            sys.executable,
            str(_INVARIANT_SCRIPT),
            "--format",
            args.format,
        ]
        if combined_diff is not None:
            diff_path = Path(tmpdir) / "combined.diff"
            _write_utf8_file(diff_path, combined_diff)
            cmd.extend(["--diff-file", str(diff_path)])
        else:
            cmd.extend(["--base", resolved_base_sha])

        all_rules: list[str] = [
            str(_resolve_path_from_cwd(extra_rule, cwd)) for extra_rule in (args.rules or [])
        ]
        if guardrails_result["active"]:
            rules_md_path = Path(tmpdir) / "pr-guardrails.md"
            rules_md_text = pr_guardrails.format_rules_markdown(guardrails_result)
            _write_utf8_file(rules_md_path, rules_md_text)
            all_rules.append(str(rules_md_path))
        if all_rules:
            cmd.extend(["--rules", *all_rules])

        for preset in args.preset or []:
            cmd.extend(["--preset", preset])
        if args.dry_run:
            cmd.append("--dry-run")

        res = runner(cmd, cwd, None)
        if res.stdout:
            sys.stdout.write(res.stdout)
            if not res.stdout.endswith("\n"):
                sys.stdout.write("\n")
        if res.stderr:
            sys.stderr.write(_mask(res.stderr))
            if not res.stderr.endswith("\n"):
                sys.stderr.write("\n")
        return res.returncode


def _replace_commit_placeholders(text: str, commit_sha: str | None) -> str:
    updated = text
    if commit_sha is not None:
        short_sha = commit_sha[:7]
        updated = updated.replace("{{COMMIT_SHA}}", commit_sha)
        updated = updated.replace("{{COMMIT_SHORT}}", short_sha)
        updated = updated.replace("<次コミットハッシュ>", short_sha)
    for token in PLACEHOLDER_TOKENS:
        if token in updated:
            raise PrOpsError(
                "unresolved_placeholder",
                f"未置換のコミットプレースホルダ {token} が残っています（--commit-sha を指定してください）。",
            )
    return updated


def _apply_placeholders_to_guardrail_items(items: Any, commit_sha: str | None) -> Any:
    if isinstance(items, list):
        return [_apply_placeholders_to_guardrail_items(elem, commit_sha) for elem in items]
    if isinstance(items, dict):
        if "items" in items and isinstance(items["items"], list):
            copied = dict(items)
            copied["items"] = _apply_placeholders_to_guardrail_items(items["items"], commit_sha)
            return copied
        copied = dict(items)
        for key in ("scope", "rule", "evidence", "reason"):
            if isinstance(copied.get(key), str):
                copied[key] = _replace_commit_placeholders(copied[key], commit_sha)
        return copied
    raise PrOpsError("invalid_guardrail_items", "guardrail_items は JSON 配列または {\"items\": [...]} である必要があります。")


def _collect_triage_plan(
    args: argparse.Namespace,
    cwd: Path,
    commit_sha: str | None,
) -> tuple[list[dict[str, Any]], list[str], str | None, Any, bool]:
    plan_data: dict[str, Any] = {}
    if args.plan:
        loaded = _read_json_file_checked(args.plan, "--plan", cwd=cwd, forbid_ufffd=True)
        if not isinstance(loaded, dict):
            raise PrOpsError("invalid_plan", "--plan は JSON オブジェクトである必要があります。")
        plan_data = loaded

    replies_raw = plan_data.get("replies") or []
    if not isinstance(replies_raw, list):
        raise PrOpsError("invalid_plan", "plan.replies は配列である必要があります。")
    replies: list[dict[str, Any]] = []
    for idx, entry in enumerate(replies_raw):
        if not isinstance(entry, dict):
            raise PrOpsError("invalid_plan", f"plan.replies[{idx}] はオブジェクトである必要があります。")
        tid = _validate_thread_id(entry.get("thread_id"), f"plan.replies[{idx}].thread_id")
        body = entry.get("body")
        if not isinstance(body, str) or not body.strip():
            raise PrOpsError("invalid_plan", f"plan.replies[{idx}].body は空でない文字列である必要があります。")
        resolved_body = _replace_commit_placeholders(body, commit_sha)
        _validate_text_hygiene(resolved_body, f"plan.replies[{idx}].body", forbid_ufffd=True)
        resolve_flag = entry.get("resolve", True)
        if not isinstance(resolve_flag, bool):
            raise PrOpsError("invalid_plan", f"plan.replies[{idx}].resolve は真偽値である必要があります。")
        replies.append({"thread_id": tid, "body": resolved_body, "resolve": resolve_flag})

    resolve_only_raw = plan_data.get("resolve_only") or []
    if not isinstance(resolve_only_raw, list):
        raise PrOpsError("invalid_plan", "plan.resolve_only は配列である必要があります。")
    resolve_only = [
        _validate_thread_id(tid, f"plan.resolve_only[{idx}]")
        for idx, tid in enumerate(resolve_only_raw)
    ]

    summary_text: str | None = None
    if args.summary_file:
        summary_text = _read_text_file_checked(args.summary_file, "--summary-file", cwd=cwd, forbid_ufffd=True)
    elif isinstance(plan_data.get("summary_comment_file"), str) and plan_data["summary_comment_file"].strip():
        summary_text = _read_text_file_checked(
            plan_data["summary_comment_file"], "plan.summary_comment_file", cwd=cwd, forbid_ufffd=True
        )
    elif plan_data.get("summary_comment") is not None:
        raw_sum = plan_data.get("summary_comment")
        if not isinstance(raw_sum, str):
            raise PrOpsError("invalid_plan", "plan.summary_comment は文字列である必要があります。")
        summary_text = raw_sum

    if summary_text is not None:
        summary_text = _replace_commit_placeholders(summary_text, commit_sha).strip()
        if not summary_text:
            summary_text = None
        else:
            _validate_text_hygiene(summary_text, "summary_comment", forbid_ufffd=True)

    guardrail_items: Any = None
    if args.guardrails_items:
        guardrail_items = _read_json_file_checked(args.guardrails_items, "--guardrails-items", cwd=cwd, forbid_ufffd=True)
    elif isinstance(plan_data.get("guardrail_items_file"), str) and plan_data["guardrail_items_file"].strip():
        guardrail_items = _read_json_file_checked(
            plan_data["guardrail_items_file"], "plan.guardrail_items_file", cwd=cwd, forbid_ufffd=True
        )
    elif plan_data.get("guardrail_items") is not None:
        guardrail_items = plan_data.get("guardrail_items")

    if guardrail_items is not None:
        guardrail_items = _apply_placeholders_to_guardrail_items(guardrail_items, commit_sha)

    collapsible = bool(args.collapsible or plan_data.get("collapsible_guardrails"))
    return replies, resolve_only, summary_text, guardrail_items, collapsible


def handle_apply_triage(args: argparse.Namespace, *, runner: CommandRunner) -> int:
    cwd = _resolve_cwd(args.cwd)
    commit_sha = _validate_commit_sha(args.commit_sha)
    replies, resolve_only, summary_text, guardrail_items, collapsible = _collect_triage_plan(args, cwd, commit_sha)

    if not replies and not resolve_only and summary_text is None and guardrail_items is None:
        raise PrOpsError("empty_plan", "適用対象の返信・Resolve・サマリ・再発防止策が 1 件も指定されていません。")

    repo, pr_num = _resolve_repo_and_pr(args.repo, args.pr, cwd, runner)
    owner, repo_name = repo.split("/", 1)

    existing_pr = _fetch_pr_view(pr_num, repo, cwd, runner, fields="headRefOid,body,comments,reviews")
    remote_head = str(existing_pr.get("headRefOid") or "").strip().lower()
    effective_sha = commit_sha
    if commit_sha is not None:
        if remote_head:
            if not remote_head.startswith(commit_sha):
                raise PrOpsError(
                    "commit_sha_mismatch",
                    f"PR #{pr_num} の HEAD ({remote_head}) が指定 --commit-sha ({commit_sha}) と一致しません。",
                )
            effective_sha = remote_head
            if effective_sha != commit_sha:
                replies, resolve_only, summary_text, guardrail_items, collapsible = _collect_triage_plan(
                    args, cwd, effective_sha
                )
        elif not args.dry_run:
            raise PrOpsError("invalid_head_oid", f"PR #{pr_num} の headRefOid を取得できませんでした。")

    guardrails_block: str | None = None
    guardrail_warnings: list[str] = []
    if guardrail_items is not None:
        existing_sources = pr_guardrails.load_pr_sources(existing_pr)
        existing_result = pr_guardrails.merge_guardrails(existing_sources)
        try:
            guardrails_block, guardrail_warnings = pr_guardrails.render_guardrail_block(
                guardrail_items,
                existing_result=existing_result,
                collapsible=collapsible,
            )
        except pr_guardrails.GuardrailError as exc:
            raise PrOpsError("guardrails_render_failed", f"再発防止策ブロック生成エラー: {_mask(exc.message)}") from exc

        if summary_text:
            final_summary: str | None = summary_text.rstrip() + "\n\n" + guardrails_block
        else:
            final_summary = guardrails_block
    else:
        final_summary = summary_text

    if final_summary is not None:
        _validate_text_hygiene(final_summary, "final_summary", forbid_ufffd=True)

    if args.dry_run:
        preview = {
            "ok": True,
            "dry_run": True,
            "repo": repo,
            "pr_number": pr_num,
            "commit_sha": effective_sha,
            "replies_count": len(replies),
            "replies": replies,
            "resolve_only": resolve_only,
            "has_summary": final_summary is not None,
            "summary_preview": final_summary,
            "guardrail_warnings": guardrail_warnings,
        }
        sys.stdout.write(json.dumps(preview, ensure_ascii=False, indent=2) + "\n")
        return EXIT_OK

    target_thread_ids = {item["thread_id"] for item in replies} | set(resolve_only)
    if target_thread_ids:
        valid_thread_ids = _fetch_review_thread_ids_graphql(owner, repo_name, pr_num, cwd, runner)
        foreign_ids = sorted(tid for tid in target_thread_ids if tid not in valid_thread_ids)
        if foreign_ids:
            raise PrOpsError(
                "foreign_thread_id",
                f"PR #{pr_num} に属さない reviewThread ID が含まれています: {', '.join(foreign_ids)}",
            )

    replied_ids: list[str] = []
    resolved_ids: list[str] = []
    for item in replies:
        tid = item["thread_id"]
        resp = _run_gh_json(
            ["api", "graphql", "--input", "-"],
            cwd,
            runner,
            input_obj={
                "query": ADD_THREAD_REPLY_MUTATION,
                "variables": {"threadId": tid, "body": item["body"]},
            },
        )
        if not isinstance(resp, dict) or resp.get("errors"):
            raise PrOpsError("graphql_mutation_failed", f"スレッド返信に失敗しました ({tid}): {_mask(str(resp))}")
        replied_ids.append(tid)
        if item["resolve"]:
            r_resp = _run_gh_json(
                ["api", "graphql", "--input", "-"],
                cwd,
                runner,
                input_obj={"query": RESOLVE_THREAD_MUTATION, "variables": {"threadId": tid}},
            )
            if not isinstance(r_resp, dict) or r_resp.get("errors"):
                raise PrOpsError("graphql_mutation_failed", f"スレッド Resolve に失敗しました ({tid}): {_mask(str(r_resp))}")
            resolved_ids.append(tid)

    for tid in resolve_only:
        r_resp = _run_gh_json(
            ["api", "graphql", "--input", "-"],
            cwd,
            runner,
            input_obj={"query": RESOLVE_THREAD_MUTATION, "variables": {"threadId": tid}},
        )
        if not isinstance(r_resp, dict) or r_resp.get("errors"):
            raise PrOpsError("graphql_mutation_failed", f"スレッド Resolve に失敗しました ({tid}): {_mask(str(r_resp))}")
        resolved_ids.append(tid)

    summary_posted = False
    if final_summary is not None:
        with tempfile.TemporaryDirectory(prefix="pr_ops_comment_") as tmpdir:
            summary_path = Path(tmpdir) / "summary.md"
            _write_utf8_file(summary_path, final_summary)
            res = runner(
                ["gh", "pr", "comment", str(pr_num), "--repo", repo, "--body-file", str(summary_path)],
                cwd,
                None,
            )
            if res.returncode != 0:
                raise PrOpsError("gh_comment_failed", f"PR サマリコメント投稿に失敗しました: {_mask(res.stderr.strip() or res.stdout.strip())}")
            summary_posted = True

    result: dict[str, Any] = {
        "ok": True,
        "dry_run": False,
        "repo": repo,
        "pr_number": pr_num,
        "replied_threads": replied_ids,
        "resolved_threads": resolved_ids,
        "summary_posted": summary_posted,
        "guardrail_warnings": guardrail_warnings,
    }

    exit_code = EXIT_OK
    if args.verify:
        head_after, threads_after = _fetch_review_threads_graphql(owner, repo_name, pr_num, cwd, runner)
        pr_after = _fetch_pr_view(pr_num, repo, cwd, runner, fields="body,comments,reviews")
        sources_after = pr_guardrails.load_pr_sources(pr_after)
        merged_after = pr_guardrails.merge_guardrails(sources_after)
        unresolved_after = [t["id"] for t in threads_after if not t["isResolved"]]

        ufffd_found = False
        control_char_found = False
        for src in sources_after:
            src_body = src.get("body") or ""
            if "\ufffd" in src_body:
                ufffd_found = True
            if _has_unexpected_control_chars(src_body):
                control_char_found = True
            if ufffd_found and control_char_found:
                break
        if not (ufffd_found and control_char_found):
            for th in threads_after:
                for comment in th.get("comments") or []:
                    comment_body = comment.get("body") or ""
                    if "\ufffd" in comment_body:
                        ufffd_found = True
                    if _has_unexpected_control_chars(comment_body):
                        control_char_found = True
                    if ufffd_found and control_char_found:
                        break
                if ufffd_found and control_char_found:
                    break

        commit_match = (head_after.lower() == effective_sha) if effective_sha is not None else None
        guardrails_strict_ok = len(merged_after["warnings"]) == 0
        verification_ok = (
            guardrails_strict_ok
            and not ufffd_found
            and not control_char_found
            and (commit_match is not False)
        )
        result["verification"] = {
            "head_ref_oid": head_after,
            "commit_sha_match": commit_match,
            "unresolved_count": len(unresolved_after),
            "unresolved_thread_ids": unresolved_after,
            "guardrails_strict_ok": guardrails_strict_ok,
            "guardrails_warnings": merged_after["warnings"],
            "guardrails_active_count": merged_after["active_count"],
            "ufffd_found": ufffd_found,
            "control_char_found": control_char_found,
        }
        if not verification_ok:
            result["ok"] = False
            exit_code = EXIT_VERIFY_FAILED

    sys.stdout.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return exit_code


def _validate_stage_file_arg(raw_path: str, cwd: Path) -> str:
    cleaned = (raw_path or "").strip()
    if not cleaned:
        raise PrOpsError("invalid_file_arg", "--files に空パスは指定できません。")
    if cleaned.startswith("-"):
        raise PrOpsError("invalid_file_arg", f"--files にオプション形式の値は指定できません: {cleaned}")
    norm = cleaned.replace("\\", "/")
    if norm in {".", "./"} or ".." in [p for p in norm.split("/") if p]:
        raise PrOpsError("invalid_file_arg", f"--files に '.' や '..' を含むパスは指定できません: {cleaned}")
    if any(ch in cleaned for ch in "*?[]:") and not re.match(r"^[A-Za-z]:[\\/]", cleaned):
        raise PrOpsError("invalid_file_arg", f"--files にワイルドカードや pathspec は指定できません: {cleaned}")
    if Path(cleaned).is_absolute():
        raise PrOpsError("invalid_file_arg", f"--files にはリポジトリ相対パスのみ指定してください: {cleaned}")

    target = _validate_non_secret_path(cleaned, "--files", cwd=cwd)
    if target.exists():
        if target.is_dir():
            raise PrOpsError("invalid_file_arg", f"--files にディレクトリは指定できません: {cleaned}")
        try:
            size = target.stat().st_size
            if size <= MAX_FILE_SECRET_SCAN_BYTES:
                raw_bytes = target.read_bytes()
                if b"\x00" not in raw_bytes:
                    text = raw_bytes.decode("utf-8", errors="replace")
                    _validate_text_hygiene(text, f"--files ({cleaned})", forbid_ufffd=False, forbid_control_chars=False)
        except OSError as exc:
            raise PrOpsError("input_read_error", f"ステージ対象ファイルを読めません ({cleaned}): {exc}") from exc
    return cleaned


def _get_origin_default_branch(cwd: Path, runner: CommandRunner) -> str | None:
    """ローカルに記録された origin の既定ブランチ名（独自名含む）を取得する。"""
    res = runner(["git", "symbolic-ref", "--short", "refs/remotes/origin/HEAD"], cwd, None)
    if res.returncode != 0:
        return None
    ref = res.stdout.strip()
    if ref.startswith("origin/"):
        return ref[len("origin/") :]
    return ref or None


def handle_commit_push(args: argparse.Namespace, *, runner: CommandRunner) -> int:
    cwd = _resolve_cwd(args.cwd)
    if args.remote != "origin":
        raise PrOpsError("invalid_remote", f"--remote は 'origin' のみ許可されています: {args.remote}")

    message_text = _read_text_file_checked(args.message_file, "--message-file", cwd=cwd, forbid_ufffd=True)
    if not message_text.strip():
        raise PrOpsError("empty_commit_message", "--message-file が空です。")

    staged_files = [_validate_stage_file_arg(f, cwd) for f in args.files]

    branch_res = runner(["git", "branch", "--show-current"], cwd, None)
    if branch_res.returncode != 0:
        raise PrOpsError("git_branch_failed", f"現在ブランチを取得できませんでした: {_mask(branch_res.stderr.strip())}")
    current_branch = _validate_branch_name(branch_res.stdout.strip(), allow_protected=False)
    origin_default = _get_origin_default_branch(cwd, runner)
    if origin_default and current_branch.lower() == origin_default.lower():
        raise PrOpsError(
            "protected_branch",
            f"origin の既定ブランチ '{current_branch}' への操作は禁止されています。",
        )
    if args.branch:
        requested = _validate_branch_name(args.branch, allow_protected=False)
        if requested != current_branch:
            raise PrOpsError(
                "branch_mismatch",
                f"--branch ({requested}) が現在のブランチ ({current_branch}) と一致しません。",
            )

    prefix_res = runner(["git", "rev-parse", "--show-prefix"], cwd, None)
    prefix = prefix_res.stdout.strip().replace("\\", "/") if prefix_res.returncode == 0 else ""
    if prefix and not prefix.endswith("/"):
        prefix += "/"
    requested_norm = {
        posixpath.normpath((prefix + p.replace("\\", "/")).lstrip("/"))
        for p in staged_files
    }
    cached_res = runner(
        ["git", "-c", "core.quotePath=false", "diff", "--cached", "--no-renames", "--name-only"],
        cwd,
        None,
    )
    if cached_res.returncode == 0:
        already_staged = {
            line.strip().replace("\\", "/")
            for line in cached_res.stdout.splitlines()
            if line.strip()
        }
        unexpected = sorted(already_staged - requested_norm)
        if unexpected:
            raise PrOpsError(
                "unexpected_staged_files",
                f"--files 指定外のファイルが既にステージされています: {', '.join(unexpected)}",
            )

    msg_path = _resolve_path_from_cwd(args.message_file, cwd)

    if args.dry_run:
        preview = {
            "ok": True,
            "dry_run": True,
            "branch": current_branch,
            "remote": "origin",
            "files": staged_files,
            "message_file": str(msg_path),
            "push": not args.no_push,
            "set_upstream": bool(args.set_upstream),
        }
        sys.stdout.write(json.dumps(preview, ensure_ascii=False, indent=2) + "\n")
        return EXIT_OK

    add_res = runner(["git", "add", "--", *staged_files], cwd, None)
    if add_res.returncode != 0:
        raise PrOpsError("git_add_failed", f"git add に失敗しました: {_mask(add_res.stderr.strip() or add_res.stdout.strip())}")

    commit_res = runner(["git", "commit", "-F", str(msg_path)], cwd, None)
    if commit_res.returncode != 0:
        raise PrOpsError("git_commit_failed", f"git commit に失敗しました: {_mask(commit_res.stderr.strip() or commit_res.stdout.strip())}")

    sha_res = runner(["git", "rev-parse", "HEAD"], cwd, None)
    if sha_res.returncode != 0:
        raise PrOpsError("git_rev_parse_failed", f"コミット SHA の取得に失敗しました: {_mask(sha_res.stderr.strip())}")
    commit_sha = sha_res.stdout.strip().lower()

    pushed = False
    if not args.no_push:
        push_cmd = ["git", "push"]
        if args.set_upstream:
            push_cmd.append("-u")
        push_cmd.extend(["origin", current_branch])
        push_res = runner(push_cmd, cwd, None)
        if push_res.returncode != 0:
            raise PrOpsError("git_push_failed", f"git push に失敗しました: {_mask(push_res.stderr.strip() or push_res.stdout.strip())}")
        pushed = True

    out = {
        "ok": True,
        "dry_run": False,
        "branch": current_branch,
        "remote": "origin",
        "files": staged_files,
        "commit_sha": commit_sha,
        "commit_short": commit_sha[:7],
        "pushed": pushed,
    }
    sys.stdout.write(json.dumps(out, ensure_ascii=False, indent=2) + "\n")
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PR レビュー運用の統合 CLI（status / invariant-check / apply-triage / commit-push）"
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    status_p = subparsers.add_parser("status", help="PR 状態・チェック・GraphQL スレッド・再発防止策・Devin Review 状態を取得する")
    status_p.add_argument("--pr", type=int, default=None, help="対象 PR 番号（省略時は現在ブランチの PR）")
    status_p.add_argument("--repo", default=None, help="owner/repo 形式のリポジトリ（省略時は origin から解決）")
    status_p.add_argument("--cwd", default=None, help="作業ディレクトリ")
    status_p.add_argument("--check-devin", action="store_true", help="Devin Review API の状態も合わせて照会する")
    status_p.add_argument("--trigger-devin", action="store_true", help="Devin Review を明示トリガする（--check-devin を含む）")
    status_p.add_argument("--output", default=None, help="出力結果の保存先パス（UTF-8 BOM なし）")
    status_p.add_argument("--save-pr-json", default=None, help="pr_guardrails / invariant-check 向け PR JSON の保存先パス")
    status_p.add_argument("--format", choices=("json", "summary"), default="json", help="標準出力形式（既定: json）")

    inv_p = subparsers.add_parser("invariant-check", help="PR 内再発防止策を抽出し invariant-gate で差分を検査する")
    inv_p.add_argument("--pr", type=int, default=None, help="対象 PR 番号")
    inv_p.add_argument("--pr-json", default=None, help="取得済み PR JSON ファイルパス")
    inv_p.add_argument("--repo", default=None, help="owner/repo 形式のリポジトリ")
    inv_p.add_argument("--base", default="origin/main", help="比較ベース ref（既定: origin/main）")
    inv_p.add_argument("--committed-only", action="store_true", help="未コミット作業ツリーを含めずコミット済み差分 (base...HEAD) のみ検査する")
    inv_p.add_argument("--cwd", default=None, help="作業ディレクトリ")
    inv_p.add_argument("--rules", action="append", default=[], help="追加ルール Markdown パス（複数指定可）")
    inv_p.add_argument("--preset", action="append", default=[], help="追加プリセット名（複数指定可）")
    inv_p.add_argument("--dry-run", action="store_true", help="invariant-gate をドライラン実行する")
    inv_p.add_argument("--strict-guardrails", action="store_true", help="再発防止策抽出の警告をエラーとして終了コード 2 で止める")
    inv_p.add_argument("--format", choices=("json", "table"), default="json", help="invariant-gate 出力形式")

    apply_p = subparsers.add_parser("apply-triage", help="スレッド返信・Resolve・再発防止策付きサマリ投稿と事後検証を実行する")
    apply_p.add_argument("--pr", type=int, default=None, help="対象 PR 番号")
    apply_p.add_argument("--repo", default=None, help="owner/repo 形式のリポジトリ")
    apply_p.add_argument("--cwd", default=None, help="作業ディレクトリ")
    apply_p.add_argument("--plan", default=None, help="返信・Resolve・サマリ定義 JSON ファイルパス")
    apply_p.add_argument("--summary-file", default=None, help="サマリコメント本文 Markdown ファイルパス")
    apply_p.add_argument("--guardrails-items", default=None, help="再発防止策項目 JSON ファイルパス")
    apply_p.add_argument("--collapsible", action="store_true", help="再発防止策ブロックを <details> 折りたたみ形式にする")
    apply_p.add_argument("--commit-sha", default=None, help="プレースホルダ置換に使う確定コミット SHA（7〜40 桁 16 進）")
    apply_p.add_argument("--no-verify", dest="verify", action="store_false", help="反映後の GraphQL 再取得・strict 復元検証をスキップする")
    apply_p.set_defaults(verify=True)
    apply_p.add_argument("--dry-run", action="store_true", help="GitHub を変更せず適用内容をプレビューする")

    cp_p = subparsers.add_parser("commit-push", help="明示ファイルのみ安全に stage / commit / push する")
    cp_p.add_argument("--files", nargs="+", required=True, help="git add 対象のリポジトリ相対ファイルパス一覧")
    cp_p.add_argument("--message-file", required=True, help="BOM なし UTF-8 のコミットメッセージファイルパス")
    cp_p.add_argument("--branch", default=None, help="期待する作業ブランチ名（現在ブランチと一致強制）")
    cp_p.add_argument("--remote", default="origin", help="push 先リモート（origin のみ許可）")
    cp_p.add_argument("-u", "--set-upstream", action="store_true", help="git push に -u を付与する")
    cp_p.add_argument("--no-push", action="store_true", help="コミットのみ行い push しない")
    cp_p.add_argument("--cwd", default=None, help="作業ディレクトリ")
    cp_p.add_argument("--dry-run", action="store_true", help="git 状態を変更せず実行計画のみ表示する")

    return parser


def run_cli(argv: list[str] | None = None, *, runner: CommandRunner = _default_runner) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.subcommand == "status":
        return handle_status(args, runner=runner)
    if args.subcommand == "invariant-check":
        return handle_invariant_check(args, runner=runner)
    if args.subcommand == "apply-triage":
        return handle_apply_triage(args, runner=runner)
    if args.subcommand == "commit-push":
        return handle_commit_push(args, runner=runner)
    return EXIT_ERROR


def main(argv: list[str] | None = None, *, runner: CommandRunner = _default_runner) -> int:
    decision_hygiene.configure_utf8_stdio()
    try:
        return run_cli(argv, runner=runner)
    except PrOpsError as exc:
        sys.stderr.write(f"[ERROR:{exc.code}] {_mask(exc.message)}\n")
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
