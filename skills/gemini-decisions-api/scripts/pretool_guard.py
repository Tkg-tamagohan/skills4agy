#!/usr/bin/env python3
"""ハイブリッド PreToolUse 安全ガードレール CLI。

第 1 段の決定論的ローカル判定（0 ms、API 非呼び出し）と、
曖昧コマンドに対する第 2 段の Gemini Decision 1 判定を組み合わせて
PreToolUse の decision（allow / deny / force_ask / ask）を返す。
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Callable

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import decision_hygiene as dh  # noqa: E402
import run_decisions as rd  # noqa: E402

DECISION1_TIMEOUT_SECONDS = 8.0
FALLBACK_REASON = "Decision 1 guard unavailable; fallback to standard confirmation."

SHELL_META_RE = re.compile(r"[;&|><`\r\n\x00]|\$\(|\$\{")
DISALLOWED_WHITELIST_ANYWHERE_RE = re.compile(r"[`\r\n\x00]|\$\(|\$\{")

SAFE_ENV_VAR_VALIDATORS: dict[str, re.Pattern[str]] = {
    "PYTHONUTF8": re.compile(r"^[01]$"),
    "PYTHONIOENCODING": re.compile(
        r"^(?:utf-?8|ascii|latin-?1|cp932)(?::(?:strict|ignore|replace|surrogateescape|backslashreplace))?$",
        re.IGNORECASE,
    ),
    "PYTHONDONTWRITEBYTECODE": re.compile(r"^[01]$"),
    "PYTHONUNBUFFERED": re.compile(r"^[01]$"),
    "NO_COLOR": re.compile(r"^(?:0|1|true|false)$", re.IGNORECASE),
    "LANG": re.compile(
        r"^(?:C|POSIX|C\.UTF-?8|[A-Za-z]{2,3}(?:_[A-Za-z]{2})?\.(?:UTF-?8|utf-?8))$"
    ),
    "LC_ALL": re.compile(
        r"^(?:C|POSIX|C\.UTF-?8|[A-Za-z]{2,3}(?:_[A-Za-z]{2})?\.(?:UTF-?8|utf-?8))$"
    ),
    "LC_CTYPE": re.compile(
        r"^(?:C|POSIX|C\.UTF-?8|[A-Za-z]{2,3}(?:_[A-Za-z]{2})?\.(?:UTF-?8|utf-?8))$"
    ),
}

PS_ENV_ASSIGN_RE = re.compile(
    r"^(?i:\$env:)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s\"';&|><`$\\]+))$"
)
POSIX_ENV_ASSIGN_PREFIX_RE = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*)=(?:\"([^\"]*)\"|'([^']*)'|([^\s\"';&|><`$\\]+))\s+"
)
PS_FAILFAST_GUARD_RE = re.compile(
    r"^if\s*\(\s*(?:\$LASTEXITCODE\s*-ne\s*0|(?:!|-not\s+)\$\?)\s*\)\s*"
    r"\{\s*exit\s+(?:\$LASTEXITCODE|[1-9]\d{0,2})\s*\}$",
    re.IGNORECASE,
)
SAFE_CD_COMMANDS = frozenset({"set-location", "cd", "sl", "chdir", "push-location", "pushd"})
SENSITIVE_CD_DIR_NAMES = frozenset(
    {".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".gcloud"}
)
WINDOWS_DRIVE_PREFIX_RE = re.compile(r"^[A-Za-z]:(?:[\\/]|$)")
SAFE_PYTHON_SHORT_FLAGS = frozenset({"B", "u", "s", "E", "I"})
MAX_WHITELIST_SEGMENTS = 10

SAFE_ENV_FILENAMES = dh.SAFE_ENV_BASENAMES

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

EXTERNAL_TRANSFER_COMMANDS = frozenset(
    {
        "curl",
        "wget",
        "invoke-webrequest",
        "invoke-restmethod",
        "iwr",
        "irm",
        "gh",
        "scp",
        "sftp",
        "rsync",
        "nc",
        "ncat",
        "netcat",
        "socat",
        "ftp",
        "tftp",
        "http",
        "xh",
    }
)

DESTRUCTIVE_DISK_COMMANDS = frozenset(
    {
        "fdisk",
        "parted",
        "gdisk",
        "diskpart",
        "format-volume",
        "clear-disk",
        "initialize-disk",
        "shutdown",
        "reboot",
        "halt",
        "poweroff",
        "stop-computer",
        "restart-computer",
    }
)

COMMAND_WRAPPERS = frozenset({"sudo", "env", "nohup", "command", "time"})
SHELL_WRAPPERS = frozenset({"sh", "bash", "zsh", "dash", "cmd", "powershell", "pwsh"})
CODE_EXEC_SINKS = frozenset(
    SHELL_WRAPPERS
    | {
        "iex",
        "invoke-expression",
        "invoke-command",
        "icm",
        "start-process",
        "saps",
        "start",
        "eval",
        "exec",
        "source",
        "python",
        "python3",
        "py",
        "node",
        "deno",
        "bun",
        "ruby",
        "perl",
        "php",
        "awk",
        "gawk",
        "sed",
        "xargs",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "ssh",
        "slogin",
        "rsh",
        "docker",
        "podman",
        "kubectl",
        "wsl",
        "su",
        "doas",
        "nsenter",
        "chroot",
        "winrm",
        "psexec",
        "enter-pssession",
        "new-pssession",
    }
)
SAFE_POSIX_HEREDOC_RECEIVERS = frozenset({"cat", "tee"})
SAFE_POSIX_HEREDOC_OUTER_COMMANDS = frozenset(
    {
        "cat",
        "tee",
        "cd",
        "set-location",
        "sl",
        "chdir",
        "push-location",
        "pushd",
        "mkdir",
        "ls",
        "dir",
        "wc",
        "test",
        "echo",
        "printf",
        "touch",
    }
)
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
TEAMWORK_SENDER_RE = re.compile(
    r"\[Message\]\s+timestamp=\S+\s+sender="
    r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b"
)
MAX_TEAMWORK_PARENT_DEPTH = 8
RG_VALUE_LONG_OPTS = frozenset(
    {
        "--regexp",
        "--file",
        "--glob",
        "--iglob",
        "--type",
        "--type-not",
        "--type-add",
        "--type-clear",
        "--max-count",
        "--max-columns",
        "--max-depth",
        "--max-filesize",
        "--after-context",
        "--before-context",
        "--context",
        "--threads",
        "--encoding",
        "--color",
        "--colors",
        "--hostname-bin",
        "--path-separator",
        "--sort",
        "--sortr",
        "--engine",
        "--context-separator",
        "--field-context-separator",
        "--field-match-separator",
        "--replace",
        "--dfa-size-limit",
        "--regex-size-limit",
    }
)
RG_VALUE_SHORT_CHARS = frozenset(
    {"e", "f", "g", "t", "T", "m", "M", "d", "A", "B", "C", "j", "E", "r"}
)
SAFE_RELATIVE_TEMP_ROOTS = frozenset(
    {
        "tmp",
        "temp",
        ".tmp",
        ".temp",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".cache",
        "dist",
        "build",
        "coverage",
    }
)
SAFE_CACHE_DIR_NAMES = frozenset(
    {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tmp", ".temp"}
)
SAFE_TEMP_PARENT_NAMES = frozenset({"tmp", "temp", ".tmp", ".temp"})

GIT_VALUE_GLOBAL_OPTS = frozenset(
    {"-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env"}
)
GIT_SAFE_GLOBAL_FLAGS = frozenset({"--no-pager", "-p", "--paginate"})
GIT_READONLY_SUBCOMMANDS = frozenset(
    {"status", "diff", "log", "show", "rev-parse", "describe", "ls-files", "ls-tree", "grep"}
)
GIT_SAFE_PUSH_REMOTES = frozenset({"origin"})
GIT_SAFE_PUSH_FLAGS = frozenset(
    {"-u", "--set-upstream", "-n", "--dry-run", "-q", "--quiet", "-v", "--verbose", "--porcelain"}
)
GIT_SAFE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
GIT_PROTECTED_PUSH_BRANCHES = frozenset(
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
GIT_PROTECTED_PUSH_PREFIXES = (
    "release/",
    "releases/",
    "prod/",
    "production/",
    "staging/",
    "stage/",
    "hotfix/",
    "tags/",
)

BEARER_RE = re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]{4,}")
GOOG_HEADER_QUOTED_RE = re.compile(
    r"(?i)(x-goog-api-key\s*[:=]\s*)([\"'])(?:\\.|(?!\2).)+\2"
)
GOOG_HEADER_PLAIN_RE = re.compile(r"(?i)(x-goog-api-key\s*[:=]\s*)([^\s;|&\"'`]+)")
GOOGLE_KEY_RE = dh.GOOGLE_API_KEY_RE
GH_TOKEN_RE = dh.GITHUB_TOKEN_RE
GH_PAT_RE = dh.GITHUB_PAT_RE
SK_TOKEN_RE = dh.SECRET_KEY_PREFIX_RE
AWS_AKIA_RE = dh.AWS_ACCESS_KEY_RE
ASSIGN_QUOTED_RE = re.compile(
    r"(?i)([A-Za-z0-9_-]*(?:api_?key|apikey|secret|token|password|passwd|credential|key)\s*=\s*)"
    r"([\"'])(?:\\.|(?!\2).)+\2"
)
ASSIGN_PLAIN_RE = re.compile(
    r"(?i)([A-Za-z0-9_-]*(?:api_?key|apikey|secret|token|password|passwd|credential|key)\s*=\s*)"
    r"([^\s;|&\"'`]+)"
)
PEM_BLOCK_RE = dh.PRIVATE_KEY_BLOCK_RE

DECISION1_QUESTIONS: dict[str, dict[str, Any]] = {
    "risk_level": {
        "type": "choice",
        "instructions": (
            "Classify the operational risk of executing this shell command "
            "in the specified working directory."
        ),
        "criteria": {
            "safe_readonly": (
                "Purely read-only inspection, listing, searching, or local unit tests "
                "with no external or destructive side effects."
            ),
            "local_reversible": (
                "Local workspace build, edit, or reversible development step "
                "without destroying data or mutating remote production state."
            ),
            "destructive_irreversible": (
                "Irreversible file or history deletion, disk/permission modification, "
                "force-push, or remote/production-impacting mutation."
            ),
            "secret_exposure": (
                "Reading, printing, exfiltrating, or transmitting credentials, tokens, "
                "private keys, or sensitive environment files."
            ),
            "other": "Insufficient context or does not match the categories above.",
        },
    },
    "needs_confirm": {
        "type": "noul",
        "instructions": (
            "Does this shell command perform an irreversible, destructive, "
            "production-impacting, or secret-exposing operation that requires "
            "explicit user confirmation?"
        ),
    },
}


def redact_secrets(text: str, extra_secrets: tuple[str, ...] = ()) -> str:
    """送信前およびエラーログ出力向けに秘密情報やトークンをマスクする。"""
    masked = text
    masked = BEARER_RE.sub(r"\g<1>[REDACTED]", masked)
    masked = GOOG_HEADER_QUOTED_RE.sub(r"\g<1>\g<2>[REDACTED]\g<2>", masked)
    masked = GOOG_HEADER_PLAIN_RE.sub(r"\g<1>[REDACTED]", masked)
    masked = ASSIGN_QUOTED_RE.sub(r"\g<1>\g<2>[REDACTED]\g<2>", masked)
    masked = ASSIGN_PLAIN_RE.sub(r"\g<1>[REDACTED]", masked)
    return dh.mask_secrets(masked, secrets=extra_secrets)


def _tokenize_command(command: str) -> list[str]:
    """Windows パス内のバックスラッシュを保持しつつ引用符単位で分割する。"""
    tokens: list[str] = []
    buf: list[str] = []
    in_token = False
    quote: str | None = None
    i = 0
    n = len(command)

    while i < n:
        ch = command[i]
        if quote is not None:
            if ch == quote:
                quote = None
            elif quote == '"' and ch == "\\" and i + 1 < n and command[i + 1] == '"':
                buf.append('"')
                i += 1
            else:
                buf.append(ch)
            i += 1
            continue

        if ch.isspace():
            if in_token:
                tokens.append("".join(buf))
                buf = []
                in_token = False
            i += 1
            continue

        in_token = True
        if ch in ("'", '"'):
            quote = ch
        else:
            buf.append(ch)
        i += 1

    if quote is not None:
        raise ValueError("Unclosed quote in command.")
    if in_token:
        tokens.append("".join(buf))
    return tokens


def _tokenize_lossy(segment: str) -> list[str]:
    """ブラックリスト検査用に未閉じクォートでも可能な限りトークン化する。"""
    try:
        return _tokenize_command(segment)
    except ValueError:
        return segment.split()


def _split_top_level_segments_raw(text: str, *, posix_shell: bool = False) -> list[str]:
    """連結記号・パイプ・改行および $() / バッククォート内をセグメント分割する（従来分割）。"""
    raw_parts = re.split(r"&&|\|\||[;|&`]|[\r\n]+", text)
    segments: list[str] = []
    for part in raw_parts:
        stripped = part.strip()
        if not stripped:
            continue
        segments.append(stripped)
        for m in re.finditer(r"\$\(([^)]+)\)", stripped):
            if posix_shell:
                backslashes = 0
                k = m.start() - 1
                while k >= 0 and stripped[k] == "\\":
                    backslashes += 1
                    k -= 1
                if backslashes % 2 == 1:
                    continue
            sub_stripped = m.group(1).strip()
            if sub_stripped:
                segments.append(sub_stripped)
    return segments


def _split_unquoted_top_level(command: str, *, posix_shell: bool = False) -> list[str] | None:
    """クォート外の連結記号・パイプ・改行で分割する。未閉鎖クォート時は None を返す。"""
    parts: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    n = len(command)

    while i < n:
        ch = command[i]
        if quote is not None:
            buf.append(ch)
            if ch == quote:
                quote = None
            elif posix_shell and quote == '"' and ch == "\\" and i + 1 < n and command[i + 1] in ('"', "\\"):
                buf.append(command[i + 1])
                i += 2
                continue
            i += 1
            continue

        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue

        if command[i : i + 2] in ("&&", "||"):
            seg = "".join(buf).strip()
            if seg:
                parts.append(seg)
            buf = []
            i += 2
            continue

        if ch in ";|&\r\n":
            seg = "".join(buf).strip()
            if seg:
                parts.append(seg)
            buf = []
            i += 1
            continue

        buf.append(ch)
        i += 1

    if quote is not None:
        return None
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def _extract_rg_pre_info(args: list[str]) -> tuple[bool, list[str]]:
    """rg 引数列をオプション境界（-- および値消費フラグ）に従って走査し (--pre/--pre-glob 有無, --pre コマンド列) を返す。"""
    has_pre = False
    pre_cmds: list[str] = []
    i = 0
    n = len(args)
    while i < n:
        arg = args[i]
        low = arg.lower()
        if arg == "--":
            break
        if low == "--pre":
            has_pre = True
            if i + 1 < n:
                pre_cmds.append(args[i + 1])
                i += 2
                continue
            i += 1
            continue
        if low.startswith("--pre="):
            has_pre = True
            pre_cmds.append(arg.split("=", 1)[1])
            i += 1
            continue
        if low == "--pre-glob":
            has_pre = True
            i += 2 if i + 1 < n else 1
            continue
        if low.startswith("--pre-glob="):
            has_pre = True
            i += 1
            continue
        if low in RG_VALUE_LONG_OPTS:
            i += 2 if i + 1 < n else 1
            continue
        if (
            arg.startswith("-")
            and not arg.startswith("--")
            and len(arg) > 1
            and arg[-1] in RG_VALUE_SHORT_CHARS
            and not any(ch in RG_VALUE_SHORT_CHARS for ch in arg[1:-1])
        ):
            i += 2 if i + 1 < n else 1
            continue
        i += 1
    return has_pre, pre_cmds


def _is_safe_rg_segment(segment: str) -> bool:
    """--pre / --pre-glob を含まない単一の rg コマンドセグメントか判定する。"""
    try:
        tokens = _tokenize_command(segment)
    except ValueError:
        return False
    if not tokens:
        return False
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if "=" in tok and not tok.startswith("-"):
            idx += 1
            continue
        break
    if idx >= len(tokens) or _command_basename(tokens[idx]) != "rg":
        return False
    has_pre, _ = _extract_rg_pre_info(tokens[idx + 1 :])
    return not has_pre


def _find_matching_backtick(text: str, start: int, *, in_double_quote: bool) -> int | None:
    """` の直後から対応する閉じ ` の位置をエスケープを考慮して返す。未閉鎖時は None。"""
    escapable = {"$", "`", "\\"}
    if in_double_quote:
        escapable.add('"')
    i = start
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n and text[i + 1] in escapable:
            i += 2
            continue
        if ch == "`":
            return i
        i += 1
    return None


def _unescape_backtick_body(body: str, *, in_double_quote: bool) -> str:
    """バッククォートコマンド置換内のシェルエスケープを1パスで解除する。"""
    escapable = {"$", "`", "\\"}
    if in_double_quote:
        escapable.add('"')
    out: list[str] = []
    i = 0
    n = len(body)
    while i < n:
        if body[i] == "\\" and i + 1 < n and body[i + 1] in escapable:
            out.append(body[i + 1])
            i += 2
            continue
        out.append(body[i])
        i += 1
    return "".join(out)


def _find_matching_paren_subst(text: str, start: int, *, posix_shell: bool = False) -> int | None:
    """$( の直後から対応する ) の位置をクォート・ネストを考慮して返す。未閉鎖時は None。"""
    depth = 1
    quote: str | None = None
    i = start
    n = len(text)
    while i < n:
        ch = text[i]
        if quote == "'":
            if ch == "'":
                quote = None
            i += 1
            continue
        if quote == '"':
            if posix_shell and ch == "\\" and i + 1 < n:
                i += 2
                continue
            if text[i : i + 2] == "$(":
                end = _find_matching_paren_subst(text, i + 2, posix_shell=posix_shell)
                if end is None:
                    return None
                i = end + 1
                continue
            if ch == "`":
                end = _find_matching_backtick(text, i + 1, in_double_quote=True)
                if end is None:
                    return None
                i = end + 1
                continue
            if ch == '"':
                quote = None
            i += 1
            continue
        if posix_shell and ch == "\\" and i + 1 < n:
            i += 2
            continue
        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue
        if text[i : i + 2] == "$(":
            end = _find_matching_paren_subst(text, i + 2, posix_shell=posix_shell)
            if end is None:
                return None
            i = end + 1
            continue
        if ch == "`":
            end = _find_matching_backtick(text, i + 1, in_double_quote=False)
            if end is None:
                return None
            i = end + 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _extract_command_substitutions(text: str, *, posix_shell: bool = False) -> list[str]:
    """単一引用外（未引用＋ダブルクォート内）からエスケープを除外し対応が閉じた $(...) / `...` 本体を再帰抽出する。"""
    bodies: list[str] = []
    quote: str | None = None
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if quote == "'":
            if ch == "'":
                quote = None
            i += 1
            continue
        if quote == '"':
            if posix_shell and ch == "\\" and i + 1 < n:
                i += 2
                continue
            if text[i : i + 2] == "$(":
                end = _find_matching_paren_subst(text, i + 2, posix_shell=posix_shell)
                if end is not None:
                    body = text[i + 2 : end]
                    if body.strip():
                        bodies.append(body)
                        bodies.extend(_extract_command_substitutions(body, posix_shell=posix_shell))
                    i = end + 1
                    continue
                i += 2
                continue
            if ch == "`":
                end = _find_matching_backtick(text, i + 1, in_double_quote=True)
                if end is not None:
                    body = _unescape_backtick_body(text[i + 1 : end], in_double_quote=True)
                    if body.strip():
                        bodies.append(body)
                        bodies.extend(_extract_command_substitutions(body, posix_shell=posix_shell))
                    i = end + 1
                    continue
                i += 1
                continue
            if ch == '"':
                quote = None
            i += 1
            continue
        if posix_shell and ch == "\\" and i + 1 < n and text[i + 1] in ("$", "`", "\\", "'", '"'):
            i += 2
            continue
        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue
        if text[i : i + 2] == "$(":
            end = _find_matching_paren_subst(text, i + 2, posix_shell=posix_shell)
            if end is not None:
                body = text[i + 2 : end]
                if body.strip():
                    bodies.append(body)
                    bodies.extend(_extract_command_substitutions(body, posix_shell=posix_shell))
                i = end + 1
                continue
            i += 2
            continue
        if ch == "`":
            end = _find_matching_backtick(text, i + 1, in_double_quote=False)
            if end is not None:
                body = _unescape_backtick_body(text[i + 1 : end], in_double_quote=False)
                if body.strip():
                    bodies.append(body)
                    bodies.extend(_extract_command_substitutions(body, posix_shell=posix_shell))
                i = end + 1
                continue
            i += 1
            continue
        i += 1
    return bodies


def _extract_rg_substitutions(segment: str, *, posix_shell: bool = False) -> list[str]:
    """単一引用外（未引用＋ダブルクォート内）から $(...) と `...` の中身を抽出し引用境界に沿って分割する。"""
    subs: list[str] = []
    for body in _extract_command_substitutions(segment, posix_shell=posix_shell):
        parts = _split_unquoted_top_level(body, posix_shell=posix_shell)
        if parts is not None:
            subs.extend(parts)
        else:
            subs.extend(_split_top_level_segments_raw(body, posix_shell=posix_shell))
    return subs


def _split_top_level_segments(command: str, *, posix_shell: bool = False) -> list[str]:
    """連結記号・パイプ・改行および $() / バッククォート内をセグメント分割する。"""
    unquoted_parts = _split_unquoted_top_level(command, posix_shell=posix_shell)
    if unquoted_parts is None:
        return _split_top_level_segments_raw(command, posix_shell=posix_shell)

    segments: list[str] = []
    any_safe_rg = False
    for part in unquoted_parts:
        if _is_safe_rg_segment(part):
            segments.append(part)
            any_safe_rg = True
        else:
            segments.extend(_split_top_level_segments_raw(part, posix_shell=posix_shell))
    if any_safe_rg:
        segments.extend(_extract_rg_substitutions(command, posix_shell=posix_shell))
    return segments


def _command_basename(token: str) -> str:
    """パスや .exe 拡張子を除いた小文字のコマンド名を返す。"""
    cleaned = token.strip().strip("\"'")
    name = cleaned.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def _unwrap_segment_tokens(
    tokens: list[str], *, posix_shell: bool = False
) -> list[list[str]]:
    """sudo 等のラッパーや bash -c / cmd /c / rg --pre 内のコマンド列を展開して返す。"""
    if not tokens:
        return []

    results: list[list[str]] = []
    idx = 0
    while idx < len(tokens):
        base = _command_basename(tokens[idx])
        if base in COMMAND_WRAPPERS:
            idx += 1
            while idx < len(tokens) and tokens[idx].startswith("-"):
                idx += 1
            continue
        if "=" in tokens[idx] and not tokens[idx].startswith("-") and idx + 1 < len(tokens):
            idx += 1
            continue
        break

    if idx >= len(tokens):
        return []

    sub_tokens = tokens[idx:]
    results.append(sub_tokens)
    head = _command_basename(sub_tokens[0])
    if head in SHELL_WRAPPERS:
        is_unix_shell = head in {"sh", "bash", "zsh", "dash"}
        for i, tok in enumerate(sub_tokens[1:], start=1):
            low = tok.lower()
            is_cmd_flag = low in {"-c", "/c", "/k", "-command", "-encodedcommand"} or (
                is_unix_shell and low.startswith("-") and not low.startswith("--") and "c" in low[1:]
            )
            if is_cmd_flag and i + 1 < len(sub_tokens):
                nested = " ".join(sub_tokens[i + 1 :])
                for seg in _split_top_level_segments(nested, posix_shell=posix_shell):
                    results.extend(
                        _unwrap_segment_tokens(_tokenize_lossy(seg), posix_shell=posix_shell)
                    )
                break
    elif head == "rg":
        _, pre_cmds = _extract_rg_pre_info(sub_tokens[1:])
        for nested in pre_cmds:
            if nested:
                for seg in _split_top_level_segments(nested, posix_shell=posix_shell):
                    results.extend(
                        _unwrap_segment_tokens(_tokenize_lossy(seg), posix_shell=posix_shell)
                    )
    return results


def _collect_all_command_segments(
    command: str, *, posix_shell: bool = False
) -> list[list[str]]:
    all_segments: list[list[str]] = []
    for seg in _split_top_level_segments(command, posix_shell=posix_shell):
        tokens = _tokenize_lossy(seg)
        all_segments.extend(_unwrap_segment_tokens(tokens, posix_shell=posix_shell))
    return all_segments


def _extract_secret_file_hits(command: str) -> list[str]:
    """コマンドライン内の機密ファイル（非除外 .env と秘密鍵ファイル）参照を検出する。"""
    hits: list[str] = []
    candidates = re.findall(r"[^\s;|&\"'`<>()]+", command)
    for raw in candidates:
        cleaned = raw.lstrip("@<=:").rstrip(",;")
        if "=" in cleaned and not cleaned.startswith(("/", "\\", ".")):
            _, rhs = cleaned.split("=", 1)
            cleaned = rhs.lstrip("@<=")
        if not cleaned:
            continue
        norm = cleaned.replace("\\", "/")
        low_norm = norm.lower()
        base = norm.rsplit("/", 1)[-1].lower()

        if dh.is_blocked_env_path(base):
            hits.append(base)
            continue

        if base in PRIVATE_KEY_EXACT_NAMES:
            hits.append(base)
            continue

        if not base.startswith("-") and any(
            base.endswith(ext) and len(base) > len(ext) for ext in PRIVATE_KEY_EXTENSIONS
        ):
            hits.append(base)
            continue

        if low_norm.endswith("/.aws/credentials") or low_norm == ".aws/credentials":
            hits.append(".aws/credentials")
    return hits


def _has_env_dump(segments: list[list[str]]) -> bool:
    for tokens in segments:
        if not tokens:
            continue
        head = _command_basename(tokens[0])
        if head in {"env", "printenv"} and len(tokens) == 1:
            return True
        if head in {"get-childitem", "gci", "dir", "ls"} | SAFE_CD_COMMANDS:
            for tok in tokens[1:]:
                low = tok.lower()
                if low.startswith("env:") or ":env:" in low or "=env:" in low:
                    return True
    return False


def _has_external_transfer(segments: list[list[str]]) -> bool:
    for tokens in segments:
        if not tokens:
            continue
        if _command_basename(tokens[0]) in EXTERNAL_TRANSFER_COMMANDS:
            return True
    return False


def _is_safe_filesystem_cd_target(target: str) -> bool:
    """PSDrive、UNC パス、ワイルドカード、機密ディレクトリを除いたローカル FS パスか検証する。"""
    if not target or not target.strip():
        return False
    if target.startswith("-"):
        return False
    if any(ord(ch) < 32 for ch in target):
        return False
    if target.startswith(("\\\\", "//")):
        return False
    if "::" in target:
        return False
    if ":" in target:
        if target.count(":") != 1 or not WINDOWS_DRIVE_PREFIX_RE.match(target):
            return False
    if any(ch in target for ch in "*?[]"):
        return False
    parts = [p.lower() for p in target.replace("\\", "/").split("/") if p]
    if any(part in SENSITIVE_CD_DIR_NAMES for part in parts):
        return False
    return True


def _extract_git_subcommand(
    tokens: list[str], *, strict_safe_globals: bool
) -> tuple[str | None, list[str]]:
    """git 引数列からグローバルオプションをスキップし (subcommand, sub_args) を返す。"""
    if not tokens or _command_basename(tokens[0]) != "git":
        return None, []
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        low = tok.lower()
        if not tok.startswith("-"):
            return low, tokens[i + 1 :]
        if strict_safe_globals:
            if tok == "-C" and i + 1 < len(tokens) and _is_safe_filesystem_cd_target(tokens[i + 1]):
                i += 2
                continue
            if tok == "-c" and i + 1 < len(tokens) and tokens[i + 1] == "core.quotePath=false":
                i += 2
                continue
            if tok in GIT_SAFE_GLOBAL_FLAGS:
                i += 1
                continue
            return None, []
        if low in GIT_VALUE_GLOBAL_OPTS:
            i += 2
            continue
        if any(low.startswith(opt + "=") for opt in GIT_VALUE_GLOBAL_OPTS):
            i += 1
            continue
        i += 1
    return None, []


def _is_main_or_master_ref(arg: str) -> bool:
    cleaned = arg.strip()
    if ":" in cleaned:
        _, dst = cleaned.split(":", 1)
    else:
        dst = cleaned
    dst = dst.lstrip("+").lower()
    return dst in {"main", "master", "refs/heads/main", "refs/heads/master"}


def _check_destructive_git(tokens: list[str]) -> str | None:
    subcmd, args = _extract_git_subcommand(tokens, strict_safe_globals=False)
    if subcmd is None:
        return None

    if subcmd == "push":
        positional: list[str] = []
        seen_double_dash = False
        for arg in args:
            if not seen_double_dash and arg == "--":
                seen_double_dash = True
                continue
            if not seen_double_dash and arg.startswith("-"):
                low = arg.lower()
                if low in {"--force", "--force-with-lease", "--force-if-includes"}:
                    return f"git push {arg}"
                if low in {"--delete", "--mirror"}:
                    return f"git push {arg}"
                if not low.startswith("--") and ("f" in low[1:] or "d" in low[1:]):
                    return f"git push {arg}"
                if low.startswith("--force-with-lease="):
                    return "git push --force-with-lease"
                continue
            positional.append(arg)
        for pos in positional:
            if pos.startswith("+") or pos.startswith(":") or _is_main_or_master_ref(pos):
                return f"git push targeting {pos}"
        return None

    if subcmd == "reset":
        if any(arg.lower() == "--hard" for arg in args):
            return "git reset --hard"
        return None

    if subcmd == "clean":
        for arg in args:
            if arg == "--":
                break
            low = arg.lower()
            if low == "--force":
                return "git clean --force"
            if low.startswith("-") and not low.startswith("--") and "f" in low[1:]:
                return f"git clean {arg}"
        return None

    return None


def _has_recursive_flag(args: list[str], *, short_chars: str) -> bool:
    for arg in args:
        if arg == "--":
            break
        if arg == "--recursive":
            return True
        if arg.startswith("-") and not arg.startswith("--") and any(ch in short_chars for ch in arg[1:]):
            return True
    return False


def _is_reparse_or_symlink(path: Path) -> bool:
    """パスがシンボリックリンクまたは Windows リパースポイント（ジャンクション等）か判定する。"""
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


def _has_unsafe_temp_reparse_or_escape(anchor_path: Path, check_parts: list[str]) -> bool:
    """アンカー以降の既存コンポーネントにリンクや外部逸脱がないか検証する。"""
    cur = anchor_path
    existing_deepest = anchor_path if os.path.lexists(anchor_path) else None
    for seg in check_parts:
        cur = cur / seg
        if os.path.lexists(cur):
            if _is_reparse_or_symlink(cur):
                return True
            existing_deepest = cur
    if existing_deepest is not None and os.path.lexists(anchor_path):
        try:
            real_anchor = Path(os.path.realpath(anchor_path))
            real_deepest = Path(os.path.realpath(existing_deepest))
            if not real_deepest.is_relative_to(real_anchor):
                return True
        except OSError:
            return True
    return False


def _is_safe_teamwork_temp_delete_target(target: str, *, cwd: str = "") -> bool:
    """/teamwork 中の削除対象が安全な一時・キャッシュ・scratch 配下（リンクなし）か検証する。"""
    raw = target.strip()
    if not raw or any(ord(ch) < 32 for ch in raw):
        return False
    if raw.startswith(("\\\\", "//")):
        return False
    if any(ch in raw for ch in "*?[],`") or "$(" in raw:
        return False

    norm = raw.replace("\\", "/").rstrip("/")
    if not norm:
        return False
    parts = [p for p in norm.split("/") if p]
    if not parts:
        return False
    if ".." in parts:
        return False
    low_parts = [p.lower() for p in parts]
    if any(part in (SENSITIVE_CD_DIR_NAMES | {".git"}) for part in low_parts):
        return False

    env_temp_m = re.match(r"^\$env:(TEMP|TMP)/(.+)$", norm, re.IGNORECASE)
    if env_temp_m:
        env_name = env_temp_m.group(1).upper()
        tail = env_temp_m.group(2)
        if "$" in tail or ":" in tail:
            return False
        tail_parts = [p for p in tail.split("/") if p]
        if not tail_parts:
            return False
        env_root_val = os.environ.get(env_name, "").strip()
        if env_root_val and _has_unsafe_temp_reparse_or_escape(Path(env_root_val), tail_parts):
            return False
        return True

    if "$" in norm:
        return False
    if ":" in norm:
        if norm.count(":") != 1 or not re.match(r"^[A-Za-z]:/", norm):
            return False

    is_unix_abs = norm.startswith("/")
    is_win_abs = bool(re.match(r"^[A-Za-z]:/", norm))
    is_abs = is_unix_abs or is_win_abs

    anchor_index: int | None = None
    rel_parts: list[str] = []

    if is_unix_abs and len(parts) >= 2 and low_parts[0] == "tmp":
        anchor_index = 1
    elif is_unix_abs and len(parts) >= 3 and low_parts[:2] == ["var", "tmp"]:
        anchor_index = 2
    elif is_win_abs and len(parts) >= 3 and low_parts[1] in {"temp", "tmp"}:
        anchor_index = 1
    elif (
        is_win_abs
        and len(parts) >= 6
        and low_parts[1] == "users"
        and low_parts[3:6] == ["appdata", "local", "temp"]
    ):
        anchor_index = 6
    else:
        # Antigravity .gemini/antigravity/brain/<uuid>/scratch/<child...>
        for idx in range(len(low_parts) - 5):
            if (
                low_parts[idx : idx + 3] == [".gemini", "antigravity", "brain"]
                and UUID_RE.fullmatch(parts[idx + 3])
                and low_parts[idx + 4] == "scratch"
            ):
                anchor_index = idx
                break

    if anchor_index is None:
        if not is_abs:
            rel_parts = list(parts)
            while rel_parts and rel_parts[0] == ".":
                rel_parts.pop(0)
            if not rel_parts or rel_parts[0].lower() not in SAFE_RELATIVE_TEMP_ROOTS:
                return False
            anchor_index = 0
        else:
            if low_parts[-1] in SAFE_CACHE_DIR_NAMES and len(parts) >= 2:
                anchor_index = len(parts) - 1
            else:
                for idx in range(1, len(parts) - 1):
                    if low_parts[idx] in SAFE_TEMP_PARENT_NAMES:
                        anchor_index = idx
                        break

    if anchor_index is None:
        return False

    if not is_abs:
        anchor_path = Path(cwd) if cwd else Path.cwd()
        check_parts = rel_parts
    elif is_unix_abs:
        anchor_path = Path("/" + "/".join(parts[:anchor_index]))
        check_parts = parts[anchor_index:]
    else:
        anchor_path = Path(parts[0] + "/" + "/".join(parts[1:anchor_index]))
        check_parts = parts[anchor_index:]

    if not check_parts:
        return False
    if _has_unsafe_temp_reparse_or_escape(anchor_path, check_parts):
        return False
    return True


def _extract_safe_temp_delete_targets(head: str, args: list[str]) -> list[str] | None:
    """rm / Remove-Item / del 系から許容フラグ以外を除いた削除対象パス一覧を返す。"""
    targets: list[str] = []
    if head == "rm":
        seen_dd = False
        for arg in args:
            if not seen_dd and arg == "--":
                seen_dd = True
                continue
            if not seen_dd and arg.startswith("-"):
                low = arg.lower()
                if low in {"--recursive", "--force", "--verbose", "--dir"}:
                    continue
                if not low.startswith("--") and len(arg) > 1 and all(ch in "rRfvd" for ch in arg[1:]):
                    continue
                return None
            targets.append(arg)
        return targets or None

    if head in {"remove-item", "ri"}:
        i = 0
        n = len(args)
        while i < n:
            arg = args[i]
            low = arg.lower()
            if arg.startswith("-"):
                flag, has_colon, inline_val = low.partition(":")
                if (
                    ("-recurse".startswith(flag) and len(flag) >= 4)
                    or ("-force".startswith(flag) and len(flag) >= 3)
                    or ("-verbose".startswith(flag) and len(flag) >= 2)
                ) and not has_colon:
                    i += 1
                    continue
                if flag == "-confirm" and inline_val in {"$false", "false"}:
                    i += 1
                    continue
                if flag in {"-erroraction", "-ea"}:
                    i += 1 if has_colon else (2 if i + 1 < n else 1)
                    continue
                if flag in {"-path", "-literalpath"}:
                    if has_colon:
                        if not inline_val:
                            return None
                        targets.append(arg.split(":", 1)[1])
                        i += 1
                    elif i + 1 < n:
                        targets.append(args[i + 1])
                        i += 2
                    else:
                        return None
                    continue
                return None
            targets.append(arg)
            i += 1
        return targets or None

    if head in {"del", "erase", "rmdir", "rd"}:
        for arg in args:
            low = arg.lower()
            if arg.startswith("/"):
                if low in {"/s", "/q", "/f"}:
                    continue
                return None
            targets.append(arg)
        return targets or None

    return None


def _check_destructive_command(
    tokens: list[str], *, is_teamwork: bool = False, cwd: str = ""
) -> str | None:
    if not tokens:
        return None
    head = _command_basename(tokens[0])
    args = tokens[1:]
    low_args = [a.lower() for a in args]

    if head == "git":
        return _check_destructive_git(tokens)

    if head == "rm":
        short_flags: set[str] = set()
        has_force = False
        for arg in args:
            if arg == "--":
                break
            if arg == "--force":
                has_force = True
            elif arg.startswith("-") and not arg.startswith("--"):
                short_flags.update(arg[1:])
        if _has_recursive_flag(args, short_chars="rR") and (has_force or "f" in short_flags):
            if is_teamwork:
                targets = _extract_safe_temp_delete_targets(head, args)
                if targets and all(
                    _is_safe_teamwork_temp_delete_target(t, cwd=cwd) for t in targets
                ):
                    return None
            return "rm recursive force"
        return None

    if head in {"remove-item", "ri"}:
        has_recurse = any(
            "-recurse".startswith(a) and len(a) >= 4 for a in low_args
        )
        has_force = any(
            "-force".startswith(a) and len(a) >= 3 for a in low_args
        )
        if has_recurse and has_force:
            if is_teamwork:
                targets = _extract_safe_temp_delete_targets(head, args)
                if targets and all(
                    _is_safe_teamwork_temp_delete_target(t, cwd=cwd) for t in targets
                ):
                    return None
            return "Remove-Item -Recurse -Force"
        return None

    if head in {"del", "erase", "rmdir", "rd"}:
        if "/s" in low_args and "/q" in low_args:
            if is_teamwork:
                targets = _extract_safe_temp_delete_targets(head, args)
                if targets and all(
                    _is_safe_teamwork_temp_delete_target(t, cwd=cwd) for t in targets
                ):
                    return None
            return f"{head} /s /q"
        return None

    if head in DESTRUCTIVE_DISK_COMMANDS or head.startswith("mkfs"):
        return head

    if head == "format" and args:
        return "format"

    if head == "dd" and any(a.startswith("of=") for a in low_args):
        return "dd of=..."

    if head == "chmod":
        has_rec = _has_recursive_flag(args, short_chars="R")
        has_open_perm = any(a in {"777", "0777", "a+rwx", "000", "0000"} for a in low_args)
        if has_rec and has_open_perm:
            return "chmod -R dangerous permissions"
        if "/" in args and has_open_perm:
            return "chmod / dangerous permissions"
        return None

    if head == "chown":
        if _has_recursive_flag(args, short_chars="R") and any(a in {"/", "/*"} for a in args):
            return "chown -R /"
        return None

    if head == "icacls":
        if ("/reset" in low_args and "/t" in low_args) or (
            "/grant" in low_args and any("everyone:f" in a for a in low_args)
        ):
            return "icacls permission modification"
        return None

    if head == "takeown" and "/f" in low_args and "/r" in low_args:
        return "takeown /f /r"

    return None


def _is_safe_git_ref_name(ref: str) -> bool:
    if not ref or not GIT_SAFE_REF_RE.fullmatch(ref):
        return False
    if ref.endswith(("/", ".", ".lock")):
        return False
    if "//" in ref or ".." in ref or "/." in ref or "./" in ref:
        return False
    return True


def _is_whitelisted_git_push(args: list[str]) -> bool:
    """origin 上の非保護 feature ブランチへの安全な非強制 git push のみを許可する。"""
    positional: list[str] = []
    for arg in args:
        if arg.startswith("-"):
            if arg not in GIT_SAFE_PUSH_FLAGS:
                return False
            continue
        positional.append(arg)

    if len(positional) != 2:
        return False

    remote, refspec = positional
    if remote not in GIT_SAFE_PUSH_REMOTES:
        return False

    if not refspec or refspec.startswith(("+", ":")) or refspec.count(":") > 1:
        return False

    if ":" in refspec:
        src, dst = refspec.split(":", 1)
        if not src or not dst:
            return False
        if src != "HEAD" and not _is_safe_git_ref_name(src):
            return False
        target = dst
    else:
        target = refspec

    if target.lower().startswith("refs/"):
        if not target.startswith("refs/heads/"):
            return False
        branch = target[len("refs/heads/") :]
    else:
        branch = target

    if not _is_safe_git_ref_name(branch):
        return False

    low_branch = branch.lower()
    if low_branch in GIT_PROTECTED_PUSH_BRANCHES:
        return False
    if low_branch.startswith(GIT_PROTECTED_PUSH_PREFIXES):
        return False
    return True


def _classify_whitelisted_git(tokens: list[str]) -> tuple[bool, bool]:
    """git コマンドを (ホワイトリスト許可可否, 安全な git push を含むか) で返す。"""
    subcmd, args = _extract_git_subcommand(tokens, strict_safe_globals=True)
    if subcmd is None:
        return False, False

    if subcmd in GIT_READONLY_SUBCOMMANDS:
        for arg in args:
            low = arg.lower()
            if low == "--ext-diff" or low == "--output" or low.startswith("--output="):
                return False, False
            if subcmd == "grep" and (
                low == "--open-files-in-pager"
                or low.startswith("--open-files-in-pager=")
                or (arg.startswith("-") and not arg.startswith("--") and "O" in arg[1:])
            ):
                return False, False
        return True, False

    if subcmd == "branch":
        allowed_flags = {
            "--show-current",
            "-a",
            "--all",
            "-r",
            "--remotes",
            "-v",
            "-vv",
            "--verbose",
            "-l",
            "--list",
            "--no-color",
            "--color",
        }
        return all(arg in allowed_flags for arg in args), False

    if subcmd == "tag":
        return (len(args) == 0 or all(arg in {"-l", "--list", "-n"} for arg in args)), False

    if subcmd == "remote":
        return (
            len(args) == 0
            or args == ["-v"]
            or args == ["--verbose"]
            or (len(args) >= 1 and args[0] == "show")
        ), False

    if subcmd == "push":
        return (_is_whitelisted_git_push(args), True)

    return False, False


def _is_whitelisted_git(tokens: list[str]) -> bool:
    return _classify_whitelisted_git(tokens)[0]


def _is_safe_env_assignment(name: str, value: str, *, case_insensitive: bool) -> bool:
    """環境変数名とリテラル値が許可リストと安全な値パターンに一致するか検証する。"""
    key = name.upper() if case_insensitive else name
    validator = SAFE_ENV_VAR_VALIDATORS.get(key)
    return validator is not None and validator.fullmatch(value) is not None


def _split_whitelist_segments(
    command: str, *, posix_shell: bool = False
) -> list[str] | None:
    """クォート外の ; と && のみで単純連結を分割し、危険なメタ文字（クォート外の |>< も含む）を拒否する。"""
    if DISALLOWED_WHITELIST_ANYWHERE_RE.search(command):
        return None

    segments: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    n = len(command)

    while i < n:
        ch = command[i]
        if quote is not None:
            if ch == quote:
                quote = None
                buf.append(ch)
            elif quote == '"' and ch == "\\":
                j = i
                while j < n and command[j] == "\\":
                    j += 1
                if j < n and command[j] == '"' and (j - i) % 2 == 1:
                    if not posix_shell:
                        return None
                    buf.append(command[i : j + 1])
                    i = j + 1
                    continue
                buf.append(command[i:j])
                i = j
                continue
            else:
                buf.append(ch)
            i += 1
            continue

        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue

        if ch in ("|", ">", "<"):
            return None

        if ch == ";":
            seg = "".join(buf).strip()
            if not seg:
                return None
            segments.append(seg)
            buf = []
            i += 1
            continue

        if ch == "&":
            if i + 1 < n and command[i + 1] == "&" and (i + 2 >= n or command[i + 2] != "&"):
                seg = "".join(buf).strip()
                if not seg:
                    return None
                segments.append(seg)
                buf = []
                i += 2
                continue
            return None

        buf.append(ch)
        i += 1

    if quote is not None:
        return None

    tail = "".join(buf).strip()
    if not tail:
        return None
    segments.append(tail)
    return segments


def _contains_unquoted_grouping_chars(segment: str) -> bool:
    """クォート外の括弧類 ( ) { } を検出する（未閉鎖クォートも安全側で True）。"""
    quote: str | None = None
    i = 0
    n = len(segment)

    while i < n:
        ch = segment[i]
        if quote is not None:
            if ch == quote:
                quote = None
            elif quote == '"' and ch == "\\" and i + 1 < n and segment[i + 1] == '"':
                i += 2
                continue
            i += 1
            continue

        if ch in ("'", '"'):
            quote = ch
        elif ch in ("(", ")", "{", "}"):
            return True
        i += 1

    return quote is not None


def _contains_unsafe_dollar(segment: str) -> bool:
    """クォート外の $ およびダブルクォート内の変数展開パターンを検出する。"""
    quote: str | None = None
    i = 0
    n = len(segment)

    while i < n:
        ch = segment[i]
        if quote is not None:
            if ch == quote:
                quote = None
            elif quote == '"' and ch == "\\" and i + 1 < n and segment[i + 1] == '"':
                i += 2
                continue
            elif quote == '"' and ch == "$" and i + 1 < n:
                nxt = segment[i + 1]
                if nxt.isalnum() or nxt in "_@*?#^":
                    return True
            i += 1
            continue

        if ch in ("'", '"'):
            quote = ch
        elif ch == "$":
            return True
        i += 1

    return quote is not None


def _strip_safe_posix_env_prefixes(segment: str) -> str | None:
    """セグメント先頭の安全な POSIX 形式環境変数代入を剥がし、許可外代入は None を返す。"""
    rest = segment.lstrip()
    while True:
        match = POSIX_ENV_ASSIGN_PREFIX_RE.match(rest)
        if not match:
            return rest
        name = match.group(1)
        value = next(g for g in match.groups()[1:] if g is not None)
        if not _is_safe_env_assignment(name, value, case_insensitive=False):
            return None
        rest = rest[match.end() :].lstrip()


def _is_whitelisted_cd_segment(segment: str) -> bool:
    """安全なローカルディレクトリ移動セグメント（Set-Location / cd 等）か判定する。"""
    try:
        tokens = _tokenize_command(segment)
    except ValueError:
        return False
    if not tokens:
        return False

    head = _command_basename(tokens[0])
    if head not in SAFE_CD_COMMANDS:
        return False

    args = tokens[1:]
    if len(args) == 1:
        return _is_safe_filesystem_cd_target(args[0])
    if len(args) == 2 and args[0].lower() in {"-path", "-literalpath"}:
        return _is_safe_filesystem_cd_target(args[1])
    return False


def _classify_whitelisted_single_command(segment: str) -> tuple[bool, bool]:
    """単一コマンドを (ローカルホワイトリスト許可可否, 安全な git push を含むか) で判定する。"""
    try:
        tokens = _tokenize_command(segment)
    except ValueError:
        return False, False
    if not tokens:
        return False, False

    head = _command_basename(tokens[0])
    args = tokens[1:]

    if head == "git":
        return _classify_whitelisted_git(tokens)

    if head in {"ls", "dir", "get-childitem", "pwd", "get-location"}:
        return True, False

    if head == "rg":
        has_pre, _ = _extract_rg_pre_info(args)
        return (not has_pre), False

    if head == "pytest":
        return True, False

    if head in {"python", "python3", "py"}:
        idx = 1
        if head == "py" and idx < len(tokens) and re.fullmatch(r"-\d+(?:\.\d+)?", tokens[idx]):
            idx += 1
        while idx < len(tokens):
            tok = tokens[idx]
            if (
                tok.startswith("-")
                and not tok.startswith("--")
                and len(tok) > 1
                and all(ch in SAFE_PYTHON_SHORT_FLAGS for ch in tok[1:])
            ):
                idx += 1
                continue
            break
        if idx + 1 < len(tokens) and tokens[idx] == "-m" and tokens[idx + 1] in {"unittest", "pytest"}:
            return True, False
        return False, False

    return False, False


def _is_whitelisted_single_command(segment: str) -> bool:
    return _classify_whitelisted_single_command(segment)[0]


def _classify_whitelisted_command(
    command: str, *, posix_shell: bool = False
) -> tuple[bool, bool]:
    """安全な環境変数・ローカル cd・定型 fail-fast ガード・単純連結を含む厳格ホワイトリスト判定。"""
    stripped = command.strip()
    if not stripped:
        return False, False
    segments = _split_whitelist_segments(stripped, posix_shell=posix_shell)
    if segments is None or len(segments) > MAX_WHITELIST_SEGMENTS:
        return False, False

    command_count = 0
    includes_push = False
    last_kind: str | None = None
    for seg in segments:
        if PS_FAILFAST_GUARD_RE.fullmatch(seg):
            if last_kind not in {"cmd", "cd"}:
                return False, False
            last_kind = "guard"
            continue

        if _contains_unquoted_grouping_chars(seg):
            return False, False

        ps_match = PS_ENV_ASSIGN_RE.fullmatch(seg)
        if ps_match:
            name = ps_match.group(1)
            value = next(g for g in ps_match.groups()[1:] if g is not None)
            if not _is_safe_env_assignment(name, value, case_insensitive=True):
                return False, False
            last_kind = "env"
            continue

        if _contains_unsafe_dollar(seg):
            return False, False

        if _is_whitelisted_cd_segment(seg):
            last_kind = "cd"
            continue

        cmd_part = _strip_safe_posix_env_prefixes(seg)
        if cmd_part is None:
            return False, False
        allowed, seg_has_push = _classify_whitelisted_single_command(cmd_part)
        if not allowed:
            return False, False
        command_count += 1
        includes_push = includes_push or seg_has_push
        last_kind = "cmd"

    if command_count >= 1 and last_kind in {"cmd", "guard"}:
        return True, includes_push
    return False, False


def _is_whitelisted_readonly(command: str) -> bool:
    """安全な環境変数プレフィックスと ; / && 単純連結を許容する厳格ホワイトリスト判定。"""
    return _classify_whitelisted_command(command)[0]


def _advance_shell_quote_state(text: str, in_quote: str | None) -> str | None:
    """単一行文字列を走査し、更新後のクォート状態を返す。"""
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_quote == "'":
            if ch == "'":
                if i + 1 < n and text[i + 1] == "'":
                    i += 2
                    continue
                in_quote = None
            i += 1
            continue
        if in_quote == '"':
            if ch == "`" and i + 1 < n:
                i += 2
                continue
            if ch == "\\" and i + 1 < n and text[i + 1] in ('"', "\\"):
                i += 2
                continue
            if ch == '"':
                in_quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            in_quote = ch
        i += 1
    return in_quote


def _find_single_quoted_heredoc_opener(line_no_eol: str) -> tuple[bool, bool, str]:
    """未クォートの POSIX 単一引用 heredoc（<<'DELIM' / <<-'DELIM'）を検出する。

    戻り値は (検出したか, タブ除去モードか / fail_closed フラグ, 区切り文字列)。
    未クォート << が複数ある場合や無効な形式は安全側で fail_closed=(False, True, "") を返す。
    """
    quote: str | None = None
    offsets: list[int] = []
    i = 0
    n = len(line_no_eol)
    while i < n:
        ch = line_no_eol[i]
        if quote == "'":
            if ch == "'":
                if i + 1 < n and line_no_eol[i + 1] == "'":
                    i += 2
                    continue
                quote = None
            i += 1
            continue
        if quote == '"':
            if ch == "`" and i + 1 < n:
                i += 2
                continue
            if ch == "\\" and i + 1 < n and line_no_eol[i + 1] in ('"', "\\"):
                i += 2
                continue
            if ch == '"':
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
            i += 1
            continue
        if ch == "<" and i + 1 < n and line_no_eol[i + 1] == "<":
            offsets.append(i)
            i += 2
            continue
        i += 1

    if len(offsets) > 1:
        return False, True, ""
    if not offsets:
        return False, False, ""

    match = re.match(
        r"<<(-?)\s*'([A-Za-z_][A-Za-z0-9_]*)'(?=$|[ \t;|&<>#)])",
        line_no_eol[offsets[0] :],
    )
    if not match:
        return False, False, ""
    return True, bool(match.group(1)), match.group(2)


def _strip_verbatim_herestrings_with_meta(command: str) -> tuple[str, list[str], list[str]]:
    """PowerShell @'...'@ と POSIX <<'DELIM' の逐語本体を退避し (置換後コマンド, 本体一覧, POSIX heredoc 開始行一覧) を返す。

    未閉鎖や曖昧な構文を検出した場合は安全側で (command, [], []) へフォールバックする。
    """
    lines = command.splitlines(keepends=True)
    if not lines:
        return command, [], []

    mode: str | None = None
    in_quote: str | None = None
    heredoc_delim = ""
    heredoc_strip_tabs = False
    pending_heredoc_line = ""
    heredoc_opener_lines: list[str] = []
    bodies: list[str] = []
    current_body: list[str] = []
    out_parts: list[str] = []

    for line in lines:
        line_no_eol = line.rstrip("\r\n")
        eol = line[len(line_no_eol) :]

        if mode == "ps_herestring":
            if line_no_eol.startswith("'@") and (
                len(line_no_eol) == 2 or line_no_eol[2] in " \t;)],|}+"
            ):
                trailing = line_no_eol[2:]
                if trailing.rstrip(" \t").endswith("@'"):
                    return command, [], []
                idx = len(bodies)
                bodies.append("".join(current_body))
                current_body = []
                out_parts.append(f"'<HERESTRING_{idx}>'{trailing}{eol}")
                mode = None
                in_quote = _advance_shell_quote_state(trailing, None)
            else:
                current_body.append(line)
            continue

        if mode == "posix_heredoc":
            candidate = line_no_eol.lstrip("\t") if heredoc_strip_tabs else line_no_eol
            if candidate == heredoc_delim:
                bodies.append("".join(current_body))
                current_body = []
                mode = None
                heredoc_opener_lines.append(pending_heredoc_line)
                pending_heredoc_line = ""
            else:
                current_body.append(line)
            continue

        i = 0
        n = len(line_no_eol)
        entered_ps_here = False
        while i < n:
            ch = line_no_eol[i]
            if in_quote == "'":
                if ch == "'":
                    if i + 1 < n and line_no_eol[i + 1] == "'":
                        i += 2
                        continue
                    in_quote = None
                i += 1
                continue
            if in_quote == '"':
                if ch == "`" and i + 1 < n:
                    i += 2
                    continue
                if ch == "\\" and i + 1 < n and line_no_eol[i + 1] in ('"', "\\"):
                    i += 2
                    continue
                if ch == '"':
                    in_quote = None
                i += 1
                continue

            if (
                eol
                and ch == "@"
                and i + 1 < n
                and line_no_eol[i + 1] == "'"
                and line_no_eol[i + 2 :].strip(" \t") == ""
                and (i == 0 or line_no_eol[i - 1] in " \t=(,;+")
            ):
                out_parts.append(line_no_eol[:i])
                mode = "ps_herestring"
                current_body = []
                entered_ps_here = True
                break

            if ch in ("'", '"'):
                in_quote = ch
            i += 1

        if entered_ps_here:
            continue

        if in_quote is None and eol:
            found_hd, flag_or_fail, delim = _find_single_quoted_heredoc_opener(line_no_eol)
            if not found_hd and flag_or_fail:
                return command, [], []
            if found_hd:
                heredoc_strip_tabs = flag_or_fail
                heredoc_delim = delim
                pending_heredoc_line = line_no_eol
                mode = "posix_heredoc"
                current_body = []

        out_parts.append(line)

    if mode is not None or in_quote is not None:
        return command, [], []
    return "".join(out_parts), bodies, heredoc_opener_lines


def _strip_verbatim_herestrings(command: str) -> tuple[str, list[str]]:
    """PowerShell @'...'@ と POSIX <<'DELIM' の逐語本体を退避し (置換後コマンド, 本体一覧) を返す。"""
    stripped, bodies, _ = _strip_verbatim_herestrings_with_meta(command)
    return stripped, bodies


def _extract_executable_text_chunks(
    stripped_command: str, *, posix_shell: bool = False
) -> str:
    """単一/二重引用リテラルを除外し、クォート外およびコマンド置換 $(...) / `...` 本体のみを返す。"""
    chunks: list[str] = []
    buf: list[str] = []
    in_quote: str | None = None
    i = 0
    n = len(stripped_command)

    while i < n:
        ch = stripped_command[i]
        if in_quote == "'":
            if ch == "'":
                if i + 1 < n and stripped_command[i + 1] == "'":
                    i += 2
                    continue
                in_quote = None
            i += 1
            continue
        if in_quote == '"':
            if ch == "`" and i + 1 < n:
                i += 2
                continue
            if posix_shell and ch == "\\" and i + 1 < n and stripped_command[i + 1] in ('"', "\\"):
                i += 2
                continue
            if ch == '"':
                in_quote = None
            i += 1
            continue
        if ch == "'":
            if buf:
                chunks.append("".join(buf))
                buf = []
            in_quote = "'"
        elif ch == '"':
            if buf:
                chunks.append("".join(buf))
                buf = []
            in_quote = '"'
        else:
            buf.append(ch)
        i += 1

    if buf:
        chunks.append("".join(buf))
    for body in _extract_command_substitutions(stripped_command, posix_shell=posix_shell):
        chunks.append(" " + body + " ")
    return "".join(chunks)


def _has_code_exec_sink(
    stripped_command: str, segments: list[list[str]], *, posix_shell: bool = False
) -> bool:
    """コード実行シンク（シェル起動、eval/iex、呼び出し演算子 &、ドットソース等）を検出する。"""
    for tokens in segments:
        if tokens and _command_basename(tokens[0]) in CODE_EXEC_SINKS:
            return True

    exec_text = _extract_executable_text_chunks(stripped_command, posix_shell=posix_shell)
    if re.search(
        r"\b(?:scriptblock|invoke-expression|iex|invoke-command|icm)\b",
        exec_text,
        re.IGNORECASE,
    ):
        return True

    in_quote: str | None = None
    at_stmt_start = True
    i = 0
    n = len(stripped_command)
    while i < n:
        ch = stripped_command[i]
        if in_quote == "'":
            if ch == "'":
                if i + 1 < n and stripped_command[i + 1] == "'":
                    i += 2
                    continue
                in_quote = None
            at_stmt_start = False
            i += 1
            continue
        if in_quote == '"':
            if ch == "`" and i + 1 < n:
                i += 2
                continue
            if ch == "\\" and i + 1 < n and stripped_command[i + 1] in ('"', "\\"):
                i += 2
                continue
            if ch == '"':
                in_quote = None
            at_stmt_start = False
            i += 1
            continue

        if ch in ("'", '"'):
            in_quote = ch
            at_stmt_start = False
            i += 1
            continue

        if ch == "&":
            if i + 1 < n and stripped_command[i + 1] == "&" and (
                i + 2 >= n or stripped_command[i + 2] != "&"
            ):
                at_stmt_start = True
                i += 2
                continue
            return True

        if at_stmt_start and ch == "." and i + 1 < n and stripped_command[i + 1] in " \t":
            return True

        if ch in "\r\n;|{":
            at_stmt_start = True
        elif ch not in " \t":
            at_stmt_start = False
        i += 1

    return False


def _resolve_brain_root(
    conversation_id: str,
    transcript_path: str = "",
    artifact_dir: str = "",
) -> Path | None:
    """会話 ID とフックメタデータのパスから brain ルートディレクトリを特定する。"""
    if not UUID_RE.fullmatch(conversation_id):
        return None
    low_id = conversation_id.lower()

    if artifact_dir:
        art = Path(artifact_dir)
        if art.name.lower() == low_id:
            return art.parent
        for parent in art.parents:
            if parent.name.lower() == low_id:
                return parent.parent

    if transcript_path:
        tr = Path(transcript_path)
        for parent in tr.parents:
            if parent.name.lower() == low_id:
                return parent.parent

    return None


def _is_teamwork_conversation(
    conversation_id: str,
    *,
    transcript_path: str = "",
    artifact_dir: str = "",
    brain_root: Path | None = None,
    max_depth: int = MAX_TEAMWORK_PARENT_DEPTH,
) -> bool:
    """ランタイム生成の親チェーン（sender と subagents/<id>.json）から /teamwork 配下か判定する。"""
    if not UUID_RE.fullmatch(conversation_id):
        return False
    root = brain_root or _resolve_brain_root(conversation_id, transcript_path, artifact_dir)
    if root is None:
        return False

    visited: set[str] = set()
    cur = conversation_id
    for _ in range(max_depth):
        low_cur = cur.lower()
        if low_cur in visited:
            return False
        visited.add(low_cur)

        tpath = root / cur / ".system_generated" / "logs" / "transcript.jsonl"
        try:
            with tpath.open("r", encoding="utf-8", errors="replace") as fh:
                first_line = fh.readline()
            if not first_line:
                return False
            first_obj = json.loads(first_line)
        except (OSError, ValueError, json.JSONDecodeError):
            return False

        if not isinstance(first_obj, dict):
            return False
        if first_obj.get("type") != "SYSTEM_MESSAGE" or first_obj.get("source") != "SYSTEM":
            return False

        content = str(first_obj.get("content") or "")
        sender_m = TEAMWORK_SENDER_RE.search(content)
        if not sender_m:
            return False
        parent_id = sender_m.group(1)
        if not UUID_RE.fullmatch(parent_id):
            return False

        desc_path = root / parent_id / ".system_generated" / "subagents" / f"{cur}.json"
        try:
            desc_obj = json.loads(desc_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            return False

        if not isinstance(desc_obj, dict):
            return False
        descriptor = desc_obj.get("subagentDescriptor")
        if not isinstance(descriptor, dict):
            return False
        type_name = str(descriptor.get("typeName") or "")
        if type_name == "teamwork" or type_name.startswith("teamwork_"):
            return True

        cur = parent_id

    return False


def _collect_quote_aware_segments(
    command_text: str, *, posix_shell: bool = False
) -> list[list[str]] | None:
    """引用境界を保ったまま実際のコマンドセグメントと展開式のみを抽出し展開する。"""
    unquoted_parts = _split_unquoted_top_level(command_text, posix_shell=posix_shell)
    if unquoted_parts is None:
        return None

    extracted: list[list[str]] = []
    for part in unquoted_parts:
        extracted.extend(
            _unwrap_segment_tokens(_tokenize_lossy(part), posix_shell=posix_shell)
        )
    for sub in _extract_rg_substitutions(command_text, posix_shell=posix_shell):
        extracted.extend(
            _unwrap_segment_tokens(_tokenize_lossy(sub), posix_shell=posix_shell)
        )
    return extracted


def _are_posix_heredoc_receivers_safe(
    heredoc_opener_lines: list[str],
    outer_segments: list[list[str]] | None,
    *,
    posix_shell: bool = False,
) -> bool:
    """POSIX heredoc を受け取るコマンドが cat / tee のみ、かつ外側全コマンドが許可リスト内か検証する。"""
    if not heredoc_opener_lines:
        return True
    if not outer_segments:
        return False
    for tokens in outer_segments:
        if not tokens or _command_basename(tokens[0]) not in SAFE_POSIX_HEREDOC_OUTER_COMMANDS:
            return False
    for hd_line in heredoc_opener_lines:
        parts = _split_unquoted_top_level(hd_line, posix_shell=posix_shell)
        if parts is None:
            return False
        hd_parts = [p for p in parts if _find_single_quoted_heredoc_opener(p)[0]]
        if not hd_parts:
            return False
        for part in hd_parts:
            unwrapped = _unwrap_segment_tokens(
                _tokenize_lossy(part), posix_shell=posix_shell
            )
            if not unwrapped or _command_basename(unwrapped[0][0]) not in SAFE_POSIX_HEREDOC_RECEIVERS:
                return False
    return True


def _extract_teamwork_push_segments(
    command_text: str,
    fallback_segments: list[list[str]],
    *,
    posix_shell: bool = False,
) -> list[list[str]]:
    """引用境界を保ったまま実際のコマンドセグメントと展開式のみを抽出し git push 判定に使う。"""
    extracted = _collect_quote_aware_segments(command_text, posix_shell=posix_shell)
    if extracted is None:
        return fallback_segments
    return extracted


GOOG_HEADER_SAFE_ENV_RE = re.compile(
    r"^(?:%[A-Za-z_][A-Za-z0-9_]*%|\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\}|[Ee][Nn][Vv]:[A-Za-z_][A-Za-z0-9_]*))$"
)


def _quote_state_at(text: str, pos: int) -> str | None:
    """text[:pos] を走査し、pos 時点で開いているクォート種別（' / \" / None）を返す。"""
    quote: str | None = None
    i = 0
    limit = min(pos, len(text))
    while i < limit:
        ch = text[i]
        if quote == "'":
            if ch == "'":
                quote = None
            i += 1
            continue
        if quote == '"':
            if ch == "\\" and i + 1 < limit and text[i + 1] in ('"', "\\"):
                i += 2
                continue
            if ch == '"':
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
        i += 1
    return quote


def _is_safe_goog_header_value(val: str, *, in_single_quote: bool) -> bool:
    """x-goog-api-key ヘッダ値がプレースホルダ（REDACTED）または展開される厳格な環境変数参照のみか判定する。"""
    if val.upper() in ("REDACTED", "[REDACTED]"):
        return True
    if in_single_quote:
        return False
    return bool(GOOG_HEADER_SAFE_ENV_RE.match(val))


def _has_non_var_goog_header(
    text: str, *, strict_shell_quotes: bool = True
) -> bool:
    """x-goog-api-key ヘッダに展開される環境変数参照や REDACTED 以外の生値が指定されているか検査する。"""
    for m in GOOG_HEADER_QUOTED_RE.finditer(text):
        raw_rhs = m.group(0)[len(m.group(1)) :].strip()
        val = raw_rhs[1:-1].strip() if len(raw_rhs) >= 2 else ""
        in_sq = (
            (m.group(2) == "'") or (_quote_state_at(text, m.start()) == "'")
            if strict_shell_quotes
            else False
        )
        if val and not _is_safe_goog_header_value(val, in_single_quote=in_sq):
            return True
    for m in GOOG_HEADER_PLAIN_RE.finditer(text):
        val = m.group(2).strip().strip("\"'")
        in_sq = (_quote_state_at(text, m.start()) == "'") if strict_shell_quotes else False
        if val and not _is_safe_goog_header_value(val, in_single_quote=in_sq):
            return True
    return False


def _has_inline_secret_literal(
    text: str, *, strict_shell_quotes: bool = True
) -> bool:
    """コマンド文字列内の API トークン・秘密鍵ヘッダ・認証ヘッダ実値パターンを検出する。"""
    if dh.scan_text_for_secrets(text):
        return True
    if dh.BEARER_TOKEN_RE.search(text):
        return True
    if _has_non_var_goog_header(text, strict_shell_quotes=strict_shell_quotes):
        return True
    return False


def evaluate_stage1(
    command: str,
    *,
    is_teamwork: bool = False,
    cwd: str = "",
    posix_shell: bool = False,
) -> tuple[str, str] | None:
    """第 1 段の決定論的ローカル判定を行う。決着しない場合は None を返す。"""
    if not command.strip():
        return ("ask", "Empty command line; fallback to standard confirmation.")

    stripped_for_scan, herestring_bodies, heredoc_opener_lines = (
        _strip_verbatim_herestrings_with_meta(command)
    )
    use_stripped = False
    if herestring_bodies:
        if heredoc_opener_lines:
            outer_segments = _collect_quote_aware_segments(
                stripped_for_scan, posix_shell=posix_shell
            )
            safe_posix_hd = _are_posix_heredoc_receivers_safe(
                heredoc_opener_lines, outer_segments, posix_shell=posix_shell
            )
        else:
            outer_segments = _collect_all_command_segments(
                stripped_for_scan, posix_shell=posix_shell
            )
            safe_posix_hd = True
        if (
            safe_posix_hd
            and outer_segments is not None
            and not _has_code_exec_sink(
                stripped_for_scan, outer_segments, posix_shell=posix_shell
            )
            and not _has_external_transfer(outer_segments)
        ):
            use_stripped = True
            segments = outer_segments
            secret_hits = _extract_secret_file_hits(stripped_for_scan)
        else:
            segments = _collect_all_command_segments(command, posix_shell=posix_shell)
            secret_hits = _extract_secret_file_hits(command)
    else:
        segments = _collect_all_command_segments(command, posix_shell=posix_shell)
        secret_hits = _extract_secret_file_hits(command)

    if _has_external_transfer(segments) and (secret_hits or _has_env_dump(segments)):
        return (
            "deny",
            "Blocked by local secret-exfiltration policy: sensitive credential "
            "or environment data passed to an external transfer command.",
        )

    for seg_tokens in segments:
        destructive_reason = _check_destructive_command(
            seg_tokens, is_teamwork=is_teamwork, cwd=cwd
        )
        if destructive_reason is not None:
            return (
                "force_ask",
                f"Requires explicit confirmation: destructive operation detected locally ({destructive_reason}).",
            )

    if is_teamwork:
        shell_text = stripped_for_scan if use_stripped else command
        has_inline_secret = _has_inline_secret_literal(
            shell_text, strict_shell_quotes=True
        ) or (
            use_stripped
            and any(
                _has_inline_secret_literal(body, strict_shell_quotes=False)
                for body in herestring_bodies
            )
        )
        if has_inline_secret:
            if _has_external_transfer(segments):
                return (
                    "deny",
                    "Blocked by local secret-exfiltration policy: inline credential "
                    "or token passed to an external transfer command.",
                )
            return (
                "force_ask",
                "Requires explicit confirmation: inline credential or private key pattern detected in command.",
            )
        push_scan_text = stripped_for_scan if use_stripped else command
        for seg_tokens in _extract_teamwork_push_segments(
            push_scan_text, segments, posix_shell=posix_shell
        ):
            subcmd, _ = _extract_git_subcommand(seg_tokens, strict_safe_globals=False)
            if subcmd == "push" and not _classify_whitelisted_git(seg_tokens)[0]:
                return (
                    "force_ask",
                    "Requires explicit confirmation: git push outside explicit non-protected origin branch whitelist.",
                )
        return (
            "allow",
            "Allowed in active /teamwork subagent session (safety blacklists passed).",
        )

    if not secret_hits and not _has_env_dump(segments):
        allowed, includes_push = _classify_whitelisted_command(
            command, posix_shell=posix_shell
        )
        if allowed:
            if includes_push:
                return (
                    "allow",
                    "Allowed by local whitelist (safe feature-branch git push and read-only commands).",
                )
            return ("allow", "Allowed by local read-only and unit-test whitelist.")

    return None


def build_decision1_payload(
    tool_name: str, cwd: str, command_line: str
) -> tuple[dict[str, Any], str]:
    """送信前にコマンドをマスクし、validate_payload 済みの Decision 1 ペイロードを返す。"""
    masked_command = redact_secrets(command_line)
    input_text = "\n".join(
        [
            f"tool_name: {tool_name or 'run_command'}",
            f"cwd: {cwd or '(unknown)'}",
            f"command_line: {masked_command}",
        ]
    )
    payload: dict[str, Any] = {
        "model": rd.DEFAULT_MODEL,
        "input": [{"type": "text", "text": input_text}],
        "questions": DECISION1_QUESTIONS,
    }
    errors = rd.validate_payload(payload)
    if errors:
        raise ValueError("Invalid Decision 1 payload: " + "; ".join(errors))
    return payload, masked_command


def decide_from_answers(answers: dict[str, Any]) -> tuple[str, str]:
    """Decision 1 応答の answers マップから確定方針に従って判定を返す。"""
    risk_ans = answers.get("risk_level")
    confirm_ans = answers.get("needs_confirm")
    if not isinstance(risk_ans, dict) or not isinstance(confirm_ans, dict):
        return ("ask", FALLBACK_REASON)

    risk_choice = risk_ans.get("choice")
    risk_conf = risk_ans.get("confidence")
    needs_confirm = confirm_ans.get("noul")
    if (
        not isinstance(risk_choice, str)
        or not isinstance(risk_conf, (int, float))
        or not isinstance(needs_confirm, (int, float))
    ):
        return ("ask", FALLBACK_REASON)

    risk_conf_f = float(risk_conf)
    needs_confirm_f = float(needs_confirm)

    if risk_choice == "secret_exposure" and risk_conf_f >= 0.80:
        return (
            "force_ask",
            f"Decision 1 flagged potential secret exposure (confidence={risk_conf_f:.2f}).",
        )

    if (risk_choice == "destructive_irreversible" and risk_conf_f >= 0.75) or (
        needs_confirm_f >= 0.70
    ):
        return (
            "force_ask",
            "Decision 1 flagged irreversible or confirmation-required operation "
            f"(risk={risk_choice}, confidence={risk_conf_f:.2f}, needs_confirm={needs_confirm_f:.2f}).",
        )

    if (
        risk_choice in {"safe_readonly", "local_reversible"}
        and risk_conf_f >= 0.80
        and needs_confirm_f < 0.40
    ):
        return (
            "allow",
            f"Decision 1 classified command as {risk_choice} "
            f"(confidence={risk_conf_f:.2f}, needs_confirm={needs_confirm_f:.2f}).",
        )

    return (
        "ask",
        "Decision 1 uncertain or borderline; fallback to standard confirmation "
        f"(risk={risk_choice}, confidence={risk_conf_f:.2f}, needs_confirm={needs_confirm_f:.2f}).",
    )


def evaluate_stage2(
    payload: dict[str, Any],
    *,
    api_key: str,
    endpoint: str = rd.DEFAULT_ENDPOINT,
    timeout: float = DECISION1_TIMEOUT_SECONDS,
    opener: Callable[..., Any] | None = None,
) -> tuple[str, str]:
    """第 2 段の Decision 1 API 呼び出しと安全フォールバックを行う。"""
    if not api_key:
        print(
            "pretool_guard: GEMINI_API_KEY is not set; falling back to ask.",
            file=sys.stderr,
        )
        return ("ask", FALLBACK_REASON)

    try:
        raw_response = rd.call_decisions_api(
            payload,
            api_key=api_key,
            endpoint=endpoint,
            timeout=timeout,
            opener=opener,
        )
        enriched = rd.enrich_response(raw_response)
        return decide_from_answers(enriched.get("answers") or {})
    except rd.SafetyBlockError as exc:
        msg = redact_secrets(f"{exc.source}/{exc.code}: {exc.message}", (api_key,))
        print(f"pretool_guard: SafetyBlockError ({msg})", file=sys.stderr)
        return ("ask", FALLBACK_REASON)
    except rd.ApiRequestError as exc:
        msg = redact_secrets(exc.message, (api_key,))
        print(f"pretool_guard: ApiRequestError ({msg})", file=sys.stderr)
        return ("ask", FALLBACK_REASON)
    except (TimeoutError, OSError, ValueError, json.JSONDecodeError) as exc:
        msg = redact_secrets(f"{type(exc).__name__}: {exc}", (api_key,))
        print(f"pretool_guard: fallback due to error ({msg})", file=sys.stderr)
        return ("ask", FALLBACK_REASON)


def _extract_hook_metadata(
    stdin_payload_text: str,
) -> tuple[str, str, str, str, str, str]:
    """PreToolUse 標準入力 JSON から (tool_name, cwd, command_line, conversation_id, transcript_path, artifact_dir) を抽出する。"""
    data = json.loads(stdin_payload_text)
    if not isinstance(data, dict):
        raise ValueError("PreToolUse stdin payload must be a JSON object.")

    tool_call = data.get("toolCall")
    if not isinstance(tool_call, dict):
        tool_call = {}
    tool_name = str(tool_call.get("name") or "")
    args = tool_call.get("args")
    if not isinstance(args, dict):
        args = {}
    command_line = str(
        args.get("CommandLine")
        or args.get("commandLine")
        or args.get("command")
        or ""
    )
    cwd = str(data.get("cwd") or "")
    if not cwd and isinstance(data.get("workspacePaths"), list) and data["workspacePaths"]:
        cwd = str(data["workspacePaths"][0] or "")
    conversation_id = str(data.get("conversationId") or "")
    transcript_path = str(data.get("transcriptPath") or "")
    artifact_dir = str(data.get("artifactDirectoryPath") or "")
    return tool_name, cwd, command_line, conversation_id, transcript_path, artifact_dir


def _extract_hook_context(stdin_payload_text: str) -> tuple[str, str, str]:
    """PreToolUse 標準入力 JSON から (tool_name, cwd, command_line) を抽出する。"""
    tool_name, cwd, command_line, _, _, _ = _extract_hook_metadata(stdin_payload_text)
    return tool_name, cwd, command_line


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="PreToolUse ハイブリッド安全ガードレール（ローカル判定 + Gemini Decision 1）"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="API 送信を行わずに第 1 段判定結果または検証済み Decision 1 ペイロードを出力する",
    )
    parser.add_argument(
        "--command",
        default=None,
        help="標準入力 JSON の代わりに直接評価するコマンド文字列",
    )
    parser.add_argument(
        "--cwd",
        default="",
        help="--command 指定時に使用する作業ディレクトリ文字列",
    )
    parser.add_argument(
        "--teamwork",
        action="store_true",
        help="--command 指定時に /teamwork 配下サブエージェントとして評価する",
    )
    parser.add_argument(
        "--endpoint",
        default=rd.DEFAULT_ENDPOINT,
        help="Decision 1 API エンドポイント URL",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DECISION1_TIMEOUT_SECONDS,
        help="Decision 1 API タイムアウト秒数（既定: 8.0）",
    )
    return parser


def _configure_utf8_stdio() -> None:
    dh.configure_utf8_stdio()


def main(
    argv: list[str] | None = None,
    *,
    opener: Callable[..., Any] | None = None,
    env: dict[str, str] | None = None,
    stdin_text: str | None = None,
) -> int:
    _configure_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.command is not None:
        tool_name = "run_command"
        cwd = args.cwd
        command_line = args.command
        is_teamwork = bool(args.teamwork)
    else:
        raw_stdin = stdin_text if stdin_text is not None else sys.stdin.read()
        try:
            (
                tool_name,
                cwd,
                command_line,
                conversation_id,
                transcript_path,
                artifact_dir,
            ) = _extract_hook_metadata(raw_stdin)
        except (ValueError, json.JSONDecodeError) as exc:
            print(
                f"pretool_guard: invalid PreToolUse stdin JSON ({redact_secrets(str(exc))})",
                file=sys.stderr,
            )
            print(json.dumps({"decision": "ask", "reason": FALLBACK_REASON}, ensure_ascii=False))
            return 0

        if tool_name and tool_name != "run_command" and not command_line:
            print(
                json.dumps(
                    {
                        "decision": "ask",
                        "reason": f"Non-shell tool '{tool_name}' deferred to standard confirmation.",
                    },
                    ensure_ascii=False,
                )
            )
            return 0

        is_teamwork = _is_teamwork_conversation(
            conversation_id,
            transcript_path=transcript_path,
            artifact_dir=artifact_dir,
        )

    is_posix_shell = (os.name != "nt") and (not cwd or cwd.startswith("/"))
    stage1 = evaluate_stage1(
        command_line, is_teamwork=is_teamwork, cwd=cwd, posix_shell=is_posix_shell
    )
    if stage1 is not None:
        decision, reason = stage1
        out: dict[str, Any] = {"decision": decision, "reason": reason}
        if args.dry_run:
            out["stage"] = "local"
        print(json.dumps(out, ensure_ascii=False))
        return 0

    try:
        payload, masked_command = build_decision1_payload(tool_name, cwd, command_line)
    except ValueError as exc:
        print(
            f"pretool_guard: payload validation failed ({redact_secrets(str(exc))})",
            file=sys.stderr,
        )
        print(json.dumps({"decision": "ask", "reason": FALLBACK_REASON}, ensure_ascii=False))
        return 0

    if args.dry_run:
        dry_out = {
            "stage": "decision1",
            "dry_run": True,
            "tool_name": tool_name or "run_command",
            "cwd": cwd,
            "masked_command": masked_command,
            "payload": payload,
        }
        print(json.dumps(dry_out, ensure_ascii=False, indent=2))
        return 0

    environ = os.environ if env is None else env
    api_key = environ.get("GEMINI_API_KEY", "").strip()
    decision, reason = evaluate_stage2(
        payload,
        api_key=api_key,
        endpoint=args.endpoint,
        timeout=args.timeout,
        opener=opener,
    )
    print(json.dumps({"decision": decision, "reason": reason}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
