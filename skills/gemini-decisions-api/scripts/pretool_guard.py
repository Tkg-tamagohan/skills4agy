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
    }
)
PS_SAFE_ENCODINGS = frozenset({"utf8", "utf8nobom", "utf8bom", "ascii", "unicode", "default"})
MAX_TEAMWORK_STATEMENTS = 30

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


def _split_top_level_segments_raw(text: str) -> list[str]:
    """連結記号・パイプ・改行および $() / バッククォート内をセグメント分割する（従来分割）。"""
    raw_parts = re.split(r"&&|\|\||[;|&`]|[\r\n]+", text)
    segments: list[str] = []
    for part in raw_parts:
        stripped = part.strip()
        if not stripped:
            continue
        segments.append(stripped)
        for sub in re.findall(r"\$\(([^)]+)\)", stripped):
            sub_stripped = sub.strip()
            if sub_stripped:
                segments.append(sub_stripped)
    return segments


def _split_unquoted_top_level(command: str) -> list[str] | None:
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
            elif quote == '"' and ch == "\\" and i + 1 < n and command[i + 1] == '"':
                buf.append('"')
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
    for arg in tokens[idx + 1 :]:
        low = arg.lower()
        if low in {"--pre", "--pre-glob"} or low.startswith(("--pre=", "--pre-glob=")):
            return False
    return True


def _extract_double_quoted_substitutions(segment: str) -> list[str]:
    """ダブルクォート内のみから $(...) と `...` の中身を取り出し、サブセグメント列を返す。"""
    dq_chunks: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    n = len(segment)

    while i < n:
        ch = segment[i]
        if quote == "'":
            if ch == "'":
                quote = None
            i += 1
            continue
        if quote == '"':
            if ch == "\\" and i + 1 < n and segment[i + 1] == '"':
                buf.append('\\"')
                i += 2
                continue
            if ch == '"':
                dq_chunks.append("".join(buf))
                buf = []
                quote = None
            else:
                buf.append(ch)
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch
        i += 1

    subs: list[str] = []
    for dq in dq_chunks:
        for body in re.findall(r"\$\(([^)]+)\)", dq):
            subs.extend(_split_top_level_segments_raw(body))
        for body in re.findall(r"`([^`]+)`", dq):
            subs.extend(_split_top_level_segments_raw(body))
    return subs


def _split_top_level_segments(command: str) -> list[str]:
    """連結記号・パイプ・改行および $() / バッククォート内をセグメント分割する。"""
    unquoted_parts = _split_unquoted_top_level(command)
    if unquoted_parts is None:
        return _split_top_level_segments_raw(command)

    segments: list[str] = []
    for part in unquoted_parts:
        if _is_safe_rg_segment(part):
            segments.append(part)
            segments.extend(_extract_double_quoted_substitutions(part))
        else:
            segments.extend(_split_top_level_segments_raw(part))
    return segments


def _command_basename(token: str) -> str:
    """パスや .exe 拡張子を除いた小文字のコマンド名を返す。"""
    cleaned = token.strip().strip("\"'")
    name = cleaned.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def _unwrap_segment_tokens(tokens: list[str]) -> list[list[str]]:
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
                for seg in _split_top_level_segments(nested):
                    results.extend(_unwrap_segment_tokens(_tokenize_lossy(seg)))
                break
    elif head == "rg":
        i = 1
        while i < len(sub_tokens):
            tok = sub_tokens[i]
            low = tok.lower()
            nested: str | None = None
            if low == "--pre" and i + 1 < len(sub_tokens):
                nested = sub_tokens[i + 1]
                i += 2
            elif low.startswith("--pre="):
                nested = tok.split("=", 1)[1]
                i += 1
            else:
                i += 1
                continue
            if nested:
                for seg in _split_top_level_segments(nested):
                    results.extend(_unwrap_segment_tokens(_tokenize_lossy(seg)))
    return results


def _collect_all_command_segments(command: str) -> list[list[str]]:
    all_segments: list[list[str]] = []
    for seg in _split_top_level_segments(command):
        tokens = _tokenize_lossy(seg)
        all_segments.extend(_unwrap_segment_tokens(tokens))
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


def _check_destructive_command(tokens: list[str]) -> str | None:
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
            return "Remove-Item -Recurse -Force"
        return None

    if head in {"del", "erase", "rmdir", "rd"}:
        if "/s" in low_args and "/q" in low_args:
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


def _split_whitelist_segments(command: str) -> list[str] | None:
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
            elif quote == '"' and ch == "\\" and i + 1 < n and command[i + 1] == '"':
                buf.append('\\"')
                i += 2
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
        for arg in args:
            low = arg.lower()
            if low in {"--pre", "--pre-glob"} or low.startswith(("--pre=", "--pre-glob=")):
                return False, False
        return True, False

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


def _classify_whitelisted_command(command: str) -> tuple[bool, bool]:
    """安全な環境変数・ローカル cd・定型 fail-fast ガード・単純連結を含む厳格ホワイトリスト判定。"""
    stripped = command.strip()
    if not stripped:
        return False, False
    segments = _split_whitelist_segments(stripped)
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

    match = re.match(r"<<(-?)\s*'([A-Za-z_][A-Za-z0-9_]*)'", line_no_eol[offsets[0] :])
    if not match:
        return False, False, ""
    return True, bool(match.group(1)), match.group(2)


def _strip_verbatim_herestrings(command: str) -> tuple[str, list[str]]:
    """PowerShell @'...'@ と POSIX <<'DELIM' の逐語本体を退避し (置換後コマンド, 本体一覧) を返す。

    未閉鎖や曖昧な構文を検出した場合は安全側で (command, []) へフォールバックする。
    """
    lines = command.splitlines(keepends=True)
    if not lines:
        return command, []

    mode: str | None = None
    in_quote: str | None = None
    heredoc_delim = ""
    heredoc_strip_tabs = False
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
                    return command, []
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
                return command, []
            if found_hd:
                heredoc_strip_tabs = flag_or_fail
                heredoc_delim = delim
                mode = "posix_heredoc"
                current_body = []

        out_parts.append(line)

    if mode is not None or in_quote is not None:
        return command, []
    return "".join(out_parts), bodies


def _has_code_exec_sink(stripped_command: str, segments: list[list[str]]) -> bool:
    """コード実行シンク（シェル起動、eval/iex、呼び出し演算子 &、ドットソース等）を検出する。"""
    for tokens in segments:
        if tokens and _command_basename(tokens[0]) in CODE_EXEC_SINKS:
            return True

    if re.search(
        r"\b(?:scriptblock|invoke-expression|iex|invoke-command|icm)\b",
        stripped_command,
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


def _is_safe_teamwork_dir(path: str) -> bool:
    """ローカル FS パスかつ .agents/teamwork 配下（.. なし）であることを検証する。"""
    if not _is_safe_filesystem_cd_target(path):
        return False
    norm = path.strip().replace("\\", "/")
    parts = [p for p in norm.split("/") if p]
    if ".." in parts:
        return False
    low_parts = [p.lower() for p in parts]
    return any(
        low_parts[i] == ".agents" and low_parts[i + 1] == "teamwork"
        for i in range(len(low_parts) - 1)
    )


def _is_safe_teamwork_md_file(path: str) -> bool:
    """パスが .agents/teamwork 配下の .md ファイル（.env 系除外）であることを検証する。"""
    if not _is_safe_teamwork_dir(path):
        return False
    norm = path.strip().replace("\\", "/")
    if norm.endswith("/"):
        return False
    parts = [p for p in norm.split("/") if p]
    low_parts = [p.lower() for p in parts]
    tw_idx = next(
        (
            i
            for i in range(len(low_parts) - 1)
            if low_parts[i] == ".agents" and low_parts[i + 1] == "teamwork"
        ),
        None,
    )
    if tw_idx is None or tw_idx + 2 >= len(low_parts):
        return False
    base = low_parts[-1]
    if not base.endswith(".md") or len(base) <= 3:
        return False
    if dh.is_blocked_env_path(base):
        return False
    return True


def _strip_outer_parens(expr: str) -> str | None:
    """式の外側の対応する丸括弧を剥がす。括弧不整合時は None を返す。"""
    cur = expr.strip()
    while cur.startswith("(") and cur.endswith(")"):
        depth = 0
        in_quote: str | None = None
        matched_end = False
        i = 0
        n = len(cur)
        while i < n:
            ch = cur[i]
            if in_quote == "'":
                if ch == "'":
                    if i + 1 < n and cur[i + 1] == "'":
                        i += 2
                        continue
                    in_quote = None
                i += 1
                continue
            if in_quote == '"':
                if ch == "`" and i + 1 < n:
                    i += 2
                    continue
                if ch == "\\" and i + 1 < n and cur[i + 1] in ('"', "\\"):
                    i += 2
                    continue
                if ch == '"':
                    in_quote = None
                i += 1
                continue
            if ch in ("'", '"'):
                in_quote = ch
            elif ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    if i == n - 1:
                        matched_end = True
                    break
                if depth < 0:
                    return None
            i += 1
        if in_quote is not None or depth != 0 or not matched_end:
            return None
        cur = cur[1:-1].strip()
    return cur


def _extract_single_quoted_literal(expr: str) -> str | None:
    """単一引用リテラル '...'（'' エスケープ対応）から中身を取り出す。"""
    s = expr.strip()
    if len(s) < 2 or not s.startswith("'") or not s.endswith("'"):
        return None
    buf: list[str] = []
    i = 1
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == "'":
            if i + 1 < n and s[i + 1] == "'":
                buf.append("'")
                i += 2
                continue
            if i == n - 1:
                return "".join(buf)
            return None
        buf.append(ch)
        i += 1
    return None


def _extract_double_quoted_inner(expr: str) -> str | None:
    """二重引用リテラル "..." 全体が単一文字列リテラルなら中身を返す。"""
    s = expr.strip()
    if len(s) < 2 or not s.startswith('"') or not s.endswith('"'):
        return None
    i = 1
    n = len(s)
    while i < n:
        ch = s[i]
        if ch == "`" and i + 1 < n:
            i += 2
            continue
        if ch == "\\" and i + 1 < n and s[i + 1] in ('"', "\\"):
            i += 2
            continue
        if ch == '"':
            if i == n - 1:
                return s[1:-1]
            return None
        i += 1
    return None


def _split_ps_args(text: str) -> list[str] | None:
    """PowerShell 引数列を引用符と丸括弧を保持したまま空白で分割する。"""
    tokens: list[str] = []
    buf: list[str] = []
    in_quote: str | None = None
    paren_depth = 0
    i = 0
    n = len(text)

    while i < n:
        ch = text[i]
        if in_quote == "'":
            buf.append(ch)
            if ch == "'":
                if i + 1 < n and text[i + 1] == "'":
                    buf.append("'")
                    i += 2
                    continue
                in_quote = None
            i += 1
            continue
        if in_quote == '"':
            buf.append(ch)
            if ch == "`" and i + 1 < n:
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == "\\" and i + 1 < n and text[i + 1] in ('"', "\\"):
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_quote = None
            i += 1
            continue

        if ch in ("'", '"'):
            in_quote = ch
            buf.append(ch)
        elif ch == "(":
            paren_depth += 1
            buf.append(ch)
        elif ch == ")":
            paren_depth -= 1
            if paren_depth < 0:
                return None
            buf.append(ch)
        elif ch in ("{", "}"):
            return None
        elif ch.isspace() and paren_depth == 0:
            if buf:
                tokens.append("".join(buf))
                buf = []
        else:
            buf.append(ch)
        i += 1

    if in_quote is not None or paren_depth != 0:
        return None
    if buf:
        tokens.append("".join(buf))
    return tokens


def _split_top_level_char(text: str, sep: str, *, allow_empty: bool = False) -> list[str] | None:
    """引用符・丸括弧・波括弧の外側で単一区切り文字により分割する。"""
    parts: list[str] = []
    buf: list[str] = []
    in_quote: str | None = None
    paren_depth = 0
    brace_depth = 0
    i = 0
    n = len(text)

    while i < n:
        ch = text[i]
        if in_quote == "'":
            buf.append(ch)
            if ch == "'":
                if i + 1 < n and text[i + 1] == "'":
                    buf.append("'")
                    i += 2
                    continue
                in_quote = None
            i += 1
            continue
        if in_quote == '"':
            buf.append(ch)
            if ch == "`" and i + 1 < n:
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == "\\" and i + 1 < n and text[i + 1] in ('"', "\\"):
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_quote = None
            i += 1
            continue

        if ch in ("'", '"'):
            in_quote = ch
            buf.append(ch)
        elif ch == "(":
            paren_depth += 1
            buf.append(ch)
        elif ch == ")":
            paren_depth -= 1
            if paren_depth < 0:
                return None
            buf.append(ch)
        elif ch == "{":
            brace_depth += 1
            buf.append(ch)
        elif ch == "}":
            brace_depth -= 1
            if brace_depth < 0:
                return None
            buf.append(ch)
        elif ch == sep and paren_depth == 0 and brace_depth == 0:
            part = "".join(buf).strip()
            if not part and not allow_empty:
                return None
            parts.append(part)
            buf = []
        else:
            buf.append(ch)
        i += 1

    if in_quote is not None or paren_depth != 0 or brace_depth != 0:
        return None
    tail = "".join(buf).strip()
    if not tail and not allow_empty:
        return None
    parts.append(tail)
    return parts


def _split_ps_statements(text: str) -> list[str] | None:
    """PowerShell 文を改行およびトップレベル ; で分割する（単一階層 {} 内は保持）。"""
    stmts: list[str] = []
    buf: list[str] = []
    in_quote: str | None = None
    paren_depth = 0
    brace_depth = 0
    i = 0
    n = len(text)

    while i < n:
        ch = text[i]
        if in_quote == "'":
            buf.append(ch)
            if ch == "'":
                if i + 1 < n and text[i + 1] == "'":
                    buf.append("'")
                    i += 2
                    continue
                in_quote = None
            i += 1
            continue
        if in_quote == '"':
            buf.append(ch)
            if ch == "`" and i + 1 < n:
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == "\\" and i + 1 < n and text[i + 1] in ('"', "\\"):
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_quote = None
            i += 1
            continue

        if ch in ("'", '"'):
            in_quote = ch
            buf.append(ch)
        elif ch == "(":
            paren_depth += 1
            buf.append(ch)
        elif ch == ")":
            paren_depth -= 1
            if paren_depth < 0:
                return None
            buf.append(ch)
        elif ch == "{":
            brace_depth += 1
            if brace_depth > 1:
                return None
            buf.append(ch)
        elif ch == "}":
            brace_depth -= 1
            if brace_depth < 0:
                return None
            buf.append(ch)
        elif ch in ";\r\n" and paren_depth == 0 and brace_depth == 0:
            stmt = "".join(buf).strip()
            if stmt:
                stmts.append(stmt)
                if len(stmts) > MAX_TEAMWORK_STATEMENTS:
                    return None
            buf = []
        else:
            buf.append(ch)
        i += 1

    if in_quote is not None or paren_depth != 0 or brace_depth != 0:
        return None
    tail = "".join(buf).strip()
    if tail:
        stmts.append(tail)
        if len(stmts) > MAX_TEAMWORK_STATEMENTS:
            return None
    return stmts or None


def _parse_ps_double_quoted_text(
    inner: str, known_vars: dict[str, str] | set[str], *, allow_backtick_escapes: bool
) -> str | None:
    """二重引用文字列内の展開が既知変数のみであることを検証し、解決済み文字列（または空でない値）を返す。"""
    if "$(" in inner:
        return None
    out: list[str] = []
    j = 0
    m = len(inner)
    while j < m:
        ch = inner[j]
        if ch == "`":
            if not allow_backtick_escapes or j + 1 >= m or inner[j + 1] not in "nrt\"'`$":
                return None
            out.append(inner[j + 1])
            j += 2
            continue
        if ch == "$":
            if j + 1 >= m:
                return None
            if inner[j + 1] == "{":
                var_m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\}", inner[j + 2 :])
                if not var_m:
                    return None
                vname = var_m.group(1).lower()
                if vname not in known_vars:
                    return None
                if isinstance(known_vars, dict):
                    out.append(known_vars[vname])
                else:
                    out.append(f"${{{vname}}}")
                j += 2 + len(var_m.group(0))
                continue
            var_m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)", inner[j + 1 :])
            if not var_m:
                return None
            after_idx = j + 1 + len(var_m.group(1))
            if after_idx < m and inner[after_idx] in ":([.":
                return None
            vname = var_m.group(1).lower()
            if vname not in known_vars:
                return None
            if isinstance(known_vars, dict):
                out.append(known_vars[vname])
            else:
                out.append(f"${vname}")
            j = after_idx
            continue
        out.append(ch)
        j += 1
    return "".join(out)


def _resolve_ps_path_expr(expr: str, path_vars: dict[str, str]) -> str | None:
    """PowerShell のパス式を静的評価して文字列パスへ解決する。安全でない場合は None。"""
    inner = _strip_outer_parens(expr)
    if inner is None or not inner:
        return None

    sq = _extract_single_quoted_literal(inner)
    if sq is not None:
        return sq

    var_m = re.fullmatch(r"\$([A-Za-z_][A-Za-z0-9_]*)", inner)
    if var_m:
        return path_vars.get(var_m.group(1).lower())

    dq = _extract_double_quoted_inner(inner)
    if dq is not None:
        return _parse_ps_double_quoted_text(dq, path_vars, allow_backtick_escapes=False)

    jp_m = re.match(r"^Join-Path\s+(.+)$", inner, re.IGNORECASE)
    if jp_m:
        args = _split_ps_args(jp_m.group(1))
        if args is None:
            return None
        base_expr: str | None = None
        child_expr: str | None = None
        pos: list[str] = []
        idx = 0
        while idx < len(args):
            tok = args[idx]
            if tok.startswith("-"):
                flag, has_colon, inline_val = tok.partition(":")
                low_flag = flag.lower()
                if low_flag in {"-path", "-childpath"}:
                    if has_colon:
                        val = inline_val
                    elif idx + 1 < len(args):
                        idx += 1
                        val = args[idx]
                    else:
                        return None
                    if low_flag == "-path":
                        if base_expr is not None:
                            return None
                        base_expr = val
                    else:
                        if child_expr is not None:
                            return None
                        child_expr = val
                else:
                    return None
            else:
                pos.append(tok)
            idx += 1
        for p in pos:
            if base_expr is None:
                base_expr = p
            elif child_expr is None:
                child_expr = p
            else:
                return None
        if base_expr is None or child_expr is None:
            return None
        base = _resolve_ps_path_expr(base_expr, path_vars)
        child = _resolve_ps_path_expr(child_expr, path_vars)
        if not base or not child:
            return None
        if child.startswith(("/", "\\")) or ".." in child.replace("\\", "/").split("/"):
            return None
        if any(ch in child for ch in ":*?[]") or any(ord(ch) < 32 for ch in child):
            return None
        return base.rstrip("/\\") + "/" + child.replace("\\", "/").lstrip("/")

    sp_m = re.match(r"^Split-Path\s+(.+)$", inner, re.IGNORECASE)
    if sp_m:
        args = _split_ps_args(sp_m.group(1))
        if args is None:
            return None
        target_expr: str | None = None
        idx = 0
        while idx < len(args):
            tok = args[idx]
            if tok.startswith("-"):
                flag, has_colon, inline_val = tok.partition(":")
                low_flag = flag.lower()
                if low_flag == "-parent" and not has_colon:
                    idx += 1
                    continue
                if low_flag in {"-path", "-literalpath"}:
                    if has_colon:
                        val = inline_val
                    elif idx + 1 < len(args):
                        idx += 1
                        val = args[idx]
                    else:
                        return None
                    if target_expr is not None:
                        return None
                    target_expr = val
                else:
                    return None
            else:
                if target_expr is not None:
                    return None
                target_expr = tok
            idx += 1
        if target_expr is None:
            return None
        resolved = _resolve_ps_path_expr(target_expr, path_vars)
        if not resolved:
            return None
        norm = resolved.replace("\\", "/").rstrip("/")
        if "/" not in norm:
            return None
        return norm.rsplit("/", 1)[0]

    return None


def _is_safe_ps_text_expr(
    expr: str, text_vars: set[str], path_vars: dict[str, str]
) -> bool:
    """文字列式が静的リテラル・既知変数・+ 連結のみで構成されているか検証する。"""
    inner = _strip_outer_parens(expr)
    if inner is None or not inner:
        return False

    parts = _split_top_level_char(inner, "+")
    if parts is None:
        return False

    known_vars = text_vars | set(path_vars.keys())
    for part in parts:
        p = _strip_outer_parens(part)
        if p is None or not p:
            return False
        if _extract_single_quoted_literal(p) is not None:
            continue
        var_m = re.fullmatch(r"\$([A-Za-z_][A-Za-z0-9_]*)", p)
        if var_m:
            if var_m.group(1).lower() not in known_vars:
                return False
            continue
        dq = _extract_double_quoted_inner(p)
        if dq is not None:
            if _parse_ps_double_quoted_text(dq, known_vars, allow_backtick_escapes=True) is None:
                return False
            continue
        return False
    return True


def _is_safe_ps_encoding_expr(expr: str, enc_vars: set[str]) -> bool:
    """PowerShell エンコーディング指定式が許可パターンに一致するか検証する。"""
    inner = _strip_outer_parens(expr)
    if inner is None or not inner:
        return False
    var_m = re.fullmatch(r"\$([A-Za-z_][A-Za-z0-9_]*)", inner)
    if var_m:
        return var_m.group(1).lower() in enc_vars
    patterns = (
        r"^\[(?:System\.)?Text\.UTF8Encoding\]::new\(\s*(?:\$false|\$true)?\s*\)$",
        r"^New-Object\s+(?:-TypeName\s+)?(?:System\.)?Text\.UTF8Encoding(?:\s+(?:\$false|\$true)|\s*\(\s*(?:\$false|\$true)\s*\))?$",
        r"^\[(?:System\.)?Text\.Encoding\]::(?:UTF8|Unicode|ASCII)$",
    )
    return any(re.fullmatch(pat, inner, re.IGNORECASE) for pat in patterns)


def _extract_ps_single_path_arg(
    rest: str, path_vars: dict[str, str], *, allow_flags: frozenset[str] = frozenset()
) -> str | None:
    """-Path / -LiteralPath または位置引数 1 件のパス式を解決して返す。"""
    args = _split_ps_args(rest)
    if args is None:
        return None
    target_expr: str | None = None
    idx = 0
    while idx < len(args):
        tok = args[idx]
        if tok.startswith("-"):
            flag, has_colon, inline_val = tok.partition(":")
            low_flag = flag.lower()
            if low_flag in allow_flags and not has_colon:
                idx += 1
                continue
            if low_flag in {"-path", "-literalpath"}:
                if has_colon:
                    val = inline_val
                elif idx + 1 < len(args):
                    idx += 1
                    val = args[idx]
                else:
                    return None
                if target_expr is not None:
                    return None
                target_expr = val
            else:
                return None
        else:
            if target_expr is not None:
                return None
            target_expr = tok
        idx += 1
    if target_expr is None:
        return None
    return _resolve_ps_path_expr(target_expr, path_vars)


def _is_safe_ps_dir_create_stmt(stmt: str, path_vars: dict[str, str]) -> bool:
    """ディレクトリ作成文が .agents/teamwork 配下のみを対象としているか検証する。"""
    pipe_parts = _split_top_level_char(stmt, "|")
    if pipe_parts is None:
        return False
    if len(pipe_parts) == 2:
        if pipe_parts[1].strip().lower() != "out-null":
            return False
        head_stmt = pipe_parts[0].strip()
    elif len(pipe_parts) == 1:
        head_stmt = pipe_parts[0].strip()
    else:
        return False

    dir_method_m = re.fullmatch(
        r"\[(?:System\.)?IO\.Directory\]::CreateDirectory\((.+)\)",
        head_stmt,
        re.IGNORECASE,
    )
    if dir_method_m:
        resolved = _resolve_ps_path_expr(dir_method_m.group(1), path_vars)
        return resolved is not None and _is_safe_teamwork_dir(resolved)

    args = _split_ps_args(head_stmt)
    if not args:
        return False
    cmd = args[0].lower()
    if cmd in {"mkdir", "md"}:
        resolved = _extract_ps_single_path_arg(
            " ".join(args[1:]), path_vars, allow_flags=frozenset({"-force"})
        )
        return resolved is not None and _is_safe_teamwork_dir(resolved)

    if cmd == "new-item":
        item_type: str | None = None
        target_expr: str | None = None
        idx = 1
        while idx < len(args):
            tok = args[idx]
            if tok.startswith("-"):
                flag, has_colon, inline_val = tok.partition(":")
                low_flag = flag.lower()
                if low_flag == "-force" and not has_colon:
                    idx += 1
                    continue
                if low_flag in {"-itemtype", "-type", "-path", "-literalpath"}:
                    if has_colon:
                        val = inline_val
                    elif idx + 1 < len(args):
                        idx += 1
                        val = args[idx]
                    else:
                        return False
                    if low_flag in {"-itemtype", "-type"}:
                        if item_type is not None:
                            return False
                        item_type = val
                    else:
                        if target_expr is not None:
                            return False
                        target_expr = val
                else:
                    return False
            else:
                if target_expr is not None:
                    return False
                target_expr = tok
            idx += 1
        if item_type is None or target_expr is None:
            return False
        item_unq = _extract_single_quoted_literal(item_type)
        if item_unq is None:
            item_unq = item_type.strip().strip('"')
        if item_unq.lower() not in {"directory", "d"}:
            return False
        resolved = _resolve_ps_path_expr(target_expr, path_vars)
        return resolved is not None and _is_safe_teamwork_dir(resolved)

    return False


def _is_safe_ps_test_path_expr(expr: str, path_vars: dict[str, str]) -> bool:
    inner = _strip_outer_parens(expr)
    if inner is None:
        return False
    m = re.match(r"^Test-Path\s+(.+)$", inner, re.IGNORECASE)
    if not m:
        return False
    resolved = _extract_ps_single_path_arg(m.group(1), path_vars)
    return resolved is not None and _is_safe_teamwork_dir(resolved)


def _is_safe_ps_get_item_expr(expr: str, path_vars: dict[str, str]) -> bool:
    inner = _strip_outer_parens(expr)
    if inner is None:
        return False
    m = re.match(r"^Get-Item\s+(.+)$", inner, re.IGNORECASE)
    if not m:
        return False
    resolved = _extract_ps_single_path_arg(m.group(1), path_vars)
    return resolved is not None and _is_safe_teamwork_dir(resolved)


def _match_ps_if_dir_create(stmt: str) -> tuple[str, str] | None:
    """if (-not (Test-Path ...)) { <body_stmt> } 形式から (cond_inner, body_stmt) を抽出する。"""
    m = re.match(r"^if\s*\(", stmt, re.IGNORECASE)
    if not m:
        return None
    i = m.end()
    n = len(stmt)
    depth = 1
    in_quote: str | None = None
    cond_start = i
    while i < n and depth > 0:
        ch = stmt[i]
        if in_quote == "'":
            if ch == "'":
                if i + 1 < n and stmt[i + 1] == "'":
                    i += 2
                    continue
                in_quote = None
            i += 1
            continue
        if in_quote == '"':
            if ch == "`" and i + 1 < n:
                i += 2
                continue
            if ch == "\\" and i + 1 < n and stmt[i + 1] in ('"', "\\"):
                i += 2
                continue
            if ch == '"':
                in_quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            in_quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                break
        i += 1
    if depth != 0 or in_quote is not None:
        return None
    cond_str = stmt[cond_start:i].strip()
    rest = stmt[i + 1 :].strip()
    if not rest.startswith("{") or not rest.endswith("}"):
        return None
    body_str = rest[1:-1].strip()
    if not body_str:
        return None
    return cond_str, body_str


def _is_whitelisted_ps_teamwork_md_write(stripped: str) -> bool:
    """PowerShell の .agents/teamwork 配下 .md 作成・更新スクリプトを厳格に記号検証する。"""
    stmts = _split_ps_statements(stripped)
    if stmts is None:
        return False

    path_vars: dict[str, str] = {}
    text_vars: set[str] = set()
    enc_vars: set[str] = set()
    md_write_count = 0
    last_was_cmd = False

    for stmt in stmts:
        if PS_FAILFAST_GUARD_RE.fullmatch(stmt):
            if not last_was_cmd:
                return False
            last_was_cmd = False
            continue

        ps_env_m = PS_ENV_ASSIGN_RE.fullmatch(stmt)
        if ps_env_m:
            name = ps_env_m.group(1)
            val = next(g for g in ps_env_m.groups()[1:] if g is not None)
            if not _is_safe_env_assignment(name, val, case_insensitive=True):
                return False
            last_was_cmd = False
            continue

        assign_m = re.match(r"^\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$", stmt, re.DOTALL)
        if assign_m and not stmt.lstrip().lower().startswith("if"):
            vname = assign_m.group(1).lower()
            rhs = assign_m.group(2).strip()
            if _is_safe_ps_encoding_expr(rhs, enc_vars):
                enc_vars.add(vname)
                path_vars.pop(vname, None)
                text_vars.discard(vname)
                last_was_cmd = False
                continue
            resolved_path = _resolve_ps_path_expr(rhs, path_vars)
            if resolved_path is not None and _is_safe_teamwork_dir(resolved_path):
                path_vars[vname] = resolved_path
                text_vars.discard(vname)
                enc_vars.discard(vname)
                last_was_cmd = False
                continue
            if _is_safe_ps_text_expr(rhs, text_vars, path_vars):
                text_vars.add(vname)
                path_vars.pop(vname, None)
                enc_vars.discard(vname)
                last_was_cmd = False
                continue
            return False

        if_pair = _match_ps_if_dir_create(stmt)
        if if_pair is not None:
            cond_str, body_str = if_pair
            cond_m = re.match(r"^(?:-not\s+|!\s*)(.+)$", cond_str, re.IGNORECASE)
            if not cond_m or not _is_safe_ps_test_path_expr(cond_m.group(1), path_vars):
                return False
            if not _is_safe_ps_dir_create_stmt(body_str, path_vars):
                return False
            last_was_cmd = True
            continue

        if _is_safe_ps_dir_create_stmt(stmt, path_vars):
            last_was_cmd = True
            continue

        file_write_m = re.fullmatch(
            r"\[(?:System\.)?IO\.File\]::(?:WriteAllText|AppendAllText)\((.+)\)",
            stmt,
            re.IGNORECASE,
        )
        if file_write_m:
            call_args = _split_top_level_char(file_write_m.group(1), ",")
            if call_args is None or len(call_args) not in {2, 3}:
                return False
            target_path = _resolve_ps_path_expr(call_args[0], path_vars)
            if target_path is None or not _is_safe_teamwork_md_file(target_path):
                return False
            if not _is_safe_ps_text_expr(call_args[1], text_vars, path_vars):
                return False
            if len(call_args) == 3 and not _is_safe_ps_encoding_expr(call_args[2], enc_vars):
                return False
            md_write_count += 1
            last_was_cmd = True
            continue

        pipe_parts = _split_top_level_char(stmt, "|")
        if pipe_parts is None:
            return False

        # <textExpr> | Set-Content / Add-Content / Out-File ...
        if len(pipe_parts) == 2:
            cmd_args = _split_ps_args(pipe_parts[1])
            if cmd_args and cmd_args[0].lower() in {"set-content", "add-content", "out-file"}:
                if not _is_safe_ps_text_expr(pipe_parts[0], text_vars, path_vars):
                    return False
                if not _validate_ps_content_write(
                    cmd_args, path_vars, text_vars, has_piped_value=True
                ):
                    return False
                md_write_count += 1
                last_was_cmd = True
                continue

            # Get-Item ... | Select-Object <ident-list>
            if (
                _is_safe_ps_get_item_expr(pipe_parts[0], path_vars)
                and re.fullmatch(
                    r"Select-Object\s+[A-Za-z_][A-Za-z0-9_]*(?:\s*,\s*[A-Za-z_][A-Za-z0-9_]*)*",
                    pipe_parts[1].strip(),
                    re.IGNORECASE,
                )
            ):
                last_was_cmd = True
                continue

            return False

        if len(pipe_parts) != 1:
            return False

        single = pipe_parts[0]

        prop_m = re.fullmatch(r"(.+)\.([A-Za-z_][A-Za-z0-9_]*)", single)
        if prop_m and _is_safe_ps_get_item_expr(prop_m.group(1), path_vars):
            last_was_cmd = True
            continue

        if _is_safe_ps_test_path_expr(single, path_vars) or _is_safe_ps_get_item_expr(
            single, path_vars
        ):
            last_was_cmd = True
            continue

        args = _split_ps_args(single)
        if not args:
            return False
        cmd_low = args[0].lower()

        if cmd_low in {"set-content", "add-content", "out-file"}:
            if not _validate_ps_content_write(args, path_vars, text_vars, has_piped_value=False):
                return False
            md_write_count += 1
            last_was_cmd = True
            continue

        if cmd_low == "copy-item":
            if not _validate_ps_copy_md(args[1:], path_vars):
                return False
            md_write_count += 1
            last_was_cmd = True
            continue

        if cmd_low == "write-output":
            if len(args) < 2 or not all(
                _is_safe_ps_text_expr(arg, text_vars, path_vars) for arg in args[1:]
            ):
                return False
            last_was_cmd = True
            continue

        return False

    return md_write_count >= 1


def _validate_ps_content_write(
    args: list[str],
    path_vars: dict[str, str],
    text_vars: set[str],
    *,
    has_piped_value: bool,
) -> bool:
    """Set-Content / Add-Content / Out-File 引数検証。"""
    cmd_low = args[0].lower()
    path_expr: str | None = None
    value_expr: str | None = None
    pos: list[str] = []
    idx = 1
    while idx < len(args):
        tok = args[idx]
        if tok.startswith("-"):
            flag, has_colon, inline_val = tok.partition(":")
            low_flag = flag.lower()
            if low_flag in {"-nonewline", "-force"} and not has_colon:
                idx += 1
                continue
            path_flags = {"-path", "-literalpath"}
            if cmd_low == "out-file":
                path_flags = path_flags | {"-filepath"}
            if low_flag in path_flags:
                val = inline_val if has_colon else (args[idx + 1] if idx + 1 < len(args) else None)
                if val is None or path_expr is not None:
                    return False
                if not has_colon:
                    idx += 1
                path_expr = val
            elif low_flag in {"-value", "-inputobject"}:
                if has_piped_value:
                    return False
                val = inline_val if has_colon else (args[idx + 1] if idx + 1 < len(args) else None)
                if val is None or value_expr is not None:
                    return False
                if not has_colon:
                    idx += 1
                value_expr = val
            elif low_flag == "-encoding":
                val = inline_val if has_colon else (args[idx + 1] if idx + 1 < len(args) else None)
                if val is None:
                    return False
                if not has_colon:
                    idx += 1
                unq = _extract_single_quoted_literal(val)
                if unq is None:
                    unq = val.strip().strip('"')
                if unq.lower() not in PS_SAFE_ENCODINGS:
                    return False
            else:
                return False
        else:
            pos.append(tok)
        idx += 1

    for p in pos:
        if path_expr is None:
            path_expr = p
        elif value_expr is None and not has_piped_value:
            value_expr = p
        else:
            return False

    if path_expr is None or (not has_piped_value and value_expr is None):
        return False
    resolved = _resolve_ps_path_expr(path_expr, path_vars)
    if resolved is None or not _is_safe_teamwork_md_file(resolved):
        return False
    if value_expr is not None and not _is_safe_ps_text_expr(value_expr, text_vars, path_vars):
        return False
    return True


def _validate_ps_copy_md(args: list[str], path_vars: dict[str, str]) -> bool:
    """Copy-Item が .agents/teamwork 配下の .md 同士の複製に限定されているか検証する。"""
    src_expr: str | None = None
    dst_expr: str | None = None
    pos: list[str] = []
    idx = 0
    while idx < len(args):
        tok = args[idx]
        if tok.startswith("-"):
            flag, has_colon, inline_val = tok.partition(":")
            low_flag = flag.lower()
            if low_flag == "-force" and not has_colon:
                idx += 1
                continue
            if low_flag in {"-path", "-literalpath", "-destination"}:
                val = inline_val if has_colon else (args[idx + 1] if idx + 1 < len(args) else None)
                if val is None:
                    return False
                if not has_colon:
                    idx += 1
                if low_flag == "-destination":
                    if dst_expr is not None:
                        return False
                    dst_expr = val
                else:
                    if src_expr is not None:
                        return False
                    src_expr = val
            else:
                return False
        else:
            pos.append(tok)
        idx += 1

    for p in pos:
        if src_expr is None:
            src_expr = p
        elif dst_expr is None:
            dst_expr = p
        else:
            return False

    if src_expr is None or dst_expr is None:
        return False
    src_path = _resolve_ps_path_expr(src_expr, path_vars)
    dst_path = _resolve_ps_path_expr(dst_expr, path_vars)
    return (
        src_path is not None
        and dst_path is not None
        and _is_safe_teamwork_md_file(src_path)
        and _is_safe_teamwork_md_file(dst_path)
    )


def _split_posix_teamwork_statements(stripped: str) -> list[str] | None:
    """POSIX シェル文を改行・;・&& で分割し、パイプやサブシェル等の危険構文を拒否する。"""
    if re.search(r"`|\$\(|\$\{", stripped):
        return None
    stmts: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    n = len(stripped)

    while i < n:
        ch = stripped[i]
        if quote == "'":
            buf.append(ch)
            if ch == "'":
                quote = None
            i += 1
            continue
        if quote == '"':
            if ch == "\\" and i + 1 < n and stripped[i + 1] in ('"', "\\", "$", "`"):
                buf.append(ch)
                buf.append(stripped[i + 1])
                i += 2
                continue
            if ch == "$":
                return None
            buf.append(ch)
            if ch == '"':
                quote = None
            i += 1
            continue

        if ch in ("'", '"'):
            quote = ch
            buf.append(ch)
            i += 1
            continue

        if ch == "|":
            return None
        if ch == "&":
            if i + 1 < n and stripped[i + 1] == "&" and (i + 2 >= n or stripped[i + 2] != "&"):
                stmt = "".join(buf).strip()
                if not stmt:
                    return None
                stmts.append(stmt)
                if len(stmts) > MAX_TEAMWORK_STATEMENTS:
                    return None
                buf = []
                i += 2
                continue
            return None
        if ch in ";\r\n":
            stmt = "".join(buf).strip()
            if stmt:
                stmts.append(stmt)
                if len(stmts) > MAX_TEAMWORK_STATEMENTS:
                    return None
            buf = []
            i += 1
            continue

        buf.append(ch)
        i += 1

    if quote is not None:
        return None
    tail = "".join(buf).strip()
    if tail:
        stmts.append(tail)
        if len(stmts) > MAX_TEAMWORK_STATEMENTS:
            return None
    return stmts or None


def _unquote_posix_token(tok: str) -> str | None:
    s = tok.strip()
    if not s:
        return None
    if len(s) >= 2 and s[0] == "'" and s[-1] == "'":
        return s[1:-1] if "'" not in s[1:-1] else None
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        inner = s[1:-1]
        if "$" in inner or "`" in inner or '"' in inner:
            return None
        return inner
    if any(ch in s for ch in "'\"$`*?<>|;&()"):
        return None
    return s


def _is_whitelisted_posix_teamwork_md_write(stripped: str, *, has_heredoc: bool) -> bool:
    """POSIX の単一引用 heredoc による .agents/teamwork 配下 .md 作成コマンドを検証する。"""
    if not has_heredoc:
        return False
    stmts = _split_posix_teamwork_statements(stripped)
    if stmts is None:
        return False

    md_write_count = 0
    for stmt in stmts:
        try:
            tokens = _tokenize_command(stmt)
        except ValueError:
            return False
        if not tokens:
            continue
        head = _command_basename(tokens[0])

        if head == "mkdir":
            dirs = [t for t in tokens[1:] if t not in {"-p", "--parents"}]
            if any(t.startswith("-") for t in dirs) or not dirs:
                return False
            if not all(_is_safe_teamwork_dir(d) for d in dirs):
                return False
            continue

        if head == "cat":
            hd_pat = r"<<-?\s*'[A-Za-z_][A-Za-z0-9_]*'"
            rd_pat = r"(?:>>|>)\s*('[^']+'|\"[^\"]+\"|[^\s;|&<>'\"]+)"
            m1 = re.fullmatch(rf"cat\s+{hd_pat}\s+{rd_pat}", stmt)
            m2 = re.fullmatch(rf"cat\s+{rd_pat}\s+{hd_pat}", stmt)
            m = m1 or m2
            if not m:
                return False
            target = _unquote_posix_token(m.group(1))
            if target is None or not _is_safe_teamwork_md_file(target):
                return False
            md_write_count += 1
            continue

        if head == "ls":
            paths = [t for t in tokens[1:] if t not in {"-l", "-la", "-lh", "-a", "-1"}]
            if any(t.startswith("-") for t in paths) or not paths:
                return False
            if not all(_is_safe_teamwork_dir(p) for p in paths):
                return False
            continue

        if head == "wc":
            paths = [t for t in tokens[1:] if t not in {"-l", "-c", "-w", "-m"}]
            if any(t.startswith("-") for t in paths) or not paths:
                return False
            if not all(_is_safe_teamwork_dir(p) for p in paths):
                return False
            continue

        if head == "test":
            if len(tokens) != 3 or tokens[1] not in {"-f", "-e", "-d"}:
                return False
            if not _is_safe_teamwork_dir(tokens[2]):
                return False
            continue

        return False

    return md_write_count >= 1


def _is_whitelisted_teamwork_md_write(
    command: str, stripped_command: str, herestring_bodies: list[str]
) -> bool:
    """/teamwork 用の .agents/teamwork 配下 .md 作成・更新コマンドか検証する（機密検出時は拒否）。"""
    if dh.scan_text_for_secrets(stripped_command):
        return False
    if any(dh.scan_text_for_secrets(body) for body in herestring_bodies):
        return False
    if _is_whitelisted_ps_teamwork_md_write(stripped_command):
        return True
    if _is_whitelisted_posix_teamwork_md_write(
        stripped_command, has_heredoc=bool(herestring_bodies)
    ):
        return True
    return False


def evaluate_stage1(command: str) -> tuple[str, str] | None:
    """第 1 段の決定論的ローカル判定を行う。決着しない場合は None を返す。"""
    if not command.strip():
        return ("ask", "Empty command line; fallback to standard confirmation.")

    stripped_for_scan, herestring_bodies = _strip_verbatim_herestrings(command)
    use_stripped = False
    if herestring_bodies:
        outer_segments = _collect_all_command_segments(stripped_for_scan)
        if not _has_code_exec_sink(stripped_for_scan, outer_segments) and not _has_external_transfer(
            outer_segments
        ):
            use_stripped = True
            segments = outer_segments
            secret_hits = _extract_secret_file_hits(stripped_for_scan)
        else:
            segments = _collect_all_command_segments(command)
            secret_hits = _extract_secret_file_hits(command)
    else:
        segments = _collect_all_command_segments(command)
        secret_hits = _extract_secret_file_hits(command)

    if _has_external_transfer(segments) and (secret_hits or _has_env_dump(segments)):
        return (
            "deny",
            "Blocked by local secret-exfiltration policy: sensitive credential "
            "or environment data passed to an external transfer command.",
        )

    for seg_tokens in segments:
        destructive_reason = _check_destructive_command(seg_tokens)
        if destructive_reason is not None:
            return (
                "force_ask",
                f"Requires explicit confirmation: destructive operation detected locally ({destructive_reason}).",
            )

    if not secret_hits and not _has_env_dump(segments):
        allowed, includes_push = _classify_whitelisted_command(command)
        if allowed:
            if includes_push:
                return (
                    "allow",
                    "Allowed by local whitelist (safe feature-branch git push and read-only commands).",
                )
            return ("allow", "Allowed by local read-only and unit-test whitelist.")

        scan_text = stripped_for_scan if use_stripped else command
        if _is_whitelisted_teamwork_md_write(command, scan_text, herestring_bodies):
            return ("allow", "Allowed by local whitelist (teamwork markdown file creation).")

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


def _extract_hook_context(stdin_payload_text: str) -> tuple[str, str, str]:
    """PreToolUse 標準入力 JSON から (tool_name, cwd, command_line) を抽出する。"""
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
    else:
        raw_stdin = stdin_text if stdin_text is not None else sys.stdin.read()
        try:
            tool_name, cwd, command_line = _extract_hook_context(raw_stdin)
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

    stage1 = evaluate_stage1(command_line)
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
