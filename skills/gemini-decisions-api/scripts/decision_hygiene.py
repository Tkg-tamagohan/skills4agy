#!/usr/bin/env python3
"""Decision 1 系 CLI 群で共有する秘密情報検査、マスク、.env 判定、UTF-8 標準入出力設定モジュール。

外部依存を持たず Python 標準ライブラリのみで動作する。
"""

from __future__ import annotations

from pathlib import Path
import re
import sys
import urllib.parse

SAFE_ENV_BASENAMES: frozenset[str] = frozenset(
    {
        ".env.example",
        ".env.sample",
        ".env.template",
        ".env.dist",
        ".env.schema",
    }
)
SAFE_ENV_SUFFIXES: tuple[str, ...] = (
    ".example",
    ".sample",
    ".template",
    ".dist",
    ".schema",
)

PRIVATE_KEY_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?:\s+BLOCK)?-----[\s\S]*?"
    r"-----END [A-Z0-9 ]*PRIVATE KEY(?:\s+BLOCK)?-----"
)
PRIVATE_KEY_HEADER_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?:\s+BLOCK)?-----"
)
GOOGLE_API_KEY_RE = re.compile(r"AIza[0-9A-Za-z_-]{20,}")
GITHUB_TOKEN_RE = re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")
GITHUB_PAT_RE = re.compile(r"github_pat_[A-Za-z0-9_]{20,}")
SECRET_KEY_PREFIX_RE = re.compile(r"(?<![A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}")
AWS_ACCESS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
DEVIN_API_KEY_RE = re.compile(r"(?<![A-Za-z0-9_])cog_[A-Za-z0-9_-]{20,}")
BEARER_TOKEN_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}")

SECRET_DETECT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("秘密鍵ヘッダ (PRIVATE KEY)", PRIVATE_KEY_HEADER_RE),
    ("Google API キー (AIza...)", GOOGLE_API_KEY_RE),
    ("GitHub トークン (gh*_...)", GITHUB_TOKEN_RE),
    ("GitHub Fine-grained PAT (github_pat_...)", GITHUB_PAT_RE),
    ("API シークレットキー (sk-...)", SECRET_KEY_PREFIX_RE),
    ("AWS アクセスキー (AKIA...)", AWS_ACCESS_KEY_RE),
    ("Devin API キー (cog_...)", DEVIN_API_KEY_RE),
)

# 複数行ブロックを単独ヘッダより先に置換し、中間行や閉じ行の残留を防ぐ
SECRET_REDACT_PATTERNS: tuple[re.Pattern[str], ...] = (
    PRIVATE_KEY_BLOCK_RE,
    PRIVATE_KEY_HEADER_RE,
    GOOGLE_API_KEY_RE,
    GITHUB_TOKEN_RE,
    GITHUB_PAT_RE,
    SECRET_KEY_PREFIX_RE,
    AWS_ACCESS_KEY_RE,
    DEVIN_API_KEY_RE,
)


def configure_utf8_stdio() -> None:
    """Windows の cp932 環境でも標準入出力が UnicodeEncodeError にならないよう UTF-8 へ再構成する。"""
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        reconf = getattr(stream, "reconfigure", None)
        if callable(reconf):
            try:
                reconf(encoding="utf-8")
            except (AttributeError, OSError, ValueError):
                pass


def is_blocked_env_path(path: Path | str) -> bool:
    """実値の秘密情報を含む可能性が高い .env 系ファイルパスかを判定する（雛形サフィックスは許容）。"""
    name = str(path).replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name in SAFE_ENV_BASENAMES:
        return False
    if name == ".env":
        return True
    if name.startswith(".env."):
        return not name.endswith(SAFE_ENV_SUFFIXES)
    return False


def scan_text_for_secrets(
    text: str,
    *,
    patterns: tuple[tuple[str, re.Pattern[str]], ...] = SECRET_DETECT_PATTERNS,
) -> list[str]:
    """テキスト内に含まれる秘密情報パターンのラベル一覧を返す（実値は返さない）。"""
    return [label for label, pattern in patterns if pattern.search(text)]


def mask_secrets(
    text: str,
    *,
    secrets: tuple[str | None, ...] = (),
    extra_patterns: tuple[re.Pattern[str], ...] = (),
) -> str:
    """実値（URL エンコード形式を含む）および秘密情報パターンを [REDACTED] へ置換する。"""
    masked = text
    for secret in secrets:
        if not secret:
            continue
        masked = masked.replace(secret, "[REDACTED]")
        quoted = urllib.parse.quote(secret, safe="")
        if quoted and quoted != secret:
            masked = masked.replace(quoted, "[REDACTED]")
    for pattern in SECRET_REDACT_PATTERNS:
        masked = pattern.sub("[REDACTED]", masked)
    for pattern in extra_patterns:
        masked = pattern.sub("[REDACTED]", masked)
    return masked


def mask_secret(text: str, secret: str | None = None) -> str:
    """単一の任意シークレット実値と共通秘密パターンをマスクする互換ヘルパー。"""
    return mask_secrets(text, secrets=(secret,) if secret else ())
