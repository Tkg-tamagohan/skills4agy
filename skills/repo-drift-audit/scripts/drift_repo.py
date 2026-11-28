#!/usr/bin/env python3
"""repo-drift-audit 向けリポジトリ収集・スナップショット・決定論的ヒント抽出モジュール。

`screen_drift_decision1.py` と `preflight_drift.py` から共有される定数、データ構造、
安全ガード、Git 更新経過日数の一括取得、不在パス・不在フラグヒント抽出を提供する。
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Sequence
from dataclasses import dataclass, field
import os
from pathlib import Path
import posixpath
import re
import stat
import subprocess
import sys
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

_DECISIONS_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "gemini-decisions-api" / "scripts"
if str(_DECISIONS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_DECISIONS_SCRIPTS_DIR))

import argparse_flag_audit  # noqa: E402
import decision_common  # noqa: E402
import decision_hygiene  # noqa: E402
import run_decisions  # noqa: E402

DEFAULT_MODEL = run_decisions.DEFAULT_MODEL
DEFAULT_ENDPOINT = run_decisions.DEFAULT_ENDPOINT
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_WORKERS = 4
DEFAULT_DOCS_MAX_CHARS = 200_000
DEFAULT_BACKLOG_MAX_CHARS = 200_000
DEFAULT_CANDIDATES_MAX_CHARS = 50_000
MAX_QUESTIONS = 1_000

DEFAULT_MIN_CONFIDENCE = 0.80
DEFAULT_DISCUSSION_THRESHOLD = 0.50
DEFAULT_NOUL_CLEAN_CEILING = 0.40
DEFAULT_MECHANIZABLE_THRESHOLD = 0.65
DEFAULT_DOCS_GIT_LOG_LIMIT = 30
DEFAULT_BACKLOG_GIT_LOG_LIMIT = 50
MAX_REPO_FILES_IN_SNAPSHOT = 800

BULK_STALENESS_MAX_PATHS = 200
BULK_STALENESS_MAX_CHARS = 16_000

DEFAULT_DOC_GLOBS: tuple[str, ...] = (
    "README.md",
    "AGENTS.md",
    "GEMINI.md",
    "CLAUDE.md",
    "docs/**/*.md",
    "skills/**/*.md",
    ".agents/skills/**/*.md",
    ".agents/rules/**/*.md",
    ".agent/rules/**/*.md",
    "_agents/rules/**/*.md",
    "_agent/rules/**/*.md",
    "rules/**/*.md",
)
DEFAULT_EXCLUDED_DOC_GLOBS: tuple[str, ...] = ("**/slop-catalog.md",)

DEFAULT_EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        "target",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
    }
)

SAFE_ENV_BASENAMES: frozenset[str] = decision_hygiene.SAFE_ENV_BASENAMES
SAFE_ENV_SUFFIXES: tuple[str, ...] = decision_hygiene.SAFE_ENV_SUFFIXES

PRIVATE_KEY_BLOCK_RE = decision_hygiene.PRIVATE_KEY_BLOCK_RE
PRIVATE_KEY_HEADER_RE = decision_hygiene.PRIVATE_KEY_HEADER_RE

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = decision_hygiene.SECRET_DETECT_PATTERNS

FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})")
MARKDOWN_LINK_RE = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)(?:\s+[\"'][^\"']*[\"'])?\)")
INLINE_CODE_RE = re.compile(r"`([^`\n]+)`")
UNCHECKED_TASK_RE = re.compile(r"^\s*[-*+]\s+\[ \]\s+(.+?)\s*$")
QUESTION_KEY_SAFE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

LINE_SUFFIX_RE = re.compile(r":L?\d+(?:-L?\d+)?$")
WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:(?:[/\\]|$)")
STANDALONE_FILENAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*\.[A-Za-z0-9]+$")
PY_SCRIPT_REF_RE = re.compile(r"([A-Za-z0-9_./\\-]+\.py)(?![A-Za-z0-9_.-])")
HOME_SKILL_SCRIPT_RE = re.compile(
    r"^(?:\$HOME|\$\{HOME\}|~)/.+?/(skills/[A-Za-z0-9_.-]+/scripts/[^/\s]+)$"
)
SHELL_TOKEN_RE = re.compile(r'"([^"]*)"|\'([^\']*)\'|(\S+)')
CMD_SPLIT_RE = re.compile(r"\s*(?:&&|\|\||;)\s*")
POSIX_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
PS_ENV_ASSIGN_RE = re.compile(r"^\$env:[A-Za-z_][A-Za-z0-9_]*=.*$", re.IGNORECASE)

PYTHON_EXECUTABLES: frozenset[str] = frozenset(
    {"python", "python.exe", "python3", "python3.exe", "py", "py.exe"}
)
PYTHON_VALUE_FLAGS: frozenset[str] = frozenset({"-W", "-X", "-Q"})
PYTHON_NON_SCRIPT_FLAGS: frozenset[str] = frozenset({"-c", "-m", "-"})
SHELL_EXECUTABLES: frozenset[str] = frozenset({"bash", "sh", "pwsh", "pwsh.exe"})
SHELL_NON_SCRIPT_FLAGS: frozenset[str] = frozenset({"-c", "-command", "-encodedcommand"})

KNOWN_STANDALONE_EXTS: frozenset[str] = frozenset(
    {
        ".md",
        ".py",
        ".json",
        ".yml",
        ".yaml",
        ".toml",
        ".sh",
        ".ps1",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".rs",
        ".go",
    }
)
DUMMY_STANDALONE_STEMS: frozenset[str] = frozenset(
    {
        "example",
        "sample",
        "foo",
        "bar",
        "baz",
        "qux",
        "test",
        "demo",
        "dummy",
        "placeholder",
        "template",
        "mock",
        "stub",
        "temp",
        "tmp",
    }
)
DUMMY_STANDALONE_NAMES: frozenset[str] = frozenset(
    {
        "candidates.json",
        "items.json",
        "payload.json",
        "tsconfig.json",
        "package.json",
        "pyproject.toml",
        "__init__.py",
        "a.js",
        "b.js",
    }
)

DOCS_RECOMMENDED_ACTIONS: dict[str, str] = {
    "plan_worker_deep_check": (
        "Likely has meaningful drift, broken references, or structural issues needing "
        "a planning worker to inspect and plan fixes."
    ),
    "quick_parent_check": (
        "Possible minor lag, ambiguity, or uncertain discrepancy that the parent agent "
        "should quickly verify."
    ),
    "mechanization_review": (
        "No urgent drift, but contains deterministic procedures that are strong candidates "
        "for scripting."
    ),
    "likely_clean": (
        "Consistent with the current repository snapshot and no follow-up action is evident."
    ),
    "other": "Insufficient context or falls outside the listed categories.",
}

DRIFT_SEVERITY_CRITERIA: list[str] = [
    "0: no meaningful drift",
    "1: minor wording or metadata lag",
    "2: broken reference or outdated procedure",
    "3: contradictory guidance likely to cause errors",
]

BACKLOG_STATUS_CRITERIA: dict[str, str] = {
    "likely_resolved": (
        "Recent commits or current repository files strongly indicate this backlog item "
        "has already been implemented or resolved."
    ),
    "partially_addressed": (
        "Related changes exist in recent commits or files, but part of the item or "
        "verification still appears incomplete."
    ),
    "still_open": (
        "No evidence in the recent commits or file snapshot indicates this backlog item "
        "has been resolved yet."
    ),
    "other": "Insufficient context in the snapshot or falls outside these statuses.",
}

CANDIDATES_IMPACT_CRITERIA: list[str] = [
    "0: cosmetic or nit",
    "1: minor maintenance lag",
    "2: functional workflow drift or broken tooling",
    "3: high-impact contradiction or operational risk",
]

CANDIDATES_DISPATCH_ROUTES: dict[str, str] = {
    "plan_worker_autonomous": (
        "Fits a single track and can likely be planned for autonomous execution without "
        "specification ambiguity."
    ),
    "plan_worker_discussion": (
        "Fits a single track, but requires user confirmation on specification or policy "
        "decisions during planning."
    ),
    "parent_direct": (
        "Operational, external configuration, or tiny direct task better handled by the "
        "parent agent than a worker."
    ),
    "defer_redesign": (
        "Requires cross-cutting redesign exceeding a single PR or track and should be "
        "deferred rather than planned now."
    ),
    "likely_false_positive": (
        "Appears to be a false positive or already aligned based on the given evidence."
    ),
    "other": "Insufficient context or falls outside the listed routing options.",
}

VALID_BACKLOG_CHOICES = frozenset(BACKLOG_STATUS_CRITERIA.keys())
VALID_DISPATCH_ROUTES = frozenset(CANDIDATES_DISPATCH_ROUTES.keys())

LOW_PRIORITY_CLEAN_NOTE = (
    "low_priority_clean はコンパクトなリポジトリスナップショット上の一次判定であり、"
    "ゼロ乖離の保証ではありません。最終確認と行番号の確定は人間またはエージェントが行ってください。"
)


class DriftScreenError(Exception):
    """スクリーニング CLI の入力検証・安全ガードエラー。"""

    def __init__(self, code: str, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code


@dataclass(frozen=True)
class RepoContext:
    """対象リポジトリの収集済みメタデータ。"""

    repo_root: Path
    is_git: bool
    repo_files: list[str]
    repo_files_set: frozenset[str]
    top_level_dirs: frozenset[str]
    git_log: str
    latest_commit_ts: int | None


@dataclass(frozen=True)
class DocEntry:
    """docs モードの検査対象ドキュメント 1 件。"""

    rel_path: str
    content: str
    staleness_days: int | None
    missing_path_hints: list[str]
    missing_flag_hints: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class BacklogItem:
    """backlog モードの未完了課題 1 件。"""

    id: str
    question_key: str
    file: str | None
    line: int | None
    text: str
    section: str | None = None


@dataclass(frozen=True)
class AuditCandidate:
    """candidates モードの第一走査候補 1 件。"""

    id: str
    category: str
    title: str
    evidence: str
    symptom: str
    files: list[str] = field(default_factory=list)
    estimated_scope: str | None = None


def configure_utf8_stdio() -> None:
    """stdin/stdout/stderr が reconfigure を持つ場合 UTF-8 へ再設定する。"""
    decision_hygiene.configure_utf8_stdio()


def mask_secret(text: str, secret: str | None = None) -> str:
    """エラー出力から API キーおよび秘密情報トークン実値をマスクする。"""
    return decision_hygiene.mask_secret(text, secret)


def scan_text_for_secrets(text: str) -> list[str]:
    """テキスト内の秘密鍵ヘッダ・API トークンパターンのラベル一覧を返す。"""
    return decision_hygiene.scan_text_for_secrets(text, patterns=SECRET_PATTERNS)


def is_blocked_env_path(path: Path | str) -> bool:
    """送信禁止の .env 系ファイル（雛形を除く）かどうかを判定する。"""
    return decision_hygiene.is_blocked_env_path(path)


def is_reparse_or_symlink(path: Path) -> bool:
    """シンボリックリンクまたは Windows リパースポイントかどうかを判定する。"""
    if os.path.islink(path):
        return True
    try:
        st = os.lstat(path)
    except OSError:
        return True
    if stat.S_ISLNK(st.st_mode):
        return True
    attrs = getattr(st, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attrs & reparse_flag)


_is_reparse_or_symlink = is_reparse_or_symlink


def assert_safe_file_path(path: Path | str, role: str) -> None:
    """.env 系ファイルが読み取り対象に含まれる場合は終了コード 2 で遮断する。"""
    if is_blocked_env_path(path):
        raise DriftScreenError(
            "secret_env_file",
            f"{role} に機密ファイル候補（{Path(path).name}）が含まれているため送信を遮断しました。",
            exit_code=2,
        )


def assert_text_has_no_secrets(text: str, label: str) -> None:
    """テキスト内に秘密情報パターンがあれば実値を出さず終了コード 2 で遮断する。"""
    matched = scan_text_for_secrets(text)
    if matched:
        joined = ", ".join(matched)
        raise DriftScreenError(
            "secret_detected",
            f"{label} に秘密情報パターン（{joined}）が含まれているため送信を遮断しました。",
            exit_code=2,
        )


_iter_string_fields = decision_hygiene.iter_string_fields
_is_real_number = decision_common.is_real_number
_extract_number = decision_common.extract_number
_glob_to_regex = decision_common.glob_to_regex


def _run_git_command(repo_root: Path, *args: str) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=repo_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            shell=False,
            check=False,
        )
    except OSError:
        return None


def is_git_repo(repo_root: Path) -> bool:
    """対象ディレクトリが Git 作業ツリー内かを安全に判定する。"""
    proc = _run_git_command(repo_root, "rev-parse", "--is-inside-work-tree")
    return proc is not None and proc.returncode == 0 and proc.stdout.strip() == "true"


def _walk_filesystem_files(repo_root: Path) -> list[str]:
    files: list[str] = []
    for root, dirs, filenames in os.walk(repo_root):
        root_path = Path(root)
        dirs[:] = sorted(
            d
            for d in dirs
            if d not in DEFAULT_EXCLUDED_DIRS and not is_reparse_or_symlink(root_path / d)
        )
        for name in sorted(filenames):
            full = root_path / name
            if is_reparse_or_symlink(full):
                continue
            try:
                rel = full.relative_to(repo_root).as_posix()
            except ValueError:
                continue
            files.append(rel)
    return sorted(files)


def collect_repo_files(repo_root: Path, is_git: bool) -> list[str]:
    """対象リポジトリ配下のファイル相対パス一覧（POSIX 形式）を返す。"""
    if is_git:
        proc = _run_git_command(repo_root, "-c", "core.quotePath=false", "ls-files")
        if proc is not None and proc.returncode == 0:
            files = [
                line.strip().replace("\\", "/")
                for line in proc.stdout.splitlines()
                if line.strip()
            ]
            return sorted(set(files))
    return _walk_filesystem_files(repo_root)


def collect_git_log(repo_root: Path, limit: int, is_git: bool) -> str:
    """Git 管理下かつ limit > 0 の場合に直近のコミット要約を返す。"""
    if not is_git or limit <= 0:
        return ""
    proc = _run_git_command(
        repo_root,
        "-c",
        "core.quotePath=false",
        "log",
        f"-n{limit}",
        "--date=short",
        "--stat",
        "--format=commit %h %ad %s",
    )
    if proc is None or proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def _get_latest_commit_ts(repo_root: Path, is_git: bool) -> int | None:
    if not is_git:
        return None
    proc = _run_git_command(repo_root, "log", "-1", "--format=%ct")
    if proc is None or proc.returncode != 0:
        return None
    raw = proc.stdout.strip()
    if raw.isdigit():
        return int(raw)
    return None


def compute_staleness_days(
    repo_root: Path,
    rel_posix: str,
    is_git: bool,
    latest_commit_ts: int | None,
) -> int | None:
    """リポジトリ最新コミット日時と文書最終更新日時の経過日数を返す。"""
    if not is_git or latest_commit_ts is None:
        return None
    proc = _run_git_command(repo_root, "log", "-1", "--format=%ct", "--", rel_posix)
    if proc is None or proc.returncode != 0:
        return None
    raw = proc.stdout.strip()
    if not raw.isdigit():
        return None
    doc_ts = int(raw)
    return max(0, (latest_commit_ts - doc_ts) // 86400)


def _chunk_paths_for_git(
    paths: Sequence[str],
    *,
    max_paths: int = BULK_STALENESS_MAX_PATHS,
    max_chars: int = BULK_STALENESS_MAX_CHARS,
) -> list[list[str]]:
    chunks: list[list[str]] = []
    cur: list[str] = []
    cur_chars = 0
    for p in paths:
        cost = len(p) + 1
        if cur and (len(cur) >= max_paths or cur_chars + cost > max_chars):
            chunks.append(cur)
            cur = []
            cur_chars = 0
        cur.append(p)
        cur_chars += cost
    if cur:
        chunks.append(cur)
    return chunks


def _consume_git_log_z_stream(
    stdout_stream: Any,
    target_set: set[str],
) -> tuple[dict[str, int], bool]:
    """`git log --format=%x1e%ct --name-only -z` の NUL 区切り出力を逐次読み取り、全対象が埋まれば打ち切る。"""
    found_ts: dict[str, int] = {}
    current_ts: int | None = None
    expect_first_file = False
    early_stopped = False
    buf = b""

    def process_token(tok: bytes) -> bool:
        nonlocal current_ts, expect_first_file
        stripped_tok = tok.lstrip(b"\r\n")
        if stripped_tok.startswith(b"\x1e"):
            ts_str = stripped_tok[1:].decode("ascii", errors="ignore").strip()
            current_ts = int(ts_str) if ts_str.isdigit() else None
            expect_first_file = True
            return False
        if expect_first_file and tok.startswith(b"\n"):
            tok = tok[1:]
        expect_first_file = False
        rel = tok.decode("utf-8", errors="replace").replace("\\", "/")
        if rel and current_ts is not None and rel in target_set and rel not in found_ts:
            found_ts[rel] = current_ts
            if len(found_ts) == len(target_set):
                return True
        return False

    while True:
        chunk = stdout_stream.read(8192)
        if not chunk:
            break
        buf += chunk
        while True:
            sep_idx = buf.find(b"\x00")
            if sep_idx < 0:
                break
            token = buf[:sep_idx]
            buf = buf[sep_idx + 1 :]
            if process_token(token):
                early_stopped = True
                break
        if early_stopped:
            break

    if not early_stopped and buf:
        process_token(buf)

    return found_ts, early_stopped


def compute_staleness_days_bulk(
    repo_root: Path,
    rel_paths: Sequence[str],
    is_git: bool,
    latest_commit_ts: int | None,
) -> dict[str, int | None]:
    """複数ファイルの経過日数をチャンク分割 `git log -z` で一括取得し、全件到達時に早期打ち切りする。"""
    result: dict[str, int | None] = {p: None for p in rel_paths}
    if not rel_paths or not is_git or latest_commit_ts is None:
        return result

    norm_to_origs: dict[str, list[str]] = defaultdict(list)
    unique_norms: list[str] = []
    for orig in rel_paths:
        norm = orig.replace("\\", "/")
        if norm.startswith("./"):
            norm = norm[2:]
        if not norm:
            continue
        if norm not in norm_to_origs:
            unique_norms.append(norm)
        norm_to_origs[norm].append(orig)

    for chunk in _chunk_paths_for_git(unique_norms):
        cmd = [
            "git",
            "-c",
            "core.quotePath=false",
            "log",
            "--format=%x1e%ct",
            "--name-only",
            "-z",
            "--",
            *chunk,
        ]
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=repo_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                shell=False,
            )
        except OSError:
            continue

        early_stopped = False
        found_ts: dict[str, int] = {}
        try:
            if proc.stdout is not None:
                found_ts, early_stopped = _consume_git_log_z_stream(proc.stdout, set(chunk))
        finally:
            if proc.stdout is not None:
                try:
                    proc.stdout.close()
                except OSError:
                    pass
            if early_stopped and proc.poll() is None:
                try:
                    proc.terminate()
                except OSError:
                    pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                except OSError:
                    pass
                proc.wait()

        for norm, doc_ts in found_ts.items():
            days = max(0, (latest_commit_ts - doc_ts) // 86400)
            for orig in norm_to_origs.get(norm, []):
                result[orig] = days

    return result


def collect_repo_context(repo_root: Path, git_log_limit: int) -> RepoContext:
    """対象リポジトリのファイル一覧と履歴スナップショットを収集する。"""
    if not repo_root.is_dir():
        raise DriftScreenError(
            "invalid_repo_path",
            f"リポジトリディレクトリが存在しません: {repo_root}",
            exit_code=2,
        )
    resolved_root = repo_root.resolve()
    git_flag = is_git_repo(resolved_root)
    repo_files = collect_repo_files(resolved_root, git_flag)
    top_dirs = frozenset(
        entry.name
        for entry in resolved_root.iterdir()
        if entry.is_dir()
        and entry.name not in DEFAULT_EXCLUDED_DIRS
        and not is_reparse_or_symlink(entry)
    )
    git_log = collect_git_log(resolved_root, git_log_limit, git_flag)
    latest_ts = _get_latest_commit_ts(resolved_root, git_flag)
    return RepoContext(
        repo_root=resolved_root,
        is_git=git_flag,
        repo_files=repo_files,
        repo_files_set=frozenset(repo_files),
        top_level_dirs=top_dirs,
        git_log=git_log,
        latest_commit_ts=latest_ts,
    )


def load_facts_blocks(facts_files: list[str]) -> list[tuple[str, str]]:
    """任意の --facts-file 群を検査し、(表示パス, 本文) の配列として読み込む。"""
    blocks: list[tuple[str, str]] = []
    for raw_path in facts_files:
        path = Path(raw_path)
        assert_safe_file_path(path, "--facts-file")
        if os.path.lexists(path) and is_reparse_or_symlink(path):
            raise DriftScreenError(
                "unsafe_facts_file",
                f"--facts-file にシンボリックリンクまたはリパースポイントは指定できません: {raw_path}",
                exit_code=2,
            )
        if not path.is_file():
            raise DriftScreenError(
                "facts_file_not_found",
                f"--facts-file が見つかりません: {raw_path}",
                exit_code=2,
            )
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise DriftScreenError(
                "facts_file_read_error",
                f"--facts-file を読めません ({raw_path}): {exc}",
                exit_code=2,
            ) from exc
        assert_text_has_no_secrets(text, f"--facts-file ({raw_path})")
        blocks.append((raw_path, text))
    return blocks


def _sample_files_round_robin(
    repo_files: Sequence[str],
    limit: int,
) -> tuple[list[str], list[str]]:
    """トップレベルディレクトリ単位のラウンドロビンで上限件数まで抽出し、省略サマリ行も返す。"""
    groups: dict[str, deque[str]] = defaultdict(deque)
    totals: dict[str, int] = defaultdict(int)
    for rel in repo_files:
        top_dir = rel.split("/", 1)[0] if "/" in rel else "."
        groups[top_dir].append(rel)
        totals[top_dir] += 1

    dir_keys = sorted(groups.keys())
    shown_files: list[str] = []
    shown_counts: dict[str, int] = defaultdict(int)

    while len(shown_files) < limit:
        progressed = False
        for d in dir_keys:
            if groups[d]:
                shown_files.append(groups[d].popleft())
                shown_counts[d] += 1
                progressed = True
                if len(shown_files) >= limit:
                    break
        if not progressed:
            break

    shown_files.sort()
    omitted_summaries: list[str] = []
    for d in dir_keys:
        tot = totals[d]
        shw = shown_counts.get(d, 0)
        omitted = tot - shw
        if omitted > 0:
            omitted_summaries.append(
                f"Omitted Files Summary: {d}/: {omitted} omitted ({shw}/{tot} shown)"
            )
    return shown_files, omitted_summaries


def build_repo_snapshot_text(
    ctx: RepoContext,
    facts_blocks: list[tuple[str, str]],
) -> str:
    """共有入力用のコンパクトなリポジトリスナップショット文字列を構築する。"""
    parts: list[str] = [
        f"Repository Root: {ctx.repo_root.name}",
        f"Git Repository: {'yes' if ctx.is_git else 'no (filesystem fallback)'}",
    ]
    total_files = len(ctx.repo_files)
    file_header = f"Repository Files ({total_files} total"
    omitted_summaries: list[str] = []
    if total_files > MAX_REPO_FILES_IN_SNAPSHOT:
        shown_files, omitted_summaries = _sample_files_round_robin(
            ctx.repo_files,
            MAX_REPO_FILES_IN_SNAPSHOT,
        )
        file_header += f", showing {len(shown_files)} via round-robin sampling"
    else:
        shown_files = list(ctx.repo_files)
    file_header += "):"
    file_body = "\n".join(shown_files) if shown_files else "(none)"
    file_section = f"{file_header}\n{file_body}"
    if omitted_summaries:
        file_section += "\n" + "\n".join(omitted_summaries)
    parts.append(file_section)

    if ctx.git_log:
        parts.append(f"Recent Git Log:\n{ctx.git_log}")
    else:
        parts.append("Recent Git Log:\n(unavailable)")

    for label, content in facts_blocks:
        parts.append(f"Supplemental Facts ({label}):\n{content}")

    return "\n\n".join(parts)


def _strip_fenced_code_blocks(text: str) -> str:
    """フェンスコードブロック内の行を空行へ置換し、誤検出を防ぐ。"""
    out_lines: list[str] = []
    in_fence = False
    fence_char = ""
    fence_len = 0
    for line in text.splitlines():
        m = FENCE_RE.match(line)
        if m:
            marker = m.group(1)
            if not in_fence:
                in_fence = True
                fence_char = marker[0]
                fence_len = len(marker)
                out_lines.append("")
                continue
            if marker[0] == fence_char and len(marker) >= fence_len:
                in_fence = False
                fence_char = ""
                fence_len = 0
                out_lines.append("")
                continue
        out_lines.append("" if in_fence else line)
    return "\n".join(out_lines)


def _is_external_or_anchor(target: str) -> bool:
    lower = target.lower()
    if not target or target.startswith("#") or target.startswith("/"):
        return True
    if WINDOWS_DRIVE_RE.match(target):
        return True
    return lower.startswith(("http://", "https://", "mailto:", "file://", "javascript:", "data:"))


def _normalize_candidate_target(raw_target: str) -> str:
    cleaned = raw_target.split("#", 1)[0].split("?", 1)[0].strip()
    return cleaned


def _strip_line_suffix(candidate: str) -> str:
    """末尾の `:L10` / `:10` / `:10-20` / `:L10-L20` を安全に除去する。"""
    if _is_external_or_anchor(candidate):
        return candidate
    return LINE_SUFFIX_RE.sub("", candidate)


def _has_disallowed_path_chars(candidate: str) -> bool:
    if not candidate or candidate.startswith("/") or "//" in candidate or "..." in candidate:
        return True
    if any(ch.isspace() for ch in candidate):
        return True
    if any(ch in candidate for ch in "*?[]{}<>$~"):
        return True
    return False


def _is_dummy_standalone_filename(name: str) -> bool:
    lower = name.lower()
    if lower in DUMMY_STANDALONE_NAMES:
        return True
    stem = Path(lower).stem
    if stem in DUMMY_STANDALONE_STEMS:
        return True
    return False


def _resolve_repo_candidate(candidate: str, doc_relpath: str, ctx: RepoContext) -> bool:
    """相対パス候補が doc 相対または repo ルート相対で実在するかを返す。"""
    clean = candidate.rstrip("/")
    if not clean or clean in (".", ".."):
        return True

    doc_dir = posixpath.dirname(doc_relpath)
    joined_from_doc = posixpath.normpath(posixpath.join(doc_dir, clean)) if doc_dir else posixpath.normpath(clean)
    norm_from_root = posixpath.normpath(clean)

    candidates_to_check: list[str] = []
    for norm in (joined_from_doc, norm_from_root):
        if norm != ".." and not norm.startswith("../"):
            candidates_to_check.append(norm.lstrip("./") if norm.startswith("./") else norm)

    if not candidates_to_check:
        # リポジトリ外（../ など）を意図的に参照するリンクは欠損ヒント対象外にする
        return True

    for rel in candidates_to_check:
        if rel in ctx.repo_files_set:
            return True
        target_disk = ctx.repo_root / rel
        if os.path.lexists(target_disk) and not is_reparse_or_symlink(target_disk):
            try:
                target_disk.resolve().relative_to(ctx.repo_root)
            except ValueError:
                pass
            else:
                if target_disk.exists():
                    return True
        dir_prefix = rel.rstrip("/") + "/"
        if any(f.startswith(dir_prefix) for f in ctx.repo_files):
            return True
    return False


def _tokenize_command_segment(segment: str) -> list[str]:
    tokens: list[str] = []
    for dq, sq, bare in SHELL_TOKEN_RE.findall(segment):
        tok = dq or sq or bare
        if tok:
            tokens.append(tok)
    return tokens


def _extract_fenced_script_candidates(doc_text: str) -> list[str]:
    """フェンスコードブロック内の python/bash/sh/pwsh 実行行からスクリプトパス候補を抽出する。"""
    candidates: list[str] = []
    in_fence = False
    fence_char = ""
    fence_len = 0

    for line in doc_text.splitlines():
        m = FENCE_RE.match(line)
        if m:
            marker = m.group(1)
            if not in_fence:
                in_fence = True
                fence_char = marker[0]
                fence_len = len(marker)
                continue
            if marker[0] == fence_char and len(marker) >= fence_len:
                in_fence = False
                fence_char = ""
                fence_len = 0
                continue
        if not in_fence:
            continue

        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        for segment in CMD_SPLIT_RE.split(stripped):
            tokens = _tokenize_command_segment(segment)
            idx = 0
            while idx < len(tokens) and (
                POSIX_ENV_ASSIGN_RE.match(tokens[idx]) or PS_ENV_ASSIGN_RE.match(tokens[idx])
            ):
                idx += 1
            if idx >= len(tokens):
                continue

            cmd_base = posixpath.basename(tokens[idx].replace("\\", "/")).lower()
            idx += 1

            script_tok: str | None = None
            if cmd_base in PYTHON_EXECUTABLES:
                while idx < len(tokens):
                    tok = tokens[idx]
                    if tok in PYTHON_NON_SCRIPT_FLAGS:
                        break
                    if tok in PYTHON_VALUE_FLAGS:
                        idx += 2
                        continue
                    if tok.startswith("-"):
                        idx += 1
                        continue
                    script_tok = tok
                    break
            elif cmd_base in SHELL_EXECUTABLES:
                while idx < len(tokens):
                    tok = tokens[idx]
                    if tok.lower() in SHELL_NON_SCRIPT_FLAGS:
                        break
                    if tok.startswith("-"):
                        idx += 1
                        continue
                    script_tok = tok
                    break

            if not script_tok:
                continue

            norm_tok = _strip_line_suffix(script_tok.strip().replace("\\", "/"))
            home_match = HOME_SKILL_SCRIPT_RE.match(norm_tok)
            if home_match:
                cand = home_match.group(1)
                if not _has_disallowed_path_chars(cand) and ":" not in cand:
                    candidates.append(cand)
                continue

            if _is_external_or_anchor(norm_tok) or norm_tok.startswith(("$", "~")):
                continue
            if _has_disallowed_path_chars(norm_tok) or ":" in norm_tok:
                continue
            if "/" not in norm_tok:
                if Path(norm_tok).suffix.lower() not in {".py", ".sh", ".ps1"}:
                    continue
                if _is_dummy_standalone_filename(norm_tok):
                    continue
            candidates.append(norm_tok)

    return candidates


def extract_missing_path_hints(doc_text: str, doc_relpath: str, ctx: RepoContext) -> list[str]:
    """文書内の相対リンク・インラインコード・フェンス内スクリプト行から不在パス候補を抽出する。"""
    scanned = _strip_fenced_code_blocks(doc_text)
    repo_basenames = {posixpath.basename(f) for f in ctx.repo_files}
    missing: set[str] = set()

    for match in MARKDOWN_LINK_RE.finditer(scanned):
        raw_target = _normalize_candidate_target(match.group(1))
        if _is_external_or_anchor(raw_target):
            continue
        target = _strip_line_suffix(raw_target)
        if _is_external_or_anchor(target) or _has_disallowed_path_chars(target) or ":" in target:
            continue
        if not _resolve_repo_candidate(target, doc_relpath, ctx):
            missing.add(target)

    for match in INLINE_CODE_RE.finditer(scanned):
        raw = match.group(1).strip()
        if _is_external_or_anchor(raw):
            continue
        cleaned = _strip_line_suffix(raw)
        if _is_external_or_anchor(cleaned) or _has_disallowed_path_chars(cleaned):
            continue
        if ":" in cleaned:
            continue

        if "/" in cleaned:
            first_seg = cleaned.split("/", 1)[0]
            is_explicit_rel = cleaned.startswith(("./", "../"))
            if not is_explicit_rel and first_seg not in ctx.top_level_dirs:
                continue
            if not _resolve_repo_candidate(cleaned, doc_relpath, ctx):
                missing.add(cleaned)
        elif "\\" not in cleaned:
            if not STANDALONE_FILENAME_RE.match(cleaned):
                continue
            if Path(cleaned).suffix.lower() not in KNOWN_STANDALONE_EXTS:
                continue
            if _is_dummy_standalone_filename(cleaned):
                continue
            if cleaned in repo_basenames:
                continue
            if not _resolve_repo_candidate(cleaned, doc_relpath, ctx):
                missing.add(cleaned)

    for cand in _extract_fenced_script_candidates(doc_text):
        if "/" not in cand and cand in repo_basenames:
            continue
        if not _resolve_repo_candidate(cand, doc_relpath, ctx):
            missing.add(cand)

    return sorted(missing)


def _resolve_referenced_py_scripts(
    doc_text: str,
    doc_relpath: str,
    ctx: RepoContext,
) -> list[Path]:
    """文書内で参照されたリポジトリ内の実在 .py スクリプト Path 一覧を返す。"""
    doc_dir = posixpath.dirname(doc_relpath)
    py_files = [f for f in ctx.repo_files if f.lower().endswith(".py")]
    by_basename: dict[str, list[str]] = defaultdict(list)
    for pf in py_files:
        by_basename[posixpath.basename(pf)].append(pf)

    resolved_rels: set[str] = set()
    for match in PY_SCRIPT_REF_RE.finditer(doc_text):
        raw_ref = match.group(1).replace("\\", "/")
        while raw_ref.startswith("./"):
            raw_ref = raw_ref[2:]
        if not raw_ref:
            continue

        matched_rel: str | None = None
        if doc_dir:
            doc_cand = posixpath.normpath(posixpath.join(doc_dir, raw_ref))
            if doc_cand in ctx.repo_files_set:
                matched_rel = doc_cand
        if matched_rel is None:
            root_cand = posixpath.normpath(raw_ref)
            if root_cand in ctx.repo_files_set:
                matched_rel = root_cand
        if matched_rel is not None:
            resolved_rels.add(matched_rel)
            continue

        if "/" not in raw_ref:
            cands = by_basename.get(raw_ref, [])
            if doc_dir:
                subtree = [c for c in cands if c.startswith(doc_dir + "/")]
                if subtree:
                    resolved_rels.update(subtree)
                    continue
            resolved_rels.update(cands)

    script_paths: list[Path] = []
    for rel in sorted(resolved_rels):
        sp = ctx.repo_root / rel
        if os.path.lexists(sp) and not is_reparse_or_symlink(sp) and sp.is_file():
            try:
                sp.resolve().relative_to(ctx.repo_root)
            except ValueError:
                continue
            script_paths.append(sp)
    return script_paths


def extract_missing_flag_hints(
    doc_text: str,
    doc_relpath: str,
    ctx: RepoContext,
) -> list[str]:
    """文書内で参照された実在 .py スクリプトに対し、文書のみに記載された --flag を返す。"""
    script_paths = _resolve_referenced_py_scripts(doc_text, doc_relpath, ctx)
    if not script_paths:
        return []
    return argparse_flag_audit.find_doc_only_flags_in_text(doc_text, script_paths)


def select_doc_files(ctx: RepoContext, path_patterns: list[str] | None) -> list[str]:
    """対象グロブまたはパス群に一致するリポジトリ内ファイル一覧を昇順で返す。"""
    is_default = not path_patterns
    patterns = path_patterns if path_patterns else list(DEFAULT_DOC_GLOBS)
    compiled = [_glob_to_regex(pat) for pat in patterns]
    excluded = [_glob_to_regex(pat) for pat in DEFAULT_EXCLUDED_DOC_GLOBS] if is_default else []
    selected: list[str] = []
    seen: set[str] = set()

    for rel in ctx.repo_files:
        if any(rx.match(rel) for rx in compiled):
            if any(rx.match(rel) for rx in excluded):
                continue
            if rel not in seen:
                seen.add(rel)
                selected.append(rel)

    # Git 管理下で未追跡ファイルを明示パス指定した場合にも実在ファイルなら拾えるようにする
    if path_patterns:
        for raw_pat in patterns:
            norm = raw_pat.strip().replace("\\", "/")
            if norm.startswith("./"):
                norm = norm[2:]
            if any(c in norm for c in "*?[]"):
                continue
            candidate_path = ctx.repo_root / norm
            if (
                norm
                and norm not in seen
                and os.path.lexists(candidate_path)
                and not is_reparse_or_symlink(candidate_path)
                and candidate_path.is_file()
            ):
                try:
                    candidate_path.resolve().relative_to(ctx.repo_root)
                except ValueError:
                    continue
                seen.add(norm)
                selected.append(norm)

    return sorted(selected)


def load_doc_entries(ctx: RepoContext, rel_paths: list[str]) -> list[DocEntry]:
    """対象文書を読み込み、機密検査と一括陳腐化日数・不在ヒント算出を行う。"""
    loaded_contents: list[tuple[str, str]] = []
    for rel in rel_paths:
        full_path = ctx.repo_root / rel
        assert_safe_file_path(full_path, "検査対象ファイル")
        if os.path.lexists(full_path) and is_reparse_or_symlink(full_path):
            raise DriftScreenError(
                "unsafe_doc_file",
                f"検査対象ファイルにシンボリックリンクまたはリパースポイントは指定できません: {rel}",
                exit_code=2,
            )
        if not full_path.is_file():
            raise DriftScreenError(
                "doc_file_not_found",
                f"検査対象ファイルが見つかりません: {rel}",
                exit_code=2,
            )
        try:
            full_path.resolve().relative_to(ctx.repo_root)
        except ValueError as exc:
            raise DriftScreenError(
                "unsafe_doc_file",
                f"検査対象ファイルがリポジトリ外を指しています: {rel}",
                exit_code=2,
            ) from exc
        try:
            content = full_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise DriftScreenError(
                "doc_read_error",
                f"検査対象ファイルを UTF-8 として読めません ({rel}): {exc}",
                exit_code=2,
            ) from exc
        assert_text_has_no_secrets(content, f"対象ファイル ({rel})")
        loaded_contents.append((rel, content))

    staleness_map = compute_staleness_days_bulk(
        ctx.repo_root,
        [rel for rel, _ in loaded_contents],
        ctx.is_git,
        ctx.latest_commit_ts,
    )

    entries: list[DocEntry] = []
    for rel, content in loaded_contents:
        staleness = staleness_map.get(rel)
        missing_hints = extract_missing_path_hints(content, rel, ctx)
        missing_flags = extract_missing_flag_hints(content, rel, ctx)
        entries.append(
            DocEntry(
                rel_path=rel,
                content=content,
                staleness_days=staleness,
                missing_path_hints=missing_hints,
                missing_flag_hints=missing_flags,
            )
        )
    return entries
