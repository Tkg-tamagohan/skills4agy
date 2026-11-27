#!/usr/bin/env python3
"""
audit_skills_weekly.py - shared-skills 週次 SKILL 監査の決定論的計測 CLI

CI（check_plugin.py / check_hygiene.py / run_all_tests.py）では検知しにくい
実利用実績、コンテキスト収支、機械化・統合・廃止候補、トリガー競合と委譲整合、
文書⇔スクリプト乖離、共有結合・テスト資産・PreToolUse フック状態、
開発/本番同期、および CI 死角の文書衛生をオフライン・読み取り専用で計測する。

標準ライブラリのみを使用し、ファイル書き込み引数を持たず標準出力のみに出力する。
"""

from __future__ import annotations

import argparse
import ast
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import glob
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Iterable, Optional, Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from check_plugin import (  # noqa: E402
    AGENTS_MD_PATH,
    AGENTS_SECTION_LINE_LIMIT,
    HOOKS_JSON_PATH,
    IGNORED_RULE_STEMS,
    RULE_LINE_LIMIT,
    SKILL_DESCRIPTION_TOTAL_LIMIT,
    SKILL_LINE_LIMIT,
    parse_frontmatter,
)

DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PROD_ROOT = Path.home() / ".gemini" / "config" / "plugins" / "shared-skills"
DEFAULT_APP_DATA_DIR = Path.home() / ".gemini" / "antigravity"

DESCRIPTION_SOFT_LIMIT = 220
SKILL_BODY_SOFT_LIMIT = 180
RULE_COUNT_REVIEW_THRESHOLD = 12
PRETOOL_FALLBACK_MARKER = "Decision 1 guard unavailable; fallback to standard confirmation."

BUILTIN_SKILL_NAMES: frozenset[str] = frozenset(
    {
        "a11y-debugging",
        "agy-customizations",
        "android-cli",
        "android-device-hub",
        "antigravity-guide",
        "automation",
        "chrome-devtools",
        "chrome-extensions",
        "compose-preview",
        "conversations",
        "cookie-debugging",
        "debug-optimize-lcp",
        "gemini-api-cli",
        "gemini-api-dev",
        "gemini-live-api-dev",
        "gemini-omni-flash-api",
        "generative_ui",
        "google-antigravity-sdk",
        "mcp-app-development",
        "memory-leak-debugging",
        "migrate-agent-settings",
        "migrate-workflows",
        "modern-web-guidance",
        "plugin",
        "retrieving-developer-knowledge",
        "run-workflow",
        "swarm_monitor",
        "swarm_pane",
        "troubleshooting",
        "ui-plugin-navigation",
    }
)

KNOWN_TOOL_OR_MODEL_NAMES: frozenset[str] = frozenset(
    {
        "ask_question",
        "edit_file",
        "gemini-decision-1",
        "invoke_subagent",
        "manage_subagents",
        "read_file",
        "run_command",
        "run_workflow",
        "send_message",
        "write_file",
    }
)

REF_CONTEXT_HINTS: tuple[str, ...] = (
    "委ねる",
    "委ね",
    "従う",
    "参照",
    "準拠",
    "スキル",
    "ルール",
    "併用",
    "に任せる",
)

STOPWORDS_ASCII: frozenset[str] = frozenset(
    {
        "api",
        "cli",
        "md",
        "py",
        "json",
        "yaml",
        "skill",
        "rule",
        "skills",
        "rules",
        "true",
        "false",
    }
)

SKILL_PATH_RE = re.compile(
    r"(?:^|/)skills/([a-z0-9-]+)/([^\"'\s`<>|;&]+)", re.IGNORECASE
)
RULE_PATH_RE = re.compile(
    r"(?:^|/)rules/([a-z0-9-]+)\.md(?:$|[\"'`\s])", re.IGNORECASE
)
CMD_SCRIPT_RE = re.compile(
    r"([^\s\"'`=;|><()]*?skills/([a-z0-9-]+)/scripts/([a-z0-9_]+\.py))",
    re.IGNORECASE,
)
BACKTICK_IDENT_RE = re.compile(r"`([a-z][a-z0-9_-]{2,})`")
LONG_FLAG_RE = re.compile(r"(?<![A-Za-z0-9_-])(--[a-z][a-z0-9-]{1,})")
VERSION_STAMP_RE = re.compile(r"\b(20\d{2}-\d{2})(?:\s*版)?\b")
NUMBERED_STEP_RE = re.compile(r"^\s*\d+\.\s+\S+")
FENCE_RE = re.compile(r"^\s*(?:```|~~~)")
JAPANESE_CHUNK_RE = re.compile(r"[\u3040-\u309f\u30a0-\u30ff\u4e00-\u9fff]{2,}")
ASCII_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9_-]{1,}")
BACKTICK_PATH_RE = re.compile(r"`([^`\n]+)`")


class AuditError(Exception):
    """CLI 引数または入力構造のエラーを表す。"""


@dataclass
class SkillInventory:
    name: str
    desc_chars: int
    body_lines: int
    description: str
    boundary_text: str
    non_test_scripts: list[Path] = field(default_factory=list)
    test_files: list[Path] = field(default_factory=list)
    test_count: int = 0
    numbered_steps: int = 0
    code_blocks: int = 0
    version_stamps: list[str] = field(default_factory=list)
    staleness_days: Optional[int] = None
    last_commit_iso: Optional[str] = None
    doc_only_flags: list[str] = field(default_factory=list)
    implemented_flags: list[str] = field(default_factory=list)


@dataclass
class RuleInventory:
    name: str
    desc_chars: int
    body_lines: int
    description: str
    body_text: str
    staleness_days: Optional[int] = None
    last_commit_iso: Optional[str] = None


@dataclass
class UsageCounter:
    skill_md_reads_7d: int = 0
    skill_md_reads_28d: int = 0
    aux_reads_7d: int = 0
    aux_reads_28d: int = 0
    script_runs_7d: int = 0
    script_runs_28d: int = 0
    rule_reads_7d: int = 0
    rule_reads_28d: int = 0
    sessions_7d: set[str] = field(default_factory=set)
    sessions_28d: set[str] = field(default_factory=set)
    maintenance_touches_28d: int = 0
    last_used_dt: Optional[datetime] = None

    @property
    def total_usage_7d(self) -> int:
        return (
            self.skill_md_reads_7d
            + self.aux_reads_7d
            + self.script_runs_7d
            + self.rule_reads_7d
        )

    @property
    def total_usage_28d(self) -> int:
        return (
            self.skill_md_reads_28d
            + self.aux_reads_28d
            + self.script_runs_28d
            + self.rule_reads_28d
        )


def configure_utf8_stdio() -> None:
    """標準出力・標準エラーを UTF-8 (errors='replace') に設定する。"""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def parse_iso_datetime(value: str) -> datetime:
    """タイムゾーン付き ISO 8601 文字列を UTC datetime へ変換する。"""
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        raise ValueError(f"タイムゾーン指定が必要です: {value}")
    return dt.astimezone(timezone.utc)


def try_parse_datetime(value: Any) -> Optional[datetime]:
    """ログ中のタイムスタンプ文字列を安全に UTC datetime へ変換する。"""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def decode_tool_arg(value: Any) -> Any:
    """JSON 二重エンコード文字列を安全にデコードする。"""
    if not isinstance(value, str):
        return value
    stripped = value.strip()
    if not stripped:
        return value
    if (stripped[0] == '"' and stripped[-1] == '"') or stripped[0] in ("{", "["):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            return value
    return value


def normalize_posix_lower(raw_path: Any) -> str:
    """比較用にパス文字列を POSIX 小文字表現へ正規化する。"""
    decoded = decode_tool_arg(raw_path)
    text = str(decoded or "").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ('"', "'"):
        text = text[1:-1]
    text = text.replace("\\", "/").lower()
    text = re.sub(r"/+", "/", text)
    if text.startswith("./"):
        text = text[2:]
    return text


def _path_roots(path: Path) -> tuple[str, ...]:
    candidates = [normalize_posix_lower(str(path))]
    try:
        real_str = normalize_posix_lower(os.path.realpath(path))
        if real_str and real_str not in candidates:
            candidates.append(real_str)
    except OSError:
        pass
    return tuple(c.rstrip("/") for c in candidates if c)


def _classify_path_origin(
    norm_path: str,
    *,
    prod_roots: tuple[str, ...],
    repo_roots: tuple[str, ...],
    same_root: bool,
) -> str:
    """パス参照が本番実利用(usage)、開発保守(maintenance)、対象外(other)かを判定する。"""
    if not norm_path:
        return "other"
    for pr in prod_roots:
        if norm_path.startswith(pr + "/") or norm_path == pr:
            return "usage"
    if "/.gemini/config/plugins/shared-skills/" in norm_path or norm_path.startswith(
        "$home/.gemini/config/plugins/shared-skills/"
    ):
        return "usage"
    if not same_root:
        for rr in repo_roots:
            if norm_path.startswith(rr + "/") or norm_path == rr:
                return "maintenance"
        if norm_path.startswith(("skills/", "rules/")):
            return "maintenance"
    elif norm_path.startswith(("skills/", "rules/")):
        return "usage"
    return "other"


def _run_git(
    repo_dir: Path, *args: str, timeout: float = 10.0
) -> Optional[subprocess.CompletedProcess[str]]:
    if not repo_dir.exists():
        return None
    try:
        return subprocess.run(
            ["git", "-C", str(repo_dir), "-c", "core.quotePath=false", *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _git_last_commit_info(
    repo_dir: Path, rel_paths: Sequence[str], now_dt: datetime
) -> tuple[Optional[int], Optional[str]]:
    if not rel_paths:
        return None, None
    proc = _run_git(repo_dir, "log", "-1", "--format=%cI", "--", *rel_paths)
    if proc is None or proc.returncode != 0:
        return None, None
    stamp = proc.stdout.strip()
    if not stamp:
        return None, None
    dt = try_parse_datetime(stamp)
    if dt is None:
        return None, stamp
    days = max(0, int((now_dt - dt).total_seconds() // 86400))
    return days, dt.isoformat()


def _extract_section(text: str, heading_prefix: str) -> str:
    lines = text.splitlines()
    captured: list[str] = []
    in_section = False
    for line in lines:
        if line.startswith(heading_prefix):
            in_section = True
            continue
        if in_section and (line.startswith("## ") or line.startswith("### ")):
            # 同じレベル以上の見出しで打ち切る（## の場合は ## のみ、### の場合は ## / ###）
            if heading_prefix.startswith("### ") or line.startswith("## "):
                break
        if in_section:
            captured.append(line)
    return "\n".join(captured)


def _count_structure_metrics(text: str) -> tuple[int, int]:
    """Markdown 本文の番号付きステップ数とフェンスコードブロック数を返す。"""
    steps = 0
    blocks = 0
    in_fence = False
    for line in text.splitlines():
        if FENCE_RE.match(line):
            if not in_fence:
                blocks += 1
            in_fence = not in_fence
            continue
        if not in_fence and NUMBERED_STEP_RE.match(line):
            steps += 1
    return steps, blocks


def _extract_argparse_flags(py_path: Path) -> set[str]:
    """Python スクリプトの AST から add_argument で定義された --flag を抽出する。"""
    try:
        source = py_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(py_path))
    except (OSError, SyntaxError):
        return set()
    flags: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            attr_name = (
                func.attr
                if isinstance(func, ast.Attribute)
                else (func.id if isinstance(func, ast.Name) else "")
            )
            if attr_name != "add_argument":
                continue
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if arg.value.startswith("--") and len(arg.value) > 2:
                        flags.add(arg.value)
    return flags


def _strip_quoted_arg_values(text: str) -> str:
    """フラグ値（例: --command "git push --force"）内部の誤検出を防ぐためクォート内を除去する。"""
    cleaned = re.sub(r'"[^"\n]*"', '""', text)
    cleaned = re.sub(r"'[^'\n]*'", "''", cleaned)
    return cleaned


def _extract_doc_flags_for_skill(skill_dir: Path, script_names: set[str]) -> set[str]:
    """スキル文書内のスクリプト呼び出し行に紐づく --flag 記載を抽出する。"""
    if not script_names:
        return set()
    flags: set[str] = set()
    for md_path in sorted(skill_dir.rglob("*.md")):
        try:
            lines = md_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        in_fence = False
        block_buf: list[str] = []
        for line in lines:
            if FENCE_RE.match(line):
                if in_fence:
                    block_text = "\n".join(block_buf)
                    if any(sn in block_text for sn in script_names):
                        in_script_cmd = False
                        for b_line in block_buf:
                            stripped = b_line.strip()
                            if not stripped or stripped.startswith("#"):
                                in_script_cmd = False
                                continue
                            if any(sn in b_line for sn in script_names):
                                in_script_cmd = True
                            if in_script_cmd or stripped.startswith("--"):
                                flags.update(LONG_FLAG_RE.findall(_strip_quoted_arg_values(b_line)))
                            if not stripped.endswith(("`", "\\")):
                                in_script_cmd = False
                    block_buf = []
                in_fence = not in_fence
                continue
            if in_fence:
                block_buf.append(line)
            else:
                # 地の文ではスクリプト名を含むインラインコード片のみから抽出する
                for seg in BACKTICK_PATH_RE.findall(line):
                    if any(sn in seg for sn in script_names):
                        flags.update(LONG_FLAG_RE.findall(_strip_quoted_arg_values(seg)))
    return flags


def _count_ast_tests(test_path: Path) -> int:
    """テストファイル内の def test_* メソッド・関数数を AST で数える。"""
    try:
        source = test_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(test_path))
    except (OSError, SyntaxError):
        return 0
    count = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith("test_"):
                count += 1
    return count


def _extract_imports(py_path: Path) -> set[str]:
    """Python スクリプトのトップレベル import モジュール名集合を返す。"""
    try:
        source = py_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(py_path))
    except (OSError, SyntaxError):
        return set()
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mods.add(alias.name.split(".", 1)[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module.split(".", 1)[0])
    return mods


def collect_inventory(
    repo_root: Path, *, now_dt: datetime, use_git: bool
) -> tuple[list[SkillInventory], list[RuleInventory], dict[str, Any]]:
    """リポジトリのスキル、条件ルール、AGENTS.md 構造を収集する。"""
    skills: list[SkillInventory] = []
    skills_dir = repo_root / "skills"
    if skills_dir.is_dir():
        for skill_dir in sorted(p for p in skills_dir.iterdir() if p.is_dir()):
            skill_md = skill_dir / "SKILL.md"
            if not skill_md.is_file():
                continue
            text = skill_md.read_text(encoding="utf-8", errors="replace")
            fm = parse_frontmatter(text) or {}
            desc = str(fm.get("description") or "")
            body_lines = len(text.splitlines())
            boundary_text = _extract_section(text, "## 責任範囲の境界")
            steps, blocks = _count_structure_metrics(text)
            stamps = sorted(set(VERSION_STAMP_RE.findall(text)))

            scripts_dir = skill_dir / "scripts"
            non_tests: list[Path] = []
            tests: list[Path] = []
            if scripts_dir.is_dir():
                for py in sorted(scripts_dir.glob("*.py")):
                    if py.name.startswith("test_"):
                        tests.append(py)
                    else:
                        non_tests.append(py)

            test_count = sum(_count_ast_tests(tp) for tp in tests)
            impl_flags: set[str] = set()
            for sp in non_tests:
                impl_flags.update(_extract_argparse_flags(sp))
            # argparse の既定ヘルプフラグは文書記載を許容する
            allowed_flags = impl_flags | {"--help"}
            doc_flags = _extract_doc_flags_for_skill(
                skill_dir, {sp.name for sp in non_tests}
            )
            doc_only = sorted(f for f in doc_flags if f not in allowed_flags)

            staleness_days: Optional[int] = None
            last_commit_iso: Optional[str] = None
            if use_git:
                staleness_days, last_commit_iso = _git_last_commit_info(
                    repo_root, [f"skills/{skill_dir.name}"], now_dt
                )

            skills.append(
                SkillInventory(
                    name=skill_dir.name,
                    desc_chars=len(desc),
                    body_lines=body_lines,
                    description=desc,
                    boundary_text=boundary_text,
                    non_test_scripts=non_tests,
                    test_files=tests,
                    test_count=test_count,
                    numbered_steps=steps,
                    code_blocks=blocks,
                    version_stamps=stamps,
                    staleness_days=staleness_days,
                    last_commit_iso=last_commit_iso,
                    doc_only_flags=doc_only,
                    implemented_flags=sorted(impl_flags),
                )
            )

    rules: list[RuleInventory] = []
    rules_dir = repo_root / "rules"
    if rules_dir.is_dir():
        for rule_path in sorted(rules_dir.glob("*.md")):
            if rule_path.stem in IGNORED_RULE_STEMS:
                continue
            text = rule_path.read_text(encoding="utf-8", errors="replace")
            fm = parse_frontmatter(text) or {}
            desc = str(fm.get("description") or "")
            staleness_days: Optional[int] = None
            last_commit_iso: Optional[str] = None
            if use_git:
                staleness_days, last_commit_iso = _git_last_commit_info(
                    repo_root, [f"rules/{rule_path.name}"], now_dt
                )
            rules.append(
                RuleInventory(
                    name=rule_path.stem,
                    desc_chars=len(desc),
                    body_lines=len(text.splitlines()),
                    description=desc,
                    body_text=text,
                    staleness_days=staleness_days,
                    last_commit_iso=last_commit_iso,
                )
            )

    agents_info = _inspect_agents_md(repo_root)
    return skills, rules, agents_info


def _inspect_agents_md(repo_root: Path) -> dict[str, Any]:
    path = repo_root / AGENTS_MD_PATH
    if not path.is_file():
        legacy = repo_root / "AGENTS.md"
        if legacy.is_file():
            path = legacy
        else:
            return {"exists": False, "path": None, "chars": 0, "lines": 0, "oversized_sections": []}
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    section: Optional[str] = None
    body_lines = 0
    oversized: list[dict[str, Any]] = []
    for line in lines + ["## END"]:
        if line.startswith("## "):
            if section is not None and body_lines > AGENTS_SECTION_LINE_LIMIT:
                oversized.append({"section": section, "lines": body_lines})
            section = line[3:].strip()
            body_lines = 0
        elif section is not None and line.strip():
            body_lines += 1
    return {
        "exists": True,
        "path": path.relative_to(repo_root).as_posix(),
        "chars": len(text),
        "lines": len(lines),
        "oversized_sections": oversized,
    }


def scan_transcripts(
    *,
    app_data_dir: Path,
    prod_root: Path,
    repo_root: Path,
    now_dt: datetime,
    days: int,
    window_days: int,
) -> dict[str, Any]:
    """ローカルの transcript.jsonl を走査して利用実績とフックフォールバックを集計する。"""
    brain_dir = app_data_dir / "brain"
    prod_roots = _path_roots(prod_root)
    repo_roots = _path_roots(repo_root)
    same_root = set(prod_roots) == set(repo_roots)

    cutoff_short = now_dt - timedelta(days=days)
    cutoff_window = now_dt - timedelta(days=window_days)

    skill_usage: dict[str, UsageCounter] = defaultdict(UsageCounter)
    rule_usage: dict[str, UsageCounter] = defaultdict(UsageCounter)
    total_transcripts = 0
    recent_sessions_7d: set[str] = set()
    recent_sessions_28d: set[str] = set()
    malformed_lines = 0
    hook_fallback_7d = 0
    hook_fallback_28d = 0

    if not brain_dir.is_dir():
        return {
            "brain_dir_exists": False,
            "total_transcripts": 0,
            "active_sessions_7d": 0,
            "active_sessions_28d": 0,
            "malformed_lines": 0,
            "skill_usage": skill_usage,
            "rule_usage": rule_usage,
            "pretool_fallback_7d": 0,
            "pretool_fallback_28d": 0,
        }

    transcripts = sorted(brain_dir.glob("*/.system_generated/logs/transcript.jsonl"))
    for tp in transcripts:
        total_transcripts += 1
        session_id = tp.parents[2].name
        try:
            fallback_dt = datetime.fromtimestamp(tp.stat().st_mtime, tz=timezone.utc)
        except OSError:
            fallback_dt = now_dt

        try:
            fh = tp.open("r", encoding="utf-8", errors="replace")
        except OSError:
            continue

        with fh:
            for raw_line in fh:
                stripped = raw_line.strip()
                if not stripped:
                    continue
                try:
                    obj = json.loads(stripped)
                except json.JSONDecodeError:
                    malformed_lines += 1
                    continue
                if not isinstance(obj, dict):
                    malformed_lines += 1
                    continue

                step_dt = try_parse_datetime(obj.get("created_at")) or fallback_dt
                if step_dt > now_dt:
                    continue
                in_28d = step_dt >= cutoff_window
                in_7d = step_dt >= cutoff_short
                if in_28d:
                    recent_sessions_28d.add(session_id)
                if in_7d:
                    recent_sessions_7d.add(session_id)

                step_type = obj.get("type")
                if step_type in ("GENERIC", "SYSTEM_MESSAGE"):
                    content = obj.get("content")
                    if (
                        isinstance(content, str)
                        and PRETOOL_FALLBACK_MARKER in content
                        and "test_pretool_guard" not in content
                    ):
                        if in_28d:
                            hook_fallback_28d += 1
                        if in_7d:
                            hook_fallback_7d += 1

                if step_type != "PLANNER_RESPONSE":
                    continue

                tcs = obj.get("tool_calls")
                if not isinstance(tcs, list):
                    continue

                for tc in tcs:
                    if not isinstance(tc, dict):
                        continue
                    tool_name = str(tc.get("name") or "")
                    args = tc.get("args")
                    if args is None:
                        args = tc.get("arguments")
                    args = decode_tool_arg(args)
                    if not isinstance(args, dict):
                        continue

                    if tool_name in ("read_file", "view_file"):
                        raw_p = (
                            args.get("Path")
                            or args.get("AbsolutePath")
                            or args.get("path")
                        )
                        norm_p = normalize_posix_lower(raw_p)
                        origin = _classify_path_origin(
                            norm_p,
                            prod_roots=prod_roots,
                            repo_roots=repo_roots,
                            same_root=same_root,
                        )
                        if origin == "other":
                            continue

                        ms = SKILL_PATH_RE.search(norm_p)
                        if ms:
                            sname = ms.group(1)
                            tail = ms.group(2)
                            counter = skill_usage[sname]
                            if origin == "maintenance":
                                if in_28d:
                                    counter.maintenance_touches_28d += 1
                            else:
                                _record_skill_read(
                                    counter,
                                    tail=tail,
                                    session_id=session_id,
                                    step_dt=step_dt,
                                    in_7d=in_7d,
                                    in_28d=in_28d,
                                )
                            continue

                        mr = RULE_PATH_RE.search(norm_p)
                        if mr:
                            rname = mr.group(1)
                            if rname.upper() in IGNORED_RULE_STEMS:
                                continue
                            counter = rule_usage[rname]
                            if origin == "maintenance":
                                if in_28d:
                                    counter.maintenance_touches_28d += 1
                            else:
                                _record_rule_read(
                                    counter,
                                    session_id=session_id,
                                    step_dt=step_dt,
                                    in_7d=in_7d,
                                    in_28d=in_28d,
                                )

                    elif tool_name == "run_command":
                        raw_cmd = args.get("CommandLine") or args.get("command") or ""
                        cmd_str = str(decode_tool_arg(raw_cmd) or "")
                        if not cmd_str:
                            continue
                        norm_cmd = cmd_str.replace("\\", "/").lower()
                        seen_in_call: set[tuple[str, str, str]] = set()
                        for m in CMD_SCRIPT_RE.finditer(norm_cmd):
                            full_tok, sname, script_name = m.group(1), m.group(2), m.group(3)
                            if script_name.startswith("test_"):
                                origin = _classify_path_origin(
                                    full_tok,
                                    prod_roots=prod_roots,
                                    repo_roots=repo_roots,
                                    same_root=same_root,
                                )
                                if origin != "other" and in_28d:
                                    skill_usage[sname].maintenance_touches_28d += 1
                                continue
                            origin = _classify_path_origin(
                                full_tok,
                                prod_roots=prod_roots,
                                repo_roots=repo_roots,
                                same_root=same_root,
                            )
                            if origin == "other":
                                continue
                            key = (origin, sname, script_name)
                            if key in seen_in_call:
                                continue
                            seen_in_call.add(key)
                            counter = skill_usage[sname]
                            if origin == "maintenance":
                                if in_28d:
                                    counter.maintenance_touches_28d += 1
                            else:
                                _record_script_run(
                                    counter,
                                    session_id=session_id,
                                    step_dt=step_dt,
                                    in_7d=in_7d,
                                    in_28d=in_28d,
                                )

    return {
        "brain_dir_exists": True,
        "total_transcripts": total_transcripts,
        "active_sessions_7d": len(recent_sessions_7d),
        "active_sessions_28d": len(recent_sessions_28d),
        "malformed_lines": malformed_lines,
        "skill_usage": skill_usage,
        "rule_usage": rule_usage,
        "pretool_fallback_7d": hook_fallback_7d,
        "pretool_fallback_28d": hook_fallback_28d,
    }


def _record_skill_read(
    counter: UsageCounter,
    *,
    tail: str,
    session_id: str,
    step_dt: datetime,
    in_7d: bool,
    in_28d: bool,
) -> None:
    is_skill_md = tail == "skill.md"
    if in_28d:
        if is_skill_md:
            counter.skill_md_reads_28d += 1
        else:
            counter.aux_reads_28d += 1
        counter.sessions_28d.add(session_id)
    if in_7d:
        if is_skill_md:
            counter.skill_md_reads_7d += 1
        else:
            counter.aux_reads_7d += 1
        counter.sessions_7d.add(session_id)
    if counter.last_used_dt is None or step_dt > counter.last_used_dt:
        counter.last_used_dt = step_dt


def _record_rule_read(
    counter: UsageCounter,
    *,
    session_id: str,
    step_dt: datetime,
    in_7d: bool,
    in_28d: bool,
) -> None:
    if in_28d:
        counter.rule_reads_28d += 1
        counter.sessions_28d.add(session_id)
    if in_7d:
        counter.rule_reads_7d += 1
        counter.sessions_7d.add(session_id)
    if counter.last_used_dt is None or step_dt > counter.last_used_dt:
        counter.last_used_dt = step_dt


def _record_script_run(
    counter: UsageCounter,
    *,
    session_id: str,
    step_dt: datetime,
    in_7d: bool,
    in_28d: bool,
) -> None:
    if in_28d:
        counter.script_runs_28d += 1
        counter.sessions_28d.add(session_id)
    if in_7d:
        counter.script_runs_7d += 1
        counter.sessions_7d.add(session_id)
    if counter.last_used_dt is None or step_dt > counter.last_used_dt:
        counter.last_used_dt = step_dt


def _tokenize_description(text: str) -> set[str]:
    tokens: set[str] = set()
    lower = text.lower()
    for chunk in JAPANESE_CHUNK_RE.findall(lower):
        for i in range(len(chunk) - 1):
            tokens.add(chunk[i : i + 2])
    for tok in ASCII_TOKEN_RE.findall(lower):
        if tok not in STOPWORDS_ASCII:
            tokens.add(tok)
    return tokens


def analyze_boundaries_and_conflicts(
    skills: Sequence[SkillInventory],
    rules: Sequence[RuleInventory],
) -> dict[str, Any]:
    """委譲リンク切れと description 語彙重複ペアを検出する。"""
    known_names = (
        {s.name for s in skills}
        | {r.name for r in rules}
        | BUILTIN_SKILL_NAMES
        | KNOWN_TOOL_OR_MODEL_NAMES
    )
    dangling: list[dict[str, str]] = []

    def scan_text(source_label: str, text: str) -> None:
        if not text:
            return
        for line in text.splitlines():
            if not any(hint in line for hint in REF_CONTEXT_HINTS):
                continue
            for m in BACKTICK_IDENT_RE.finditer(line):
                cand = m.group(1)
                if "-" not in cand and "_" not in cand:
                    continue
                if cand.endswith((".py", ".md", ".json", ".yml", ".yaml", ".txt")):
                    continue
                if cand.startswith(("test_", "pretool_", "check_", "run_")):
                    continue
                # 文脈ヒント語が同一行にある、または近傍にある場合に限り未知スキル名候補として検出
                ctx_slice = line[max(0, m.start() - 20) : min(len(line), m.end() + 25)]
                if any(hint in ctx_slice for hint in REF_CONTEXT_HINTS):
                    if cand not in known_names:
                        dangling.append({"source": source_label, "target": cand})

    for s in skills:
        scan_text(f"skill:{s.name}:description", s.description)
        scan_text(f"skill:{s.name}:boundary", s.boundary_text)
    for r in rules:
        scan_text(f"rule:{r.name}:description", r.description)
        scan_text(f"rule:{r.name}:body", r.body_text)

    # 重複削除
    seen_dangling: set[tuple[str, str]] = set()
    unique_dangling: list[dict[str, str]] = []
    for item in dangling:
        key = (item["source"], item["target"])
        if key not in seen_dangling:
            seen_dangling.add(key)
            unique_dangling.append(item)

    # description 語彙 Jaccard 類似度（スキル同士＋ルール同士＋クロス）
    entries: list[tuple[str, set[str]]] = []
    for s in skills:
        entries.append((f"skill:{s.name}", _tokenize_description(s.description)))
    for r in rules:
        entries.append((f"rule:{r.name}", _tokenize_description(r.description)))

    overlaps: list[dict[str, Any]] = []
    for i in range(len(entries)):
        name_a, tok_a = entries[i]
        if not tok_a:
            continue
        for j in range(i + 1, len(entries)):
            name_b, tok_b = entries[j]
            if not tok_b:
                continue
            union = tok_a | tok_b
            if not union:
                continue
            jaccard = len(tok_a & tok_b) / len(union)
            if jaccard >= 0.12:
                overlaps.append(
                    {
                        "pair": [name_a, name_b],
                        "jaccard": round(jaccard, 3),
                    }
                )
    overlaps.sort(key=lambda x: (-x["jaccard"], x["pair"][0], x["pair"][1]))
    return {
        "dangling_references": unique_dangling,
        "top_description_overlaps": overlaps[:8],
    }


def analyze_coupling_and_hooks(
    repo_root: Path,
    skills: Sequence[SkillInventory],
    *,
    pretool_fallback_7d: int,
    pretool_fallback_28d: int,
) -> dict[str, Any]:
    """スキル間の非テストスクリプト import 結合と hooks.json 設定を解析する。"""
    module_owners: dict[str, list[str]] = defaultdict(list)
    for s in skills:
        for sp in s.non_test_scripts:
            module_owners[sp.stem].append(s.name)

    cross_edges: list[dict[str, str]] = []
    for s in skills:
        for sp in s.non_test_scripts:
            imported = _extract_imports(sp)
            for mod in sorted(imported):
                owners = [o for o in module_owners.get(mod, []) if o != s.name]
                for target_skill in owners:
                    cross_edges.append(
                        {
                            "from_skill": s.name,
                            "from_script": sp.name,
                            "to_skill": target_skill,
                            "module": mod,
                        }
                    )

    hooks_path = repo_root / HOOKS_JSON_PATH
    hooks_summary: list[dict[str, Any]] = []
    hooks_error: Optional[str] = None
    if hooks_path.is_file():
        try:
            raw = json.loads(hooks_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                for hook_name, hook_cfg in sorted(raw.items()):
                    if not isinstance(hook_cfg, dict):
                        continue
                    enabled = bool(hook_cfg.get("enabled", True))
                    timeouts: list[int] = []
                    commands: list[str] = []
                    for ev in ("PreToolUse", "PostToolUse"):
                        groups = hook_cfg.get(ev)
                        if isinstance(groups, list):
                            for grp in groups:
                                if not isinstance(grp, dict):
                                    continue
                                for h in grp.get("hooks") or []:
                                    if isinstance(h, dict):
                                        if isinstance(h.get("command"), str):
                                            commands.append(h["command"])
                                        t = h.get("timeout")
                                        if isinstance(t, int) and not isinstance(t, bool):
                                            timeouts.append(t)
                    hooks_summary.append(
                        {
                            "name": hook_name,
                            "enabled": enabled,
                            "timeouts": timeouts,
                            "commands": commands,
                        }
                    )
        except (OSError, json.JSONDecodeError) as exc:
            hooks_error = str(exc)

    return {
        "cross_skill_imports": cross_edges,
        "hooks_exists": hooks_path.is_file(),
        "hooks": hooks_summary,
        "hooks_error": hooks_error,
        "pretool_fallback_7d": pretool_fallback_7d,
        "pretool_fallback_28d": pretool_fallback_28d,
    }


def check_doc_hygiene_blind_spots(repo_root: Path) -> dict[str, Any]:
    """REVIEW.md 除外対象パスと .sloplintignore の存在切れを検査する。"""
    missing_review_exclusions: list[str] = []
    review_path = repo_root / "REVIEW.md"
    if review_path.is_file():
        text = review_path.read_text(encoding="utf-8", errors="replace")
        sec = _extract_section(text, "### 除外対象")
        for m in BACKTICK_PATH_RE.finditer(sec):
            pat = m.group(1).strip()
            if "/" not in pat:
                continue
            if any(ch in pat for ch in "*?[]"):
                matches = [
                    Path(p)
                    for p in glob.glob(str(repo_root / pat), recursive=True)
                ]
                if not matches:
                    missing_review_exclusions.append(pat)
            else:
                if not (repo_root / pat).exists():
                    missing_review_exclusions.append(pat)

    missing_slop_ignores: list[str] = []
    slopignore_path = repo_root / ".sloplintignore"
    if slopignore_path.is_file():
        for raw_line in slopignore_path.read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            pat = line.lstrip("/")
            if any(ch in pat for ch in "*?[]"):
                matches = glob.glob(str(repo_root / pat), recursive=True)
                if not matches:
                    missing_slop_ignores.append(line)
            else:
                if not (repo_root / pat).exists():
                    missing_slop_ignores.append(line)

    return {
        "missing_review_exclusions": missing_review_exclusions,
        "missing_slop_ignores": missing_slop_ignores,
    }


def _inspect_git_clone(clone_dir: Path, *, include_merged: bool) -> dict[str, Any]:
    if not clone_dir.exists():
        return {"exists": False, "path": str(clone_dir)}
    head_proc = _run_git(clone_dir, "rev-parse", "--short", "HEAD")
    if head_proc is None or head_proc.returncode != 0:
        return {"exists": True, "is_git": False, "path": str(clone_dir)}
    branch_proc = _run_git(clone_dir, "rev-parse", "--abbrev-ref", "HEAD")
    status_proc = _run_git(clone_dir, "status", "--porcelain")
    dirty_lines = [
        ln for ln in (status_proc.stdout.splitlines() if status_proc else []) if ln.strip()
    ]

    ahead_main: Optional[int] = None
    behind_main: Optional[int] = None
    ab_proc = _run_git(clone_dir, "rev-list", "--left-right", "--count", "origin/main...HEAD")
    if ab_proc is not None and ab_proc.returncode == 0:
        parts = ab_proc.stdout.strip().split()
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            behind_main = int(parts[0])
            ahead_main = int(parts[1])

    merged_branches: list[str] = []
    if include_merged:
        mb_proc = _run_git(clone_dir, "branch", "--merged", "origin/main")
        if mb_proc is not None and mb_proc.returncode == 0:
            for raw in mb_proc.stdout.splitlines():
                name = raw.lstrip("* ").strip()
                if not name or name == "main" or name.startswith("("):
                    continue
                merged_branches.append(name)

    return {
        "exists": True,
        "is_git": True,
        "path": str(clone_dir),
        "head_sha": head_proc.stdout.strip(),
        "branch": branch_proc.stdout.strip() if branch_proc else None,
        "dirty_count": len(dirty_lines),
        "behind_origin_main": behind_main,
        "ahead_origin_main": ahead_main,
        "merged_local_branches": merged_branches,
    }


def check_git_sync(
    repo_root: Path, prod_root: Path, *, use_git: bool
) -> dict[str, Any]:
    if not use_git:
        return {"skipped": True}
    repo_info = _inspect_git_clone(repo_root, include_merged=True)
    prod_info = _inspect_git_clone(prod_root, include_merged=False)
    in_sync: Optional[bool] = None
    if (
        repo_info.get("is_git")
        and prod_info.get("is_git")
        and repo_info.get("head_sha")
        and prod_info.get("head_sha")
    ):
        in_sync = repo_info["head_sha"] == prod_info["head_sha"]
    return {
        "skipped": False,
        "repo": repo_info,
        "prod": prod_info,
        "head_in_sync": in_sync,
    }


def run_context_audit_summary(
    repo_root: Path,
    app_data_dir: Path,
    *,
    now_dt: datetime,
    days: int,
) -> dict[str, Any]:
    """既存の session-context-audit CLI をオフラインで呼び出し、週次 KPI を抽出する。"""
    script_path = (
        repo_root
        / "skills"
        / "session-context-audit"
        / "scripts"
        / "audit_context_metrics.py"
    )
    if not script_path.is_file():
        return {"status": "missing_script"}
    cutoff_iso = (now_dt - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cmd = [
        sys.executable,
        "-B",
        str(script_path),
        "--app-data-dir",
        str(app_data_dir),
        "--cutoff",
        cutoff_iso,
        "--scope",
        "parent",
        "--no-full-lookup",
        "--format",
        "json",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60.0,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"status": "error", "error": str(exc)}

    if proc.returncode != 0:
        return {
            "status": "error",
            "returncode": proc.returncode,
            "error": (proc.stderr or proc.stdout)[:200],
        }
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return {"status": "error", "error": f"JSON parse error: {exc}"}

    comp = data.get("comparison", {})
    before_obj = comp.get("before", {})
    after_obj = comp.get("after", {})
    before_m = before_obj.get("metrics", {})
    after_m = after_obj.get("metrics", {})
    before_agg = before_obj.get("aggregates", {})
    after_agg = after_obj.get("aggregates", {})
    delta = comp.get("delta_pct", {})

    def pick_p50_or_rate(metrics: dict[str, Any], key: str) -> Any:
        val = metrics.get(key)
        if isinstance(val, dict):
            return val.get("p50")
        return val

    def pick_delta(key: str) -> Any:
        val = delta.get(key)
        if isinstance(val, dict):
            return val.get("p50") if "p50" in val else val.get("rate")
        return val

    tracked_keys = (
        "peak_context_tokens",
        "blind_large_code_read_rate",
        "turns_to_first_edit",
        "edit_error_rate",
        "redundant_reread_rate",
    )
    kpis: dict[str, Any] = {}
    b_wchr = before_agg.get("weighted_cache_hit_rate")
    a_wchr = after_agg.get("weighted_cache_hit_rate")
    d_wchr = (
        round(((a_wchr - b_wchr) / b_wchr) * 100.0, 2)
        if isinstance(b_wchr, (int, float))
        and not isinstance(b_wchr, bool)
        and isinstance(a_wchr, (int, float))
        and not isinstance(a_wchr, bool)
        and b_wchr != 0
        else None
    )
    kpis["weighted_cache_hit_rate"] = {
        "before": b_wchr,
        "after": a_wchr,
        "delta_pct": d_wchr,
    }
    for k in tracked_keys:
        kpis[k] = {
            "before": pick_p50_or_rate(before_m, k),
            "after": pick_p50_or_rate(after_m, k),
            "delta_pct": pick_delta(k),
        }

    return {
        "status": "ok",
        "cutoff": cutoff_iso,
        "before_sessions": before_obj.get("n", 0),
        "after_sessions": after_obj.get("n", 0),
        "kpis": kpis,
    }


def _assign_skill_tags(skill: SkillInventory, usage: UsageCounter) -> list[str]:
    tags: list[str] = []
    if usage.total_usage_28d == 0 and (
        skill.desc_chars >= 180
        or (skill.staleness_days is not None and skill.staleness_days >= 14)
    ):
        tags.append("prune_or_merge_candidate")
    if skill.desc_chars > DESCRIPTION_SOFT_LIMIT:
        tags.append("trim_description_candidate")
    if skill.body_lines >= SKILL_BODY_SOFT_LIMIT:
        tags.append("split_body_candidate")
    if (
        not skill.non_test_scripts
        and (skill.body_lines >= 100 or skill.numbered_steps >= 6)
        and (usage.total_usage_28d > 0 or skill.code_blocks >= 3)
    ):
        tags.append("mechanization_candidate")
    if skill.doc_only_flags:
        tags.append("flag_drift_candidate")
    return tags


def _assign_rule_tags(rule: RuleInventory, usage: UsageCounter) -> list[str]:
    tags: list[str] = []
    if usage.total_usage_28d == 0 and (
        rule.desc_chars >= 80
        or (rule.staleness_days is not None and rule.staleness_days >= 14)
    ):
        tags.append("prune_or_merge_candidate")
    if rule.body_lines >= (RULE_LINE_LIMIT - 5):
        tags.append("near_rule_line_limit")
    return tags


def build_weekly_report(
    *,
    repo_root: Path,
    prod_root: Path,
    app_data_dir: Path,
    now_dt: datetime,
    days: int,
    window_days: int,
    use_git: bool,
    include_context_audit: bool,
) -> dict[str, Any]:
    """全 6 主眼の週次監査レポートデータ構造を組み立てる。"""
    skills, rules, agents_info = collect_inventory(
        repo_root, now_dt=now_dt, use_git=use_git
    )
    tx_data = scan_transcripts(
        app_data_dir=app_data_dir,
        prod_root=prod_root,
        repo_root=repo_root,
        now_dt=now_dt,
        days=days,
        window_days=window_days,
    )
    skill_usage_map: dict[str, UsageCounter] = tx_data["skill_usage"]
    rule_usage_map: dict[str, UsageCounter] = tx_data["rule_usage"]

    skill_rows: list[dict[str, Any]] = []
    total_skill_desc_chars = 0
    for s in skills:
        total_skill_desc_chars += s.desc_chars
        u = skill_usage_map.get(s.name, UsageCounter())
        tags = _assign_skill_tags(s, u)
        skill_rows.append(
            {
                "name": s.name,
                "usage_7d": u.total_usage_7d,
                "usage_28d": u.total_usage_28d,
                "skill_md_reads_7d": u.skill_md_reads_7d,
                "skill_md_reads_28d": u.skill_md_reads_28d,
                "aux_reads_7d": u.aux_reads_7d,
                "aux_reads_28d": u.aux_reads_28d,
                "script_runs_7d": u.script_runs_7d,
                "script_runs_28d": u.script_runs_28d,
                "sessions_7d": len(u.sessions_7d),
                "sessions_28d": len(u.sessions_28d),
                "maintenance_touches_28d": u.maintenance_touches_28d,
                "last_used_at": u.last_used_dt.isoformat() if u.last_used_dt else None,
                "desc_chars": s.desc_chars,
                "body_lines": s.body_lines,
                "has_scripts": bool(s.non_test_scripts),
                "script_count": len(s.non_test_scripts),
                "test_file_count": len(s.test_files),
                "test_case_count": s.test_count,
                "numbered_steps": s.numbered_steps,
                "code_blocks": s.code_blocks,
                "version_stamps": s.version_stamps,
                "staleness_days": s.staleness_days,
                "doc_only_flags": s.doc_only_flags,
                "tags": tags,
            }
        )

    rule_rows: list[dict[str, Any]] = []
    total_rule_desc_chars = 0
    for r in rules:
        total_rule_desc_chars += r.desc_chars
        u = rule_usage_map.get(r.name, UsageCounter())
        tags = _assign_rule_tags(r, u)
        rule_rows.append(
            {
                "name": r.name,
                "usage_7d": u.rule_reads_7d,
                "usage_28d": u.rule_reads_28d,
                "sessions_7d": len(u.sessions_7d),
                "sessions_28d": len(u.sessions_28d),
                "maintenance_touches_28d": u.maintenance_touches_28d,
                "last_used_at": u.last_used_dt.isoformat() if u.last_used_dt else None,
                "desc_chars": r.desc_chars,
                "body_lines": r.body_lines,
                "staleness_days": r.staleness_days,
                "tags": tags,
            }
        )

    skill_rows.sort(key=lambda r: (-r["usage_28d"], -r["desc_chars"], r["name"]))
    rule_rows.sort(key=lambda r: (-r["usage_28d"], -r["desc_chars"], r["name"]))

    boundaries = analyze_boundaries_and_conflicts(skills, rules)
    coupling_hooks = analyze_coupling_and_hooks(
        repo_root,
        skills,
        pretool_fallback_7d=tx_data["pretool_fallback_7d"],
        pretool_fallback_28d=tx_data["pretool_fallback_28d"],
    )
    hygiene_blind_spots = check_doc_hygiene_blind_spots(repo_root)
    git_sync = check_git_sync(repo_root, prod_root, use_git=use_git)
    context_audit = (
        run_context_audit_summary(
            repo_root, app_data_dir, now_dt=now_dt, days=days
        )
        if include_context_audit
        else {"status": "skipped"}
    )

    budget = {
        "skill_count": len(skills),
        "skill_desc_total_chars": total_skill_desc_chars,
        "skill_desc_limit": SKILL_DESCRIPTION_TOTAL_LIMIT,
        "skill_desc_remaining": SKILL_DESCRIPTION_TOTAL_LIMIT - total_skill_desc_chars,
        "skill_desc_utilization_pct": round(
            (total_skill_desc_chars / SKILL_DESCRIPTION_TOTAL_LIMIT) * 100, 1
        ),
        "over_soft_desc_limit": [
            {"name": r["name"], "desc_chars": r["desc_chars"]}
            for r in skill_rows
            if r["desc_chars"] > DESCRIPTION_SOFT_LIMIT
        ],
        "near_skill_line_limit": [
            {"name": r["name"], "body_lines": r["body_lines"]}
            for r in skill_rows
            if r["body_lines"] >= SKILL_BODY_SOFT_LIMIT
        ],
        "rule_count": len(rules),
        "rule_count_threshold": RULE_COUNT_REVIEW_THRESHOLD,
        "rule_review_triggered": len(rules) >= RULE_COUNT_REVIEW_THRESHOLD,
        "rule_desc_total_chars": total_rule_desc_chars,
        "agents_md": agents_info,
        "always_loaded_total_chars": (
            total_skill_desc_chars + total_rule_desc_chars + agents_info.get("chars", 0)
        ),
    }

    inventory_candidates = {
        "zero_usage_28d_skills": [
            r["name"] for r in skill_rows if r["usage_28d"] == 0
        ],
        "zero_usage_28d_rules": [
            r["name"] for r in rule_rows if r["usage_28d"] == 0
        ],
        "prune_or_merge_candidates": [
            r["name"]
            for r in skill_rows
            if "prune_or_merge_candidate" in r["tags"]
        ],
        "mechanization_candidates": [
            r["name"]
            for r in skill_rows
            if "mechanization_candidate" in r["tags"]
        ],
        "trim_description_candidates": [
            r["name"]
            for r in skill_rows
            if "trim_description_candidate" in r["tags"]
        ],
        "split_body_candidates": [
            r["name"]
            for r in skill_rows
            if "split_body_candidate" in r["tags"]
        ],
    }

    return {
        "meta": {
            "generated_at": now_dt.isoformat(),
            "days": days,
            "window_days": window_days,
            "repo_root": str(repo_root),
            "prod_root": str(prod_root),
            "brain_dir_exists": tx_data["brain_dir_exists"],
            "total_transcripts": tx_data["total_transcripts"],
            "active_sessions_7d": tx_data["active_sessions_7d"],
            "active_sessions_28d": tx_data["active_sessions_28d"],
            "malformed_lines": tx_data["malformed_lines"],
        },
        "budget": budget,
        "skills": skill_rows,
        "rules": rule_rows,
        "inventory_candidates": inventory_candidates,
        "boundaries": boundaries,
        "coupling_and_hooks": coupling_hooks,
        "hygiene_blind_spots": hygiene_blind_spots,
        "git_sync": git_sync,
        "context_audit": context_audit,
    }


def _fmt_val(val: Any, *, is_pct: bool = False) -> str:
    if val is None:
        return "-"
    if isinstance(val, float):
        if is_pct:
            return f"{val * 100:.1f}%"
        return f"{val:.2f}"
    return str(val)


def render_markdown(report: dict[str, Any]) -> str:
    """週次監査レポートを Markdown で整形する。"""
    meta = report["meta"]
    budget = report["budget"]
    cand = report["inventory_candidates"]
    bounds = report["boundaries"]
    ch = report["coupling_and_hooks"]
    blind = report["hygiene_blind_spots"]
    gs = report["git_sync"]
    ca = report["context_audit"]

    lines: list[str] = [
        "# 週次 SKILL 監査定量レポート",
        "",
        f"- **計測時刻 (UTC)**: `{meta['generated_at']}`",
        f"- **計測窓**: 直近 `{meta['days']}` 日 / `{meta['window_days']}` 日",
        f"- **ログ走査**: `{meta['total_transcripts']}` トランスクリプト（直近窓アクティブ `{meta['active_sessions_28d']}` セッション、7日 `{meta['active_sessions_7d']}` セッション）",
        "",
        "## 1. 常時コンテキスト予算と規模サマリ",
        "",
        f"- **スキル数 / description 合計**: `{budget['skill_count']}` 件 / `{budget['skill_desc_total_chars']}` / `{budget['skill_desc_limit']}` 文字（使用率 `{budget['skill_desc_utilization_pct']}%`、残 `{budget['skill_desc_remaining']}` 文字）",
        f"- **条件ルール数 / description 合計**: `{budget['rule_count']}` 件（見直し閾値 `{budget['rule_count_threshold']}` 件、超過={budget['rule_review_triggered']}） / `{budget['rule_desc_total_chars']}` 文字",
        f"- **常時読込 (`rules/AGENTS.md`)**: `{budget['agents_md'].get('chars', 0)}` 文字 / `{budget['agents_md'].get('lines', 0)}` 行",
        f"- **常時注入文字数総計**: `{budget['always_loaded_total_chars']}` 文字",
        "",
    ]

    if ca.get("status") == "ok":
        lines.extend(
            [
                f"### セッション指標比較 (`audit_context_metrics.py`, cutoff `{ca['cutoff']}`)",
                "",
                f"比較母数: before `{ca['before_sessions']}` 件 / after `{ca['after_sessions']}` 件",
                "",
                "| 指標 | before | after | delta(%) |",
                "| --- | ---: | ---: | ---: |",
            ]
        )
        for k, vals in ca["kpis"].items():
            is_pct = "rate" in k
            lines.append(
                f"| `{k}` | {_fmt_val(vals['before'], is_pct=is_pct)} | {_fmt_val(vals['after'], is_pct=is_pct)} | {_fmt_val(vals['delta_pct'])} |"
            )
        lines.append("")

    lines.extend(
        [
            "## 2. スキル利用率・コスト・棚卸し一覧",
            "",
            "| スキル | 7d利用 | 28d利用 | SKILL/Aux/Run(28d) | セッション(28d) | 保守(28d) | desc文字 | 本文行 | スクリプト/テスト | タグ |",
            "| --- | ---: | ---: | --- | ---: | ---: | ---: | ---: | --- | --- |",
        ]
    )
    for r in report["skills"]:
        triple = f"{r['skill_md_reads_28d']}/{r['aux_reads_28d']}/{r['script_runs_28d']}"
        st_info = f"{r['script_count']}/{r['test_case_count']}件"
        tags = ", ".join(f"`{t}`" for t in r["tags"]) if r["tags"] else "-"
        lines.append(
            f"| `{r['name']}` | {r['usage_7d']} | {r['usage_28d']} | {triple} | {r['sessions_28d']} | {r['maintenance_touches_28d']} | {r['desc_chars']} | {r['body_lines']} | {st_info} | {tags} |"
        )
    lines.append("")

    lines.extend(
        [
            "## 3. 条件ルール利用率・棚卸し一覧",
            "",
            "| ルール | 7d読込 | 28d読込 | セッション(28d) | 保守(28d) | desc文字 | 本文行 | タグ |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    for r in report["rules"]:
        tags = ", ".join(f"`{t}`" for t in r["tags"]) if r["tags"] else "-"
        lines.append(
            f"| `{r['name']}` | {r['usage_7d']} | {r['usage_28d']} | {r['sessions_28d']} | {r['maintenance_touches_28d']} | {r['desc_chars']} | {r['body_lines']} | {tags} |"
        )
    lines.append("")

    lines.extend(
        [
            "## 4. 機械化・統合・廃止の一次候補",
            "",
            f"- **28日実利用ゼロのスキル ({len(cand['zero_usage_28d_skills'])}件)**: "
            + (", ".join(f"`{n}`" for n in cand["zero_usage_28d_skills"]) or "なし"),
            f"- **28日実利用ゼロのルール ({len(cand['zero_usage_28d_rules'])}件)**: "
            + (", ".join(f"`{n}`" for n in cand["zero_usage_28d_rules"]) or "なし"),
            f"- **統廃合・見直し候補 (`prune_or_merge_candidate`)**: "
            + (", ".join(f"`{n}`" for n in cand["prune_or_merge_candidates"]) or "なし"),
            f"- **機械化候補 (`mechanization_candidate`)**: "
            + (", ".join(f"`{n}`" for n in cand["mechanization_candidates"]) or "なし"),
            f"- **description 圧縮候補 (>220文字)**: "
            + (", ".join(f"`{n}`" for n in cand["trim_description_candidates"]) or "なし"),
            f"- **本文分割候補 (>=180行)**: "
            + (", ".join(f"`{n}`" for n in cand["split_body_candidates"]) or "なし"),
            "",
            "## 5. トリガー競合・ドリフト・結合・同期・衛生チェック",
            "",
            f"- **委譲・参照リンク切れ**: {len(bounds['dangling_references'])} 件"
            + (
                " — "
                + ", ".join(
                    f"{d['source']} -> `{d['target']}`"
                    for d in bounds["dangling_references"]
                )
                if bounds["dangling_references"]
                else ""
            ),
            "- **description 類似上位ペア (Jaccard >= 0.12)**: "
            + (
                ", ".join(
                    f"`{p['pair'][0]}` × `{p['pair'][1]}` ({p['jaccard']})"
                    for p in bounds["top_description_overlaps"][:5]
                )
                or "なし"
            ),
            "- **CLI --flag 文書ドリフト候補**: "
            + (
                ", ".join(
                    f"`{r['name']}`: {' '.join(r['doc_only_flags'])}"
                    for r in report["skills"]
                    if r["doc_only_flags"]
                )
                or "なし"
            ),
            f"- **横断スクリプト import 結合**: {len(ch['cross_skill_imports'])} 件",
            f"- **`PreToolUse` フックフォールバック発生**: 7d `{ch['pretool_fallback_7d']}` 件 / 28d `{ch['pretool_fallback_28d']}` 件",
            f"- **REVIEW.md / .sloplintignore 実在切れ**: REVIEW={len(blind['missing_review_exclusions'])} 件, sloplintignore={len(blind['missing_slop_ignores'])} 件",
        ]
    )

    if not gs.get("skipped"):
        repo_g = gs.get("repo", {})
        prod_g = gs.get("prod", {})
        lines.extend(
            [
                f"- **Git 同期状態**: `HEAD` 一致={gs.get('head_in_sync')} "
                f"(repo=`{repo_g.get('branch')}@{repo_g.get('head_sha')}` dirty={repo_g.get('dirty_count')}, "
                f"prod=`{prod_g.get('branch')}@{prod_g.get('head_sha')}` dirty={prod_g.get('dirty_count')})",
                f"- **マージ済み残存ローカルブランチ**: "
                + (
                    ", ".join(f"`{b}`" for b in repo_g.get("merged_local_branches") or [])
                    or "なし"
                ),
            ]
        )

    return "\n".join(lines) + "\n"


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="shared-skills 週次 SKILL 監査の決定論的計測 CLI（読み取り専用）"
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=DEFAULT_REPO_ROOT,
        help="PR 作業用リポジトリルート（既定: スクリプト位置から自動解決）",
    )
    parser.add_argument(
        "--prod-root",
        type=Path,
        default=DEFAULT_PROD_ROOT,
        help="本番稼働プラグインディレクトリ（既定: ~/.gemini/config/plugins/shared-skills）",
    )
    parser.add_argument(
        "--app-data-dir",
        type=Path,
        default=DEFAULT_APP_DATA_DIR,
        help="Antigravity App Data ディレクトリ（既定: ~/.gemini/antigravity）",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="短期集計窓の日数（既定: 7）",
    )
    parser.add_argument(
        "--window-days",
        type=int,
        default=28,
        help="中期集計窓の日数（既定: 28、--days 以上）",
    )
    parser.add_argument(
        "--now",
        type=str,
        default=None,
        help="基準時刻（タイムゾーン付き ISO 8601、既定: 現在 UTC）",
    )
    parser.add_argument(
        "--include-context-audit",
        action="store_true",
        help="session-context-audit の週次前後比較 KPI を統合する",
    )
    parser.add_argument(
        "--no-git",
        action="store_true",
        help="Git 同期・更新経過日数の計測をスキップする",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="出力形式（既定: markdown）",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    configure_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.days < 1:
        print("エラー: --days は 1 以上を指定してください", file=sys.stderr)
        return 2
    if args.window_days < args.days:
        print("エラー: --window-days は --days 以上を指定してください", file=sys.stderr)
        return 2

    if args.now:
        try:
            now_dt = parse_iso_datetime(args.now)
        except ValueError as exc:
            print(f"エラー: --now の形式が不正です ({exc})", file=sys.stderr)
            return 2
    else:
        now_dt = datetime.now(timezone.utc)

    repo_root = args.repo.resolve()
    if not repo_root.is_dir():
        print(f"エラー: --repo ディレクトリが見つかりません: {repo_root}", file=sys.stderr)
        return 2
    prod_root = args.prod_root.expanduser()
    app_data_dir = args.app_data_dir.expanduser()

    report = build_weekly_report(
        repo_root=repo_root,
        prod_root=prod_root,
        app_data_dir=app_data_dir,
        now_dt=now_dt,
        days=args.days,
        window_days=args.window_days,
        use_git=not args.no_git,
        include_context_audit=args.include_context_audit,
    )

    if args.format == "json":
        print(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False))
    else:
        print(render_markdown(report), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
