#!/usr/bin/env python3
"""Gemini Decision 1 を用いたプロジェクト非依存の不変条件検査 CLI。

任意のリポジトリの git diff とルール文書（AGENTS.md / GEMINI.md / CLAUDE.md /
.agents/rules/*.md / .agent/rules/*.md / _agents/rules/*.md / _agent/rules/*.md /
プラグインの rules/*.md / --rules / .agents/invariants.json）を
1 回の Decisions API 呼び出しで突合し、違反候補と警告を抽出する。
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Callable

_DECISIONS_SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "gemini-decisions-api" / "scripts"
if str(_DECISIONS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_DECISIONS_SCRIPTS_DIR))

import decision_common  # noqa: E402
import decision_hygiene  # noqa: E402
import run_decisions  # noqa: E402

DEFAULT_MODEL = run_decisions.DEFAULT_MODEL
DEFAULT_ENDPOINT = run_decisions.DEFAULT_ENDPOINT
DEFAULT_THRESHOLD = 0.70
DEFAULT_WARN_THRESHOLD = 0.40
DEFAULT_MAX_CHARS = 400_000
MAX_QUESTIONS = 1_000
DEFAULT_TIMEOUT = 30.0
DEFAULT_UNIFIED_LINES = 15

DEFAULT_EXCLUDE_LOCKS: tuple[str, ...] = (
    "Cargo.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "uv.lock",
    "poetry.lock",
)

AUTO_RULE_FILES: tuple[str, ...] = (
    "AGENTS.md",
    "GEMINI.md",
    "CLAUDE.md",
)

AUTO_RULE_DIRS: tuple[str, ...] = (
    ".agents/rules",
    ".agent/rules",
    "_agents/rules",
    "_agent/rules",
)

PLUGIN_MANIFEST_FILES: tuple[str, ...] = (
    "plugin.json",
    ".antigravity-plugin/plugin.json",
    ".gemini-plugin/plugin.json",
)

PLUGIN_RULE_FILES: tuple[str, ...] = (
    "rules/AGENTS.md",
    "rules/GEMINI.md",
)

PLUGIN_RULE_DIRS: tuple[str, ...] = (
    "rules",
)

SAFE_ENV_BASENAMES = decision_hygiene.SAFE_ENV_BASENAMES
SAFE_ENV_SUFFIXES = decision_hygiene.SAFE_ENV_SUFFIXES

PRIVATE_KEY_BLOCK_RE = decision_hygiene.PRIVATE_KEY_BLOCK_RE
PRIVATE_KEY_HEADER_RE = decision_hygiene.PRIVATE_KEY_HEADER_RE
GOOGLE_API_KEY_RE = decision_hygiene.GOOGLE_API_KEY_RE
GITHUB_TOKEN_RE = decision_hygiene.GITHUB_TOKEN_RE
GITHUB_PAT_RE = decision_hygiene.GITHUB_PAT_RE
SECRET_KEY_PREFIX_RE = decision_hygiene.SECRET_KEY_PREFIX_RE
AWS_ACCESS_KEY_RE = decision_hygiene.AWS_ACCESS_KEY_RE
DEVIN_API_KEY_RE = decision_hygiene.DEVIN_API_KEY_RE

SECRET_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    decision_hygiene.SECRET_TOKEN_DETECT_PATTERNS
)

PRESET_RULE_RELPATHS: dict[str, Path] = {
    "systems-pre-pr": Path("systems-pre-pr-audit") / "SKILL.md",
}
HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
FENCE_RE = re.compile(r"^(`{3,}|~{3,})")
TOP_BULLET_RE = re.compile(r"^(?:[-*+]|\d+\.)\s+(.*)$")
SLUG_NON_ALNUM_RE = re.compile(r"[^A-Za-z0-9_-]+")
DIFF_GIT_HEADER_RE = re.compile(r"^diff --git a/(.+?) b/(.+)$")


@dataclass
class RuleItem:
    """抽出またはカスタム定義された不変条件ルール 1 件。"""

    key: str
    source_file: str
    start_line: int
    end_line: int
    heading: str
    text: str
    instructions: str
    criteria: dict[str, str] | None = None
    path_globs: list[str] = field(default_factory=list)
    threshold: float | None = None
    warn_threshold: float | None = None
    matched_files: list[str] = field(default_factory=list)


class GateError(Exception):
    """実行エラー（終了コード 2）を表す例外。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


configure_utf8_stdio = decision_hygiene.configure_utf8_stdio


def mask_secret(text: str, secret: str | None = None) -> str:
    """エラー出力から API キーおよび主要トークン・秘密鍵文字列を確実にマスクする。"""
    return decision_hygiene.mask_secret(text, secret)


_normalize_rel_path = decision_common.normalize_posix_rel_path
_glob_to_regex = decision_common.glob_to_regex


def glob_match(path_str: str, pattern: str) -> bool:
    """POSIX パスに対して ** を含む glob 一致判定を行う。"""
    return decision_common.glob_match(path_str, pattern)


def is_lockfile_path(path_str: str) -> bool:
    """既定の除外対象ロックファイルかどうかを返す。"""
    name = _normalize_rel_path(path_str).rsplit("/", 1)[-1]
    return name in DEFAULT_EXCLUDE_LOCKS


def is_sensitive_env_path(path_str: str) -> bool:
    """送信遮断対象となる .env 系ファイルかどうかを判定する。"""
    return decision_hygiene.is_blocked_env_path(path_str.strip())


def check_diff_secrets(changed_files: list[str], diff_text: str) -> list[str]:
    """変更ファイル名と差分内の追加行・文脈行から秘密情報混入を検出する。"""
    findings: list[str] = []
    for path_str in changed_files:
        if is_sensitive_env_path(path_str):
            findings.append(f"秘密情報を含む可能性のある環境変数ファイルが差分に含まれています: {path_str}")

    found_private_key = False
    found_token_labels: list[str] = []

    for line in diff_text.splitlines():
        if line.startswith("+++ ") or line.startswith("--- ") or line.startswith("-"):
            continue
        if line.startswith("+") or line.startswith(" "):
            if not found_private_key and PRIVATE_KEY_HEADER_RE.search(line):
                findings.append("差分の追加行または文脈行に秘密鍵ヘッダ（PRIVATE KEY）が含まれています。")
                found_private_key = True
            for label in decision_hygiene.scan_text_for_secrets(line, patterns=SECRET_TOKEN_PATTERNS):
                if label not in found_token_labels:
                    found_token_labels.append(label)

    if found_token_labels:
        labels_str = "、".join(found_token_labels)
        findings.append(
            f"差分の追加行または文脈行に主要トークン形式（{labels_str}）が含まれています。"
        )

    return findings


def _make_slug(source_file: str) -> str:
    stem = Path(source_file).stem
    slug = SLUG_NON_ALNUM_RE.sub("_", stem).strip("_")
    if not slug:
        slug = "rule"
    return slug


def make_question_key(
    source_file: str,
    start_line: int,
    text: str,
    used_keys: set[str],
) -> str:
    """Decisions API のキー制約 ^[A-Za-z0-9_-]{1,64}$ を満たす一意キーを採番する。"""
    slug = _make_slug(source_file)
    suffix = f"_L{start_line}"
    candidate = f"{slug}{suffix}"
    digest = hashlib.sha1(f"{source_file}:{start_line}:{text}".encode("utf-8")).hexdigest()[:8]

    if len(candidate) > 64:
        hash_suffix = f"_{digest}{suffix}"
        max_slug = max(1, 64 - len(hash_suffix))
        candidate = f"{slug[:max_slug]}{hash_suffix}"

    if candidate not in used_keys:
        used_keys.add(candidate)
        return candidate

    hash_suffix = f"_{digest}{suffix}"
    max_slug = max(1, 64 - len(hash_suffix))
    candidate = f"{slug[:max_slug]}{hash_suffix}"
    if candidate not in used_keys:
        used_keys.add(candidate)
        return candidate

    counter = 2
    while True:
        extra = f"_{counter}"
        base = candidate[: 64 - len(extra)]
        alt = f"{base}{extra}"
        if alt not in used_keys:
            used_keys.add(alt)
            return alt
        counter += 1


def build_rule_instructions(
    source_file: str,
    start_line: int,
    end_line: int,
    heading: str,
    rule_text: str,
) -> tuple[str, dict[str, str]]:
    """否定疑問を避けた完全な肯定文の noul 質問と criteria を組み立てる。"""
    section_label = heading or "(document root)"
    instructions = (
        "Does the Changed files list or Git diff contain a concrete code or configuration "
        "change that violates the following repository rule?\n"
        f"Source: {source_file} (lines {start_line}-{end_line}, section: {section_label})\n"
        f"Rule: {rule_text}\n"
        "Answer Yes only if the diff itself directly violates this rule. "
        "Answer No if the rule applies only to unchanged files, out-of-diff code, "
        "chat responses, commit or PR procedures, or cannot be observed from the diff."
    )
    criteria = {
        "true_description": (
            "The Changed files or Git diff directly contains a concrete code or "
            "configuration change that violates the stated rule."
        ),
        "false_description": (
            "The diff complies with the rule, does not modify relevant paths, "
            "or the rule cannot be evaluated from the diff alone."
        ),
    }
    return instructions, criteria


EXCLUDED_HEADING_NAMES: frozenset[str] = frozenset(
    {
        "対象外",
        "out of scope",
        "non goal",
        "non goals",
        "nongoal",
        "nongoals",
    }
)


def _normalize_heading_token(text: str) -> str:
    norm = text.strip().lower()
    norm = re.sub(r"^\d+(?:[.-]\d+)*[.)]?\s*", "", norm)
    while True:
        updated = re.sub(r"(?:\s*(?:\([^)]*\)|（[^）]*）|[:：]))+\s*$", "", norm).strip()
        if updated == norm:
            break
        norm = updated
    return re.sub(r"[\s\-\u2010-\u2015\u2212]+", " ", norm).strip()


def _is_excluded_heading(title: str) -> bool:
    stripped = _normalize_heading_token(title)
    if not stripped:
        return False
    if stripped in EXCLUDED_HEADING_NAMES:
        return True
    parts = [_normalize_heading_token(p) for p in re.split(r"[/／]", title)]
    parts = [p for p in parts if p]
    return bool(parts) and all(p in EXCLUDED_HEADING_NAMES for p in parts)


def extract_rules_from_markdown(
    content: str,
    source_file: str,
    used_keys: set[str] | None = None,
) -> list[RuleItem]:
    """Markdown から YAML frontmatter、コードブロック、および除外見出し（対象外 / Out of Scope / Non-Goals 等）を除いてルールを抽出する。"""
    if used_keys is None:
        used_keys = set()

    lines = content.splitlines()
    n = len(lines)
    idx = 0

    # YAML frontmatter 除外
    if n > 0 and lines[0].strip() == "---":
        idx = 1
        while idx < n and lines[idx].strip() not in ("---", "..."):
            idx += 1
        if idx < n:
            idx += 1

    rules: list[RuleItem] = []
    in_fence = False
    fence_char = ""
    fence_len = 0
    skip_heading_level: int | None = None
    current_heading = ""
    current_heading_level = 0
    current_heading_line = 0

    section_has_bullets = False
    prose_lines: list[tuple[int, str]] = []
    bullet_start_line: int | None = None
    bullet_end_line: int | None = None
    bullet_parts: list[str] = []

    def flush_bullet() -> None:
        nonlocal bullet_start_line, bullet_end_line, bullet_parts
        if bullet_start_line is not None and bullet_parts:
            text = " ".join(p.strip() for p in bullet_parts if p.strip()).strip()
            if text:
                key = make_question_key(source_file, bullet_start_line, text, used_keys)
                end_ln = bullet_end_line or bullet_start_line
                instructions, criteria = build_rule_instructions(
                    source_file, bullet_start_line, end_ln, current_heading, text
                )
                rules.append(
                    RuleItem(
                        key=key,
                        source_file=source_file,
                        start_line=bullet_start_line,
                        end_line=end_ln,
                        heading=current_heading,
                        text=text,
                        instructions=instructions,
                        criteria=criteria,
                    )
                )
        bullet_start_line = None
        bullet_end_line = None
        bullet_parts = []

    def flush_section_prose() -> None:
        nonlocal prose_lines, section_has_bullets
        if not section_has_bullets and current_heading_level >= 2 and prose_lines:
            text = " ".join(t.strip() for _, t in prose_lines if t.strip()).strip()
            if text:
                start_ln = current_heading_line or prose_lines[0][0]
                end_ln = prose_lines[-1][0]
                key = make_question_key(source_file, start_ln, text, used_keys)
                instructions, criteria = build_rule_instructions(
                    source_file, start_ln, end_ln, current_heading, text
                )
                rules.append(
                    RuleItem(
                        key=key,
                        source_file=source_file,
                        start_line=start_ln,
                        end_line=end_ln,
                        heading=current_heading,
                        text=text,
                        instructions=instructions,
                        criteria=criteria,
                    )
                )
        prose_lines = []
        section_has_bullets = False

    while idx < n:
        line_no = idx + 1
        raw_line = lines[idx]
        stripped = raw_line.strip()

        # フェンス付きコードブロックの開閉
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
            idx += 1
            continue

        if in_fence:
            idx += 1
            continue

        # 見出し判定
        heading_match = HEADING_RE.match(raw_line)
        if heading_match:
            flush_bullet()
            flush_section_prose()
            level = len(heading_match.group(1))
            title = heading_match.group(2).strip()

            if skip_heading_level is not None and level <= skip_heading_level:
                skip_heading_level = None

            if skip_heading_level is None and _is_excluded_heading(title):
                skip_heading_level = level
                current_heading = title
                current_heading_level = level
                current_heading_line = line_no
            elif skip_heading_level is None:
                current_heading = title
                current_heading_level = level
                current_heading_line = line_no

            idx += 1
            continue

        if skip_heading_level is not None:
            idx += 1
            continue

        # トップレベル箇条書き判定（行頭インデントなし）
        bullet_match = TOP_BULLET_RE.match(raw_line)
        if bullet_match:
            flush_bullet()
            section_has_bullets = True
            bullet_start_line = line_no
            bullet_end_line = line_no
            bullet_parts = [bullet_match.group(1).strip()]
            idx += 1
            continue

        # 箇条書きの継続行（インデントあり）
        if bullet_start_line is not None:
            if stripped and (raw_line.startswith(" ") or raw_line.startswith("\t")):
                bullet_end_line = line_no
                bullet_parts.append(stripped)
                idx += 1
                continue
            if not stripped:
                flush_bullet()
                idx += 1
                continue
            flush_bullet()

        # 地の文（テーブル区切りや水平線は除外）
        if stripped and not re.match(r"^[-:| ]+$", stripped):
            prose_lines.append((line_no, stripped))

        idx += 1

    flush_bullet()
    flush_section_prose()
    return rules


def resolve_preset_path(preset_name: str) -> Path:
    """プリセット名に対応する同梱スキルルールファイルのパスを解決する。"""
    rel = PRESET_RULE_RELPATHS.get(preset_name)
    if rel is None:
        raise GateError("unknown_preset", f"未知のプリセットが指定されました: {preset_name}")
    return (Path(__file__).resolve().parents[2] / rel).resolve()


def resolve_extra_rules(
    extra_rules: list[str] | None,
    presets: list[str] | None,
    repo_root: Path | None = None,
) -> list[str]:
    """--rules と --preset を解決し、重複を除いたルールパス文字列一覧を返す。"""
    combined: list[str] = []
    seen_resolved: set[Path] = set()
    seen_raw: set[str] = set()

    def _add(path_str: str) -> None:
        raw = Path(path_str)
        if raw.is_absolute():
            candidate = raw
        elif raw.exists() or repo_root is None:
            candidate = raw
        else:
            candidate = repo_root / raw

        if candidate.exists():
            resolved = candidate.resolve()
            if resolved in seen_resolved:
                return
            seen_resolved.add(resolved)
        elif path_str in seen_raw:
            return
        seen_raw.add(path_str)
        combined.append(path_str)

    for item in extra_rules or []:
        _add(item)
    for preset_name in presets or []:
        _add(str(resolve_preset_path(preset_name)))
    return combined


def is_native_plugin_repo(repo_root: Path) -> bool:
    """対象リポジトリルートにネイティブプラグインのマニフェストまたは rules/AGENTS.md があるか判定する。"""
    return any((repo_root / rel).is_file() for rel in (*PLUGIN_MANIFEST_FILES, "rules/AGENTS.md"))


def discover_rule_files(
    repo_root: Path,
    extra_rules: list[str] | None = None,
) -> list[Path]:
    """対象リポジトリのルール Markdown と --rules 追加ファイルを昇順で収集する。"""
    discovered: list[Path] = []
    seen: set[Path] = set()

    def add_if_file(path: Path) -> None:
        resolved = path.resolve()
        if resolved.is_file() and resolved not in seen:
            seen.add(resolved)
            discovered.append(resolved)

    for rel in AUTO_RULE_FILES:
        add_if_file(repo_root / rel)

    for rel_dir in AUTO_RULE_DIRS:
        dir_path = repo_root / rel_dir
        if dir_path.is_dir():
            for md_file in sorted(dir_path.glob("*.md"), key=lambda p: p.name.lower()):
                add_if_file(md_file)

    if is_native_plugin_repo(repo_root):
        for rel in PLUGIN_RULE_FILES:
            add_if_file(repo_root / rel)

        for rel_dir in PLUGIN_RULE_DIRS:
            dir_path = repo_root / rel_dir
            if dir_path.is_dir():
                for md_file in sorted(dir_path.glob("*.md"), key=lambda p: p.name.lower()):
                    add_if_file(md_file)

    for item in extra_rules or []:
        if is_sensitive_env_path(item):
            raise GateError(
                "secret_env_file",
                f"秘密情報を含む可能性があるため .env 系ファイルを --rules に指定できません: {item}",
            )
        raw_path = Path(item)
        candidate = raw_path if raw_path.is_absolute() else (
            raw_path if raw_path.exists() else repo_root / raw_path
        )
        if not candidate.exists():
            raise GateError("rule_file_not_found", f"指定されたルールファイルが見つかりません: {item}")
        if candidate.is_dir():
            for md_file in sorted(candidate.glob("*.md"), key=lambda p: p.name.lower()):
                add_if_file(md_file)
        else:
            add_if_file(candidate)

    return discovered


def _display_source_path(path: Path, repo_root: Path) -> str:
    try:
        return path.resolve().relative_to(repo_root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def load_custom_questions(
    questions_file: Path,
    repo_root: Path,
) -> dict[str, RuleItem]:
    """任意の .agents/invariants.json または --questions-file を読み込む。"""
    try:
        raw_data = json.loads(questions_file.read_text(encoding="utf-8"))
    except OSError as exc:
        raise GateError("questions_file_read_error", f"カスタム質問ファイルを読めません: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise GateError("questions_file_invalid_json", f"カスタム質問ファイルの JSON が不正です: {exc}") from exc

    if not isinstance(raw_data, dict):
        raise GateError(
            "questions_file_invalid_schema",
            "カスタム質問ファイルは JSON オブジェクトである必要があります。",
        )

    raw_questions = raw_data.get("questions", raw_data)
    if not isinstance(raw_questions, dict):
        raise GateError(
            "questions_file_invalid_schema",
            "questions は質問キーをマップしたオブジェクトである必要があります。",
        )

    display_file = _display_source_path(questions_file, repo_root)
    custom_items: dict[str, RuleItem] = {}

    for key, body in raw_questions.items():
        if not isinstance(key, str) or not run_decisions.QUESTION_KEY_RE.match(key):
            raise GateError(
                "invalid_question_key",
                f"カスタム質問キー {key!r} は ^[A-Za-z0-9_-]{{1,64}}$ を満たす必要があります。",
            )
        if not isinstance(body, dict):
            raise GateError(
                "invalid_question_body",
                f"カスタム質問 {key!r} はオブジェクトで指定してください。",
            )
        instructions = body.get("instructions")
        if not isinstance(instructions, str) or not instructions.strip():
            raise GateError(
                "invalid_question_instructions",
                f"カスタム質問 {key!r} に非空の instructions が必要です。",
            )

        path_globs_raw = body.get("path_globs") or []
        if not isinstance(path_globs_raw, list) or not all(isinstance(g, str) for g in path_globs_raw):
            raise GateError(
                "invalid_path_globs",
                f"カスタム質問 {key!r} の path_globs は文字列配列で指定してください。",
            )

        threshold = body.get("threshold")
        warn_threshold = body.get("warn_threshold")
        if threshold is not None and not isinstance(threshold, (int, float)):
            raise GateError("invalid_threshold", f"カスタム質問 {key!r} の threshold は数値にしてください。")
        if warn_threshold is not None and not isinstance(warn_threshold, (int, float)):
            raise GateError("invalid_warn_threshold", f"カスタム質問 {key!r} の warn_threshold は数値にしてください。")

        criteria = body.get("criteria")
        if criteria is not None and not isinstance(criteria, dict):
            raise GateError("invalid_criteria", f"カスタム質問 {key!r} の criteria はオブジェクトにしてください。")

        custom_items[key] = RuleItem(
            key=key,
            source_file=str(body.get("source_file") or display_file),
            start_line=int(body.get("start_line") or 1),
            end_line=int(body.get("end_line") or 1),
            heading=str(body.get("heading") or "custom"),
            text=str(body.get("description") or instructions.strip()),
            instructions=instructions.strip(),
            criteria=criteria,
            path_globs=list(path_globs_raw),
            threshold=float(threshold) if threshold is not None else None,
            warn_threshold=float(warn_threshold) if warn_threshold is not None else None,
        )

    return custom_items


def collect_rules(
    repo_root: Path,
    changed_files: list[str],
    extra_rules: list[str] | None = None,
    questions_file: str | None = None,
) -> list[RuleItem]:
    """第 1〜3 層のルールを統合し、path_globs で絞り込んだ一覧を返す。"""
    used_keys: set[str] = set()
    rules_by_key: dict[str, RuleItem] = {}

    for rule_path in discover_rule_files(repo_root, extra_rules=extra_rules):
        try:
            content = rule_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise GateError("rule_read_error", f"ルールファイルを読めません ({rule_path}): {exc}") from exc
        rel_display = _display_source_path(rule_path, repo_root)
        for item in extract_rules_from_markdown(content, rel_display, used_keys=used_keys):
            rules_by_key[item.key] = item

    custom_path: Path | None = None
    if questions_file:
        if is_sensitive_env_path(questions_file):
            raise GateError(
                "secret_env_file",
                f"秘密情報を含む可能性があるため .env 系ファイルを --questions-file に指定できません: {questions_file}",
            )
        raw_q = Path(questions_file)
        custom_path = raw_q if raw_q.is_absolute() else (
            raw_q if raw_q.exists() else repo_root / raw_q
        )
        if not custom_path.is_file():
            raise GateError("questions_file_not_found", f"カスタム質問ファイルが見つかりません: {questions_file}")
    else:
        default_custom = repo_root / ".agents" / "invariants.json"
        if default_custom.is_file():
            custom_path = default_custom

    if custom_path is not None:
        custom_items = load_custom_questions(custom_path, repo_root)
        for key, item in custom_items.items():
            rules_by_key[key] = item

    active_rules: list[RuleItem] = []
    for item in rules_by_key.values():
        if item.path_globs:
            matched = [
                f for f in changed_files if any(glob_match(f, pat) for pat in item.path_globs)
            ]
            if not matched:
                continue
            item.matched_files = matched
        else:
            item.matched_files = list(changed_files)
        active_rules.append(item)

    return active_rules


def resolve_repo_root(repo_root: str | None) -> Path:
    """対象リポジトリのルートディレクトリを解決する。"""
    if repo_root:
        return Path(repo_root).resolve()
    proc = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode == 0 and proc.stdout.strip():
        return Path(proc.stdout.strip()).resolve()
    return Path.cwd().resolve()


def has_head_commit(repo_root: Path) -> bool:
    """HEAD コミットが存在するかを判定する（初期コミット前を判別）。"""
    proc = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "--verify", "HEAD"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    return proc.returncode == 0


def build_git_diff_command(
    repo_root: Path,
    base: str | None = None,
    staged: bool = False,
    paths: list[str] | None = None,
    has_head: bool = True,
) -> list[str]:
    """UTF-8 取得とロックファイル除外を含む git diff コマンドを組み立てる。"""
    cmd = [
        "git",
        "-C",
        str(repo_root),
        "-c",
        "core.quotePath=false",
        "diff",
        "--no-ext-diff",
        f"--unified={DEFAULT_UNIFIED_LINES}",
    ]
    if base:
        cmd.append(f"{base}...HEAD")
    elif staged or not has_head:
        cmd.append("--cached")
    else:
        cmd.append("HEAD")

    cmd.append("--")
    if paths:
        cmd.extend(paths)
    else:
        cmd.append(".")

    for lock_name in DEFAULT_EXCLUDE_LOCKS:
        cmd.append(f":(exclude,glob)**/{lock_name}")

    return cmd


def parse_diff_sections(
    diff_text: str,
    paths: list[str] | None = None,
) -> tuple[list[str], str]:
    """unified diff からバイナリ差分とロックファイルを除き、変更ファイル一覧と整形差分を返す。"""
    if not diff_text or not diff_text.strip():
        return [], ""

    lines = diff_text.splitlines(keepends=True)
    sections: list[list[str]] = []
    current: list[str] = []

    for line in lines:
        if line.startswith("diff --git "):
            if current:
                sections.append(current)
            current = [line]
        else:
            current.append(line)
    if current:
        sections.append(current)

    changed_files: list[str] = []
    kept_sections: list[str] = []

    for sec in sections:
        sec_text = "".join(sec)
        header = sec[0].rstrip("\r\n") if sec else ""
        file_path = ""

        if header.startswith("diff --git "):
            m = DIFF_GIT_HEADER_RE.match(header)
            if m:
                file_path = _normalize_rel_path(m.group(2))
            for line in sec[1:10]:
                if line.startswith("+++ b/"):
                    file_path = _normalize_rel_path(line[6:].strip())
                    break
                if line.startswith("+++ /dev/null"):
                    for prev in sec[1:10]:
                        if prev.startswith("--- a/"):
                            file_path = _normalize_rel_path(prev[6:].strip())
                            break
                    break

        # バイナリ差分を除外
        if any(
            line.startswith("Binary files ") or line.startswith("GIT binary patch")
            for line in sec
        ):
            continue

        # ロックファイルを除外
        if file_path and is_lockfile_path(file_path):
            continue

        # --diff-file 併用時の --paths 絞り込み
        if paths and file_path:
            if not any(glob_match(file_path, pat) for pat in paths):
                continue

        if file_path and file_path not in changed_files:
            changed_files.append(file_path)
        kept_sections.append(sec_text)

    filtered_diff = "".join(kept_sections).strip("\r\n")
    return changed_files, filtered_diff


def acquire_diff(
    repo_root: Path,
    diff_file: str | None = None,
    base: str | None = None,
    staged: bool = False,
    paths: list[str] | None = None,
) -> tuple[list[str], str]:
    """--diff-file または git diff から変更ファイル一覧と差分テキストを取得する。"""
    if diff_file:
        if is_sensitive_env_path(diff_file):
            raise GateError(
                "secret_env_file",
                f"秘密情報を含む可能性があるため .env 系ファイルを --diff-file に指定できません: {diff_file}",
            )
        path = Path(diff_file)
        if not path.is_file():
            raise GateError("diff_file_not_found", f"差分ファイルが見つかりません: {diff_file}")
        try:
            raw_diff = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise GateError("diff_file_read_error", f"差分ファイルを読めません: {exc}") from exc
        return parse_diff_sections(raw_diff, paths=paths)

    head_exists = has_head_commit(repo_root)
    cmd = build_git_diff_command(
        repo_root=repo_root,
        base=base,
        staged=staged,
        paths=paths,
        has_head=head_exists,
    )
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0:
        err = proc.stderr.strip() or f"git diff が終了コード {proc.returncode} で失敗しました。"
        raise GateError("git_diff_failed", err)

    return parse_diff_sections(proc.stdout, paths=None)


def build_decisions_payload(
    repo_name: str,
    changed_files: list[str],
    diff_text: str,
    rules: list[RuleItem],
    model: str = DEFAULT_MODEL,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> dict[str, Any]:
    """Decisions API 用のペイロードを組み立て、上限と事前バリデーションを検証する。"""
    if len(rules) > MAX_QUESTIONS:
        raise GateError(
            "question_limit_exceeded",
            f"質問数が上限 {MAX_QUESTIONS} 件を超えています（現在 {len(rules)} 件）。"
            " --rules や .agents/invariants.json の path_globs で対象を絞り込んでください。",
        )

    files_listing = "\n".join(f"- {p}" for p in changed_files) if changed_files else "- (unknown)"
    input_blocks = [
        {
            "type": "text",
            "text": f"Repository: {repo_name}\nChanged files:\n{files_listing}\n\n",
        },
        {
            "type": "text",
            "text": f"Git diff:\n```diff\n{diff_text}\n```\n",
        },
    ]

    total_chars = sum(len(block["text"]) for block in input_blocks)
    if total_chars > max_chars:
        raise GateError(
            "input_size_limit_exceeded",
            f"入力文字数が上限 {max_chars:,} 文字を超えています（現在 {total_chars:,} 文字）。"
            "無言切り詰めは行いません。--paths で対象パスを分割して再実行してください。",
        )

    questions: dict[str, dict[str, Any]] = {}
    for item in rules:
        q_obj: dict[str, Any] = {
            "type": "noul",
            "instructions": item.instructions,
        }
        if item.criteria:
            q_obj["criteria"] = item.criteria
        questions[item.key] = q_obj

    payload: dict[str, Any] = {
        "model": model,
        "input": input_blocks,
        "questions": questions,
    }

    validation_errors = run_decisions.validate_payload(payload)
    if validation_errors:
        raise GateError(
            "payload_validation_failed",
            "ペイロード検証に失敗しました: " + "; ".join(validation_errors),
        )

    return payload


def _normalize_sdk_response(resp: Any) -> dict[str, Any]:
    if isinstance(resp, dict):
        return resp
    if hasattr(resp, "model_dump"):
        try:
            dumped = resp.model_dump(mode="json")
            if isinstance(dumped, dict):
                return dumped
        except TypeError:
            dumped = resp.model_dump()
            if isinstance(dumped, dict):
                return dumped
    if hasattr(resp, "to_json_dict"):
        dumped = resp.to_json_dict()
        if isinstance(dumped, dict):
            return dumped
    result: dict[str, Any] = {}
    for attr in ("answers", "prompt_feedback", "usage"):
        val = getattr(resp, attr, None)
        if val is not None:
            result[attr] = val
    return result


def call_decisions_backend(
    payload: dict[str, Any],
    api_key: str,
    backend: str = "auto",
    endpoint: str = DEFAULT_ENDPOINT,
    timeout: float = DEFAULT_TIMEOUT,
    rest_opener: Callable[..., Any] | None = None,
) -> tuple[dict[str, Any], str]:
    """SDK 優先で Decisions API を呼び出し、非対応環境では REST へフォールバックする。"""
    if backend in ("auto", "sdk"):
        try:
            from google import genai  # type: ignore[import-not-found]
        except ImportError as exc:
            if backend == "sdk":
                raise GateError(
                    "sdk_unavailable",
                    "google-genai SDK が見つかりません。--backend rest または auto を使用してください。",
                ) from exc
        else:
            try:
                client = genai.Client(
                    api_key=api_key,
                    http_options={"api_version": "v1beta"},
                )
                decisions_api = getattr(client, "decisions", None)
                if decisions_api is None or not hasattr(decisions_api, "create"):
                    raise AttributeError("google-genai client.decisions.create is unavailable")
                raw_resp = decisions_api.create(
                    model=payload["model"],
                    input=payload["input"],
                    questions=payload["questions"],
                )
                return _normalize_sdk_response(raw_resp), "sdk"
            except AttributeError as exc:
                if backend == "sdk":
                    raise GateError(
                        "sdk_decisions_unsupported",
                        "導入済みの google-genai に client.decisions がありません（3.2.0 以上が必要です）。",
                    ) from exc
            except Exception as exc:  # noqa: BLE001
                raise GateError("sdk_call_failed", mask_secret(str(exc), api_key)) from exc

    try:
        raw_rest = run_decisions.call_decisions_api(
            payload,
            api_key=api_key,
            endpoint=endpoint,
            timeout=timeout,
            opener=rest_opener,
        )
        return raw_rest, "rest"
    except run_decisions.SafetyBlockError as exc:
        raise GateError(
            "safety_blocked",
            mask_secret(f"安全フィルタにより遮断されました ({exc.source}/{exc.code}): {exc.message}", api_key),
        ) from exc
    except run_decisions.ApiRequestError as exc:
        raise GateError(
            "api_request_failed",
            mask_secret(f"Decisions API 呼び出しに失敗しました: {exc.message}", api_key),
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise GateError("api_unexpected_error", mask_secret(str(exc), api_key)) from exc


def evaluate_answers(
    enriched: dict[str, Any],
    rules: list[RuleItem],
    threshold: float = DEFAULT_THRESHOLD,
    warn_threshold: float = DEFAULT_WARN_THRESHOLD,
    strict: bool = False,
) -> tuple[dict[str, Any], int]:
    """回答確率を閾値で分類し、レポート辞書と終了コードを返す。"""
    answers = enriched.get("answers") or {}
    rules_by_key = {r.key: r for r in rules}

    violations: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []
    passed_count = 0

    for key, rule in rules_by_key.items():
        ans = answers.get(key)
        if not isinstance(ans, dict):
            continue
        noul_val = float(ans.get("noul", 0.0))
        conf_val = float(ans.get("confidence", max(noul_val, 1.0 - noul_val)))
        eff_threshold = rule.threshold if rule.threshold is not None else threshold
        eff_warn = rule.warn_threshold if rule.warn_threshold is not None else warn_threshold

        entry = {
            "key": key,
            "noul": round(noul_val, 4),
            "confidence": round(conf_val, 4),
            "threshold": eff_threshold,
            "warn_threshold": eff_warn,
            "source_file": rule.source_file,
            "start_line": rule.start_line,
            "end_line": rule.end_line,
            "heading": rule.heading,
            "matched_files": rule.matched_files,
            "rule_preview": rule.text[:160],
        }

        if noul_val >= eff_threshold:
            violations.append(entry)
        elif noul_val >= eff_warn:
            warnings.append(entry)
        else:
            passed_count += 1

    violations.sort(key=lambda x: (-x["noul"], x["key"]))
    warnings.sort(key=lambda x: (-x["noul"], x["key"]))

    if violations or (strict and warnings):
        exit_code = 1
        status = "violations_detected" if violations else "warnings_detected_strict"
    else:
        exit_code = 0
        status = "warnings_only" if warnings else "passed"

    report = {
        "status": status,
        "exit_code": exit_code,
        "rule_count": len(rules),
        "violation_candidates": violations,
        "warnings": warnings,
        "passed_count": passed_count,
    }
    return report, exit_code


def format_report_table(report: dict[str, Any]) -> str:
    """レポート辞書を人間向けの Markdown 表形式に整形する。"""
    lines = [
        f"Status: {report['status']} (exit_code={report['exit_code']}, rules={report.get('rule_count', 0)})",
    ]
    if report.get("backend_used"):
        lines.append(f"Backend: {report['backend_used']} | Model: {report.get('model', DEFAULT_MODEL)}")

    for section_title, key in (
        ("Violation Candidates", "violation_candidates"),
        ("Warnings", "warnings"),
    ):
        items = report.get(key) or []
        if not items:
            continue
        lines.append("")
        lines.append(f"### {section_title} ({len(items)})")
        lines.append("| key | noul | confidence | source | heading | matched_files |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for item in items:
            src = f"{item['source_file']}:{item['start_line']}-{item['end_line']}"
            files_str = ", ".join(item.get("matched_files") or [])
            heading = str(item.get("heading") or "").replace("|", "\\|")
            lines.append(
                f"| `{item['key']}` | {item['noul']:.4f} | {item['confidence']:.4f} | `{src}` | {heading} | {files_str} |"
            )

    if not report.get("violation_candidates") and not report.get("warnings"):
        lines.append("違反候補および警告は検出されませんでした。")

    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="git diff とルール文書を Gemini Decision 1 で一括突合する汎用不変条件検査 CLI"
    )
    parser.add_argument("--repo-root", help="対象リポジトリのルートパス（省略時は git rev-parse で自動検出）")
    parser.add_argument("--base", help="比較ベース参照（<ref>...HEAD を比較）")
    parser.add_argument("--staged", action="store_true", help="ステージ済み差分（--cached）のみを対象にする")
    parser.add_argument("--diff-file", help="git diff の代わりに指定ファイルから差分を読み込む")
    parser.add_argument("--paths", nargs="+", help="対象パスまたは glob パターンで差分を絞り込む")
    parser.add_argument("--rules", nargs="+", help="自動検出に加えて読み込むルール Markdown ファイル")
    parser.add_argument(
        "--preset",
        choices=("systems-pre-pr",),
        action="append",
        default=[],
        help="同梱スキルの推奨ルールを自動追加するプリセット（複数指定可）",
    )
    parser.add_argument("--questions-file", help="カスタム質問 JSON ファイル（既定: .agents/invariants.json）")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD, help="違反候補の noul 閾値（既定: 0.70）")
    parser.add_argument("--warn-threshold", type=float, default=DEFAULT_WARN_THRESHOLD, help="警告の noul 閾値（既定: 0.40）")
    parser.add_argument("--strict", action="store_true", help="警告検出時に終了コード 1、ルール 0 件時に 2 を返す")
    parser.add_argument("--max-chars", type=int, default=DEFAULT_MAX_CHARS, help="入力文字数上限（既定: 400000）")
    parser.add_argument("--backend", choices=("auto", "sdk", "rest"), default="auto", help="API 呼び出し経路（既定: auto）")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="モデル ID（既定: gemini-decision-1）")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT, help="REST エンドポイント URL")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="HTTP タイムアウト秒（既定: 30）")
    parser.add_argument("--format", choices=("table", "json"), default="table", help="出力形式（既定: table）")
    parser.add_argument("--dry-run", action="store_true", help="API を呼ばず検証済みペイロードとルール対応表を出力する")
    return parser


def _emit(data: dict[str, Any], output_format: str, stream: Any = None) -> None:
    target = stream or sys.stdout
    if output_format == "json":
        print(json.dumps(data, ensure_ascii=False, indent=2), file=target)
    else:
        if "error" in data:
            print(f"ERROR [{data.get('code', 'error')}]: {data['error']}", file=target)
        elif data.get("status") == "dry_run":
            print(json.dumps(data, ensure_ascii=False, indent=2), file=target)
        elif "violation_candidates" in data:
            print(format_report_table(data), file=target)
        else:
            print(f"Status: {data.get('status')} (exit_code={data.get('exit_code')})", file=target)


def run_cli(
    argv: list[str] | None = None,
    rest_opener: Callable[..., Any] | None = None,
) -> int:
    configure_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()

    try:
        repo_root = resolve_repo_root(args.repo_root)
        changed_files, diff_text = acquire_diff(
            repo_root=repo_root,
            diff_file=args.diff_file,
            base=args.base,
            staged=args.staged,
            paths=args.paths,
        )

        if not diff_text.strip():
            _emit(
                {
                    "status": "skipped_empty_diff",
                    "exit_code": 0,
                    "changed_files": changed_files,
                    "rule_count": 0,
                },
                args.format,
            )
            return 0

        secret_findings = check_diff_secrets(changed_files, diff_text)
        if secret_findings:
            raise GateError("secret_detected", " ".join(secret_findings))

        extra_rules = resolve_extra_rules(
            extra_rules=args.rules,
            presets=args.preset,
            repo_root=repo_root,
        )
        rules = collect_rules(
            repo_root=repo_root,
            changed_files=changed_files,
            extra_rules=extra_rules,
            questions_file=args.questions_file,
        )

        if not rules:
            if args.strict:
                raise GateError(
                    "no_rules_strict",
                    "検査対象のルールが 0 件のため --strict により停止しました。",
                )
            _emit(
                {
                    "status": "skipped_no_rules",
                    "exit_code": 0,
                    "changed_files": changed_files,
                    "rule_count": 0,
                },
                args.format,
            )
            return 0

        payload = build_decisions_payload(
            repo_name=repo_root.name,
            changed_files=changed_files,
            diff_text=diff_text,
            rules=rules,
            model=args.model,
            max_chars=args.max_chars,
        )

        if args.dry_run:
            dry_out = {
                "status": "dry_run",
                "exit_code": 0,
                "changed_files": changed_files,
                "rule_count": len(rules),
                "payload": payload,
                "rules": [
                    {
                        "key": r.key,
                        "source_file": r.source_file,
                        "start_line": r.start_line,
                        "end_line": r.end_line,
                        "heading": r.heading,
                        "matched_files": r.matched_files,
                    }
                    for r in rules
                ],
            }
            _emit(dry_out, args.format)
            return 0

        if not api_key:
            raise GateError(
                "missing_api_key",
                "環境変数 GEMINI_API_KEY が設定されていません。API キーを設定して再実行してください（--dry-run はキー不要です）。",
            )

        raw_response, backend_used = call_decisions_backend(
            payload=payload,
            api_key=api_key,
            backend=args.backend,
            endpoint=args.endpoint,
            timeout=args.timeout,
            rest_opener=rest_opener,
        )

        try:
            enriched = run_decisions.enrich_response(raw_response)
        except run_decisions.SafetyBlockError as exc:
            raise GateError(
                "safety_blocked",
                mask_secret(f"安全フィルタにより遮断されました ({exc.source}/{exc.code}): {exc.message}", api_key),
            ) from exc

        report, exit_code = evaluate_answers(
            enriched=enriched,
            rules=rules,
            threshold=args.threshold,
            warn_threshold=args.warn_threshold,
            strict=args.strict,
        )
        report["backend_used"] = backend_used
        report["model"] = args.model
        report["changed_files"] = changed_files
        _emit(report, args.format)
        return exit_code

    except GateError as exc:
        err_data = {
            "status": "error",
            "exit_code": 2,
            "code": exc.code,
            "error": mask_secret(exc.message, api_key),
        }
        _emit(err_data, args.format, stream=sys.stderr if args.format != "json" else sys.stdout)
        return 2
    except Exception as exc:  # noqa: BLE001
        err_data = {
            "status": "error",
            "exit_code": 2,
            "code": "unexpected_error",
            "error": mask_secret(str(exc), api_key),
        }
        _emit(err_data, args.format, stream=sys.stderr if args.format != "json" else sys.stdout)
        return 2


def main() -> None:
    sys.exit(run_cli())


if __name__ == "__main__":
    main()
