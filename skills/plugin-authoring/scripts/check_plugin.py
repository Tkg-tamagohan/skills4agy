#!/usr/bin/env python3
"""
check_plugin.py - shared-skills プラグインの構造検査スクリプト

skills/plugin-authoring/guidelines.md のチェックリストのうち、機械化できる
項目を検査する。description が読むべき状況を特定しているか等の判断が要る
項目は対象外であり、引き続き目視で確認する。

検査項目:
- rules/*.md (AGENTS.md / GEMINI.md を除く): 命名、frontmatter(trigger, description)、
  # 見出し、## 手順、## 対象外、30 行以内
- skills/<name>/SKILL.md: 命名、frontmatter の name とディレクトリ名の一致、
  単一行 description、# 見出し、200 行以内、全スキル description 合計 5,000 文字以内
- skills/<name>/**/*.md (plugin-authoring を除く): コードブロック内の
  skills/<name>/(scripts|presets)/ 相対パス禁止
- rules/AGENTS.md (未存在時はレガシー互換で AGENTS.md): ## 節の本文が 5 行以内
- README.md: rules/ と skills/ が収録一覧と双方向で一致している
- docs/*.md (docs/ 実在時): チェックリストを持つ計画書に `状態:` 行(進行中/完了/中断)がある、
  「進行中」なのに全項目チェック済みの矛盾がない
- plugin.json: name, version, description を必須とし、公式仕様の 10 キー
  (name, description, logo, suggestedPrompts, displayName, version,
  author, homepage, repository, disabled) のみ許容して型、URL、logo 相対パスを検査する
- hooks.json (存在する場合): 公式スキーマのイベント名・未知キー・ハンドラ型、
  および command 内のプラグイン内相対スクリプト実在を検査する
- --version-base <ref>: 指定した git ref の plugin.json と version が
  変わっていることを確認(PR でのバージョン更新忘れと hooks.json 等の
  削除・改名時のマイナーバンプ漏れ検出用)

実行: `python skills/plugin-authoring/scripts/check_plugin.py` (プラグインルートから)
違反があれば非ゼロで終了する。標準ライブラリのみで動作する。
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
NAME_PATTERN = re.compile(r"^[a-z0-9-]+$")
SEMVER_PATTERN = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
RULE_LINE_LIMIT = 30
SKILL_LINE_LIMIT = 200
SKILL_DESCRIPTION_TOTAL_LIMIT = 5000
SKILL_CODEBLOCK_RELPATH_PATTERN = re.compile(
    r"(?:^|[\s\"'(=])(?:\./)?(skills/[a-z0-9-]+/(?:scripts|presets)/[^\s\"'`)]*)"
)
AGENTS_SECTION_LINE_LIMIT = 5
# version の意味づけ対象となるプラグイン中身のパス。これらの移動・改名・削除は
# guidelines.md の規約上マイナーバンプを要求する
VERSIONED_CONTENT_PATHS = ("rules", "skills", "AGENTS.md", "README.md", "hooks.json")
PLUGIN_JSON_PATH = Path("plugin.json")
PLUGIN_JSON_LABEL = PLUGIN_JSON_PATH.as_posix()
HOOKS_JSON_PATH = Path("hooks.json")
HOOKS_JSON_LABEL = HOOKS_JSON_PATH.as_posix()
HOOKS_GROUPED_EVENTS = frozenset({"PreToolUse", "PostToolUse"})
HOOKS_FLAT_EVENTS = frozenset({"SessionStart", "PreInvocation", "PostInvocation", "Stop"})
HOOKS_SPEC_ALLOWED_KEYS = frozenset({"enabled"}) | HOOKS_GROUPED_EVENTS | HOOKS_FLAT_EVENTS
HOOKS_GROUP_ALLOWED_KEYS = frozenset({"matcher", "hooks"})
HOOKS_HANDLER_ALLOWED_KEYS = frozenset({"type", "command", "timeout"})
HOOKS_ALLOWED_HANDLER_TYPES = frozenset({"command"})
HOOK_SCRIPT_RUNNERS = frozenset(
    {"python", "python3", "py", "node", "bash", "sh", "zsh", "pwsh", "powershell"}
)
HOOK_RUNNER_INLINE_FLAGS = frozenset(
    {"-c", "-m", "-e", "--eval", "-p", "--print", "-command", "-encodedcommand", "-enc"}
)
HOOK_RUNNER_VALUE_FLAGS = frozenset(
    {"-executionpolicy", "-ep", "-w", "-x", "-r", "--require", "--loader", "--import"}
)
HOOK_SCRIPT_EXTENSIONS = (".py", ".sh", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".cmd", ".bat")
HOOK_SHELL_SEPARATORS = frozenset({";", "&&", "||", "|", "&"})
AGENTS_MD_PATH = Path("rules") / "AGENTS.md"
IGNORED_RULE_STEMS = frozenset({"AGENTS", "GEMINI"})
README_PATH = Path("README.md")
README_HEADINGS = {"rule": "### ルール", "skill": "### スキル"}
PLUGIN_JSON_ALLOWED_KEYS = frozenset(
    {
        "name",
        "description",
        "logo",
        "suggestedPrompts",
        "displayName",
        "version",
        "author",
        "homepage",
        "repository",
        "disabled",
    }
)
PLUGIN_JSON_REQUIRED_STRING_FIELDS = ("name", "version", "description")
PLUGIN_JSON_AUTHOR_ALLOWED_KEYS = frozenset({"name", "url"})
PLUGIN_JSON_REPOSITORY_ALLOWED_KEYS = frozenset({"type", "url"})
PLUGIN_JSON_LOGO_EXTENSIONS = (".png", ".svg", ".jpg", ".jpeg", ".webp")
HTTPS_URL_PATTERN = re.compile(r"^https://[^/\s]+(?:/\S*)?$")


def run_git(root: Path, *args: str) -> str:
    """指定ディレクトリで git サブコマンドを実行し、標準出力を UTF-8 で返す。"""
    return subprocess.run(
        ["git", *args],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    ).stdout


def semver_tuple(version: str) -> Optional[Tuple[int, int, int]]:
    """X.Y.Z 形式の SemVer を整数タプルに変換する。不一致時は None を返す。"""
    if not isinstance(version, str):
        return None
    m = SEMVER_PATTERN.fullmatch(version)
    if not m:
        return None
    return tuple(int(g) for g in m.groups())


def version_at_ref(root: Path, ref: str) -> Tuple[Optional[str], Optional[str]]:
    """git ref 上の plugin.json の version と失敗時のエラーメッセージを返す。"""
    try:
        # Windows では str(Path) がバックスラッシュを返し git が
        # 「ref:path」のパス部を解決できないため posix に固定する
        text = run_git(root, "show", f"{ref}:{PLUGIN_JSON_PATH.as_posix()}")
    except subprocess.CalledProcessError as e:
        return None, f"{ref} の plugin.json を取得できません({e.stderr.strip()})"
    try:
        version = json.loads(text)["version"]
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        return None, f"plugin.json の version を比較できません({e})"
    return version, None


def has_structural_changes(root: Path, base_ref: str) -> Tuple[Optional[bool], Optional[str]]:
    """base_ref との差分に削除・改名(D/R)が含まれるかと失敗時のエラー詳細を返す。

    base...HEAD はコミット済みの差分、HEAD は未コミット分(ローカル実行の網羅用)を見る。
    """
    diff_out = ""
    for diff_args in (
        ("diff", "--name-status", f"{base_ref}...HEAD", "--", *VERSIONED_CONTENT_PATHS),
        ("diff", "--name-status", "HEAD", "--", *VERSIONED_CONTENT_PATHS),
    ):
        try:
            diff_out += run_git(root, *diff_args)
        except subprocess.CalledProcessError as e:
            return None, e.stderr.strip()
    has_structural = any(
        line.split("\t", 1)[0].startswith(("D", "R"))
        for line in diff_out.splitlines()
        if line.strip()
    )
    return has_structural, None


def parse_frontmatter(text: str) -> Optional[dict]:
    """先頭の --- ブロックを簡易パースする。無ければ None"""
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---":
        return None
    fm = {}
    for line in lines[1:]:
        if line.strip() == "---":
            return fm
        m = re.match(r"^([A-Za-z_]+):\s*(.*)$", line)
        if m:
            fm[m.group(1)] = m.group(2).strip()
    return None


def _partition_markdown_lines(lines: List[str]) -> Tuple[List[str], List[Tuple[int, str]]]:
    """frontmatter 以降の本文行リストと、コードブロック内 (1 始まり行番号, 行) リストを返す。"""
    start = 0
    if lines and lines[0].strip() == "---":
        for idx, line in enumerate(lines[1:], start=1):
            if line.strip() == "---":
                start = idx + 1
                break
    body: List[str] = []
    codeblock: List[Tuple[int, str]] = []
    fence_char: Optional[str] = None
    fence_len = 0
    for lineno, line in enumerate(lines[start:], start=start + 1):
        stripped = line.lstrip()
        m = re.match(r"^(`{3,}|~{3,})", stripped)
        if m:
            tok = m.group(1)
            if fence_char is None:
                fence_char = tok[0]
                fence_len = len(tok)
                continue
            if tok[0] == fence_char and len(tok) >= fence_len and stripped[len(tok) :].strip() == "":
                fence_char = None
                fence_len = 0
                continue
        if fence_char is None:
            body.append(line)
        else:
            codeblock.append((lineno, line))
    return body, codeblock


def _iter_markdown_body_lines(lines: List[str]) -> List[str]:
    """frontmatter とフェンス付きコードブロックを除いた本文行を返す。"""
    body, _ = _partition_markdown_lines(lines)
    return body


def _iter_fenced_codeblock_lines(lines: List[str]) -> List[Tuple[int, str]]:
    """frontmatter 以降のフェンス付きコードブロック内の (1 始まり行番号, 行文字列) を返す。"""
    _, codeblock = _partition_markdown_lines(lines)
    return codeblock


def check_rules(root: Path = REPO_ROOT) -> List[str]:
    errors = []
    rules_dir = root / "rules"
    if not rules_dir.is_dir():
        return ["rules/ ディレクトリがありません"]
    for path in sorted(rules_dir.glob("*.md")):
        if path.stem in IGNORED_RULE_STEMS:
            continue
        rel = path.relative_to(root).as_posix()
        if not NAME_PATTERN.match(path.stem):
            errors.append(f"{rel}: ファイル名が小文字英数字とハイフンのみではありません")
        # 末尾改行が空行として数えられて実際の行数を超過させないよう splitlines で数える
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        fm = parse_frontmatter(text)
        if fm is None:
            errors.append(f"{rel}: frontmatter がありません")
        else:
            if not fm.get("trigger"):
                errors.append(f"{rel}: frontmatter に trigger がありません")
            if not fm.get("description"):
                errors.append(f"{rel}: frontmatter に description がありません")
        if len(lines) > RULE_LINE_LIMIT:
            errors.append(f"{rel}: {len(lines)} 行は上限 {RULE_LINE_LIMIT} 行を超えています")
        body_lines = _iter_markdown_body_lines(lines)
        if not any(l.startswith("# ") for l in body_lines):
            errors.append(f"{rel}: 命令形の見出し(# ...)がありません")
        if not any(re.match(r"^##\s*手順(?:\s|$)", l) for l in body_lines):
            errors.append(f"{rel}: 「## 手順」節がありません")
        if not any(re.match(r"^##\s*対象外(?:\s|$)", l) for l in body_lines):
            errors.append(f"{rel}: 「## 対象外」節がありません")
    return errors


def check_skills(root: Path = REPO_ROOT) -> List[str]:
    errors = []
    skills_dir = root / "skills"
    if not skills_dir.is_dir():
        return ["skills/ ディレクトリがありません"]
    total_desc_chars = 0
    for skill_dir in sorted(p for p in skills_dir.iterdir() if p.is_dir()):
        skill_md = skill_dir / "SKILL.md"
        rel = skill_dir.relative_to(root).as_posix()
        if not NAME_PATTERN.match(skill_dir.name):
            errors.append(f"{rel}: ディレクトリ名が小文字英数字とハイフンのみではありません")
        if not skill_md.is_file():
            errors.append(f"{rel}: SKILL.md がありません")
            continue
        text = skill_md.read_text(encoding="utf-8")
        lines = text.splitlines()
        fm = parse_frontmatter(text)
        if fm is None:
            errors.append(f"{rel}/SKILL.md: frontmatter がありません")
        else:
            if fm.get("name") != skill_dir.name:
                errors.append(
                    f"{rel}/SKILL.md: frontmatter の name({fm.get('name')})が"
                    f"ディレクトリ名({skill_dir.name})と一致しません"
                )
            desc = fm.get("description")
            if not desc:
                errors.append(f"{rel}/SKILL.md: frontmatter に description がありません")
            elif desc.startswith((">", "|")):
                errors.append(
                    f"{rel}/SKILL.md: description に複数行ブロックスカラー({desc[0]})は"
                    "使用できません(単一行 YAML で記述してください)"
                )
            else:
                total_desc_chars += len(desc)
        if len(lines) > SKILL_LINE_LIMIT:
            errors.append(
                f"{rel}/SKILL.md: {len(lines)} 行は上限 {SKILL_LINE_LIMIT} 行を超えています"
            )
        body_lines = _iter_markdown_body_lines(lines)
        if not any(l.startswith("# ") for l in body_lines):
            errors.append(f"{rel}/SKILL.md: 名詞句の見出し(# ...)がありません")
        if skill_dir.name != "plugin-authoring":
            for md_path in sorted(skill_dir.rglob("*.md")):
                md_lines = md_path.read_text(encoding="utf-8").splitlines()
                md_rel = md_path.relative_to(root).as_posix()
                for lineno, cb_line in _iter_fenced_codeblock_lines(md_lines):
                    m = SKILL_CODEBLOCK_RELPATH_PATTERN.search(cb_line)
                    if m:
                        errors.append(
                            f"{md_rel}:{lineno}: コードブロック内でプラグイン相対パス "
                            f"'{m.group(1)}' は使用できません"
                            '("$HOME/.gemini/config/plugins/shared-skills/..." 形式を使用してください)'
                        )
    if total_desc_chars > SKILL_DESCRIPTION_TOTAL_LIMIT:
        errors.append(
            f"skills/*/SKILL.md: 全スキル description の合計文字数 {total_desc_chars} は"
            f"上限 {SKILL_DESCRIPTION_TOTAL_LIMIT} 文字を超えています"
        )
    return errors


def check_agents(root: Path = REPO_ROOT) -> List[str]:
    errors = []
    path = root / AGENTS_MD_PATH
    if not path.is_file():
        legacy_path = root / "AGENTS.md"
        if legacy_path.is_file():
            path = legacy_path
        else:
            return [f"{AGENTS_MD_PATH.as_posix()} がありません"]
    label = path.relative_to(root).as_posix()
    lines = path.read_text(encoding="utf-8").splitlines()
    section = None
    body_lines = 0
    for line in lines + ["## END"]:
        if line.startswith("## "):
            if section is not None and body_lines > AGENTS_SECTION_LINE_LIMIT:
                errors.append(
                    f"{label}: 節「{section}」の本文 {body_lines} 行は"
                    f"上限 {AGENTS_SECTION_LINE_LIMIT} 行を超えています"
                )
            section = line[3:].strip()
            body_lines = 0
        elif section is not None and line.strip():
            body_lines += 1
    return errors


def find_readme_table(
    readme: str, heading: str
) -> Tuple[List[str], List[Tuple[int, str]], Optional[int]]:
    """README の指定節(### 見出し)にある収録一覧の表を解析する。

    (全行リスト, [(行番号, バッククォート囲み名), ...], 表の最終行番号または None)
    を返す。収録一覧の表だけを対象にすることで、構成例や本文中の言及が
    一覧掲載済みと誤認されるのを防ぐ。
    """
    lines = readme.splitlines()
    in_section = False
    entries: List[Tuple[int, str]] = []
    last_table_idx: Optional[int] = None
    for i, line in enumerate(lines):
        # 見出しは階層を問わず節を切り替える。#### などの下位節にある表を
        # 収録一覧と取り違えないようにする
        if re.match(r"^#+\s", line):
            if in_section and last_table_idx is not None:
                break
            in_section = line.strip().startswith(heading)
            continue
        if in_section and line.strip().startswith("|"):
            last_table_idx = i
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if cells:
                m = re.fullmatch(r"`([^`]+)`", cells[0])
                if m:
                    entries.append((i, m.group(1)))
    return lines, entries, last_table_idx


def readme_table_names(readme: str, heading: str) -> set:
    """README の指定節にある表の第1列のバッククォート囲み名の集合を返す。"""
    _, entries, _ = find_readme_table(readme, heading)
    return {name for _, name in entries}


def check_readme(root: Path = REPO_ROOT) -> List[str]:
    """README.md の収録一覧と rules/・skills/ の双方向同期を検査する。"""
    errors = []
    path = root / README_PATH
    if not path.is_file():
        return ["README.md がありません"]
    readme = path.read_text(encoding="utf-8")

    rules_dir = root / "rules"
    actual_rules = (
        {
            f.stem
            for f in rules_dir.glob("*.md")
            if f.stem not in IGNORED_RULE_STEMS
        }
        if rules_dir.is_dir()
        else set()
    )
    listed_rules = readme_table_names(readme, README_HEADINGS["rule"])
    for name in sorted(actual_rules - listed_rules):
        errors.append(f"README.md: ルール `{name}` が収録一覧の表にありません")
    for name in sorted(listed_rules - actual_rules):
        errors.append(
            f"README.md: 収録一覧のルール `{name}` に対応するファイルが rules/ にありません"
        )

    skills_dir = root / "skills"
    actual_skills = (
        {d.name for d in skills_dir.iterdir() if d.is_dir()}
        if skills_dir.is_dir()
        else set()
    )
    listed_skills = readme_table_names(readme, README_HEADINGS["skill"])
    for name in sorted(actual_skills - listed_skills):
        errors.append(f"README.md: スキル `{name}` が収録一覧の表にありません")
    for name in sorted(listed_skills - actual_skills):
        errors.append(
            f"README.md: 収録一覧のスキル `{name}` に対応するディレクトリが skills/ にありません"
        )
    return errors


DOC_STATUS_PATTERN = re.compile(r"^状態[:：]\s*(進行中|完了|中断)")
DOC_CHECKED_PATTERN = re.compile(r"^\s*[-*]\s+\[[xX]\]")
DOC_UNCHECKED_PATTERN = re.compile(r"^\s*[-*]\s+\[ \]")


def check_docs(root: Path = REPO_ROOT) -> List[str]:
    """docs/ の計画書(チェックリストを持つ Markdown)の状態行を検査する。

    計画書の完了後も陳腐化した現況記述が残る事例があったため、状態行の有無と
    「進行中だが全項目チェック済み」の矛盾を機械検出する。
    """
    errors = []
    docs_dir = root / "docs"
    if not docs_dir.is_dir():
        return errors
    for path in sorted(docs_dir.glob("*.md")):
        rel = path.relative_to(root).as_posix()
        lines = path.read_text(encoding="utf-8").splitlines()
        has_checklist = any(
            DOC_CHECKED_PATTERN.match(l) or DOC_UNCHECKED_PATTERN.match(l)
            for l in lines
        )
        if not has_checklist:
            continue
        status = next(
            (m for l in lines if (m := DOC_STATUS_PATTERN.match(l))), None
        )
        if status is None:
            errors.append(
                f"{rel}: チェックリストを持つ計画書に"
                "`状態:` 行(進行中/完了/中断)がありません"
            )
            continue
        if status.group(1) == "進行中" and not any(
            DOC_UNCHECKED_PATTERN.match(l) for l in lines
        ):
            errors.append(
                f"{rel}: 全項目がチェック済みですが `状態: 進行中` のままです。"
                "完了か中断へ更新してください"
            )
    return errors


def _is_non_empty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_https_url(value: object) -> bool:
    return isinstance(value, str) and bool(HTTPS_URL_PATTERN.match(value))


def _check_plugin_logo(logo: object, root: Optional[Path], errors: List[str]) -> None:
    if not _is_non_empty_string(logo):
        errors.append(f"{PLUGIN_JSON_LABEL}: logo は空でない文字列である必要があります")
        return
    assert isinstance(logo, str)
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", logo) or logo.startswith("//"):
        errors.append(
            f"{PLUGIN_JSON_LABEL}: logo に URL は指定できません"
            "(プラグインディレクトリからの相対パスを指定してください)"
        )
        return
    if "\\" in logo:
        errors.append(
            f"{PLUGIN_JSON_LABEL}: logo にバックスラッシュ '\\' は使えません"
            "(POSIX 相対パス '/' を使用してください)"
        )
        return
    if logo.startswith("/") or re.match(r"^[A-Za-z]:", logo):
        errors.append(
            f"{PLUGIN_JSON_LABEL}: logo に絶対パスは指定できません"
            "(プラグインディレクトリからの相対パスを指定してください)"
        )
        return
    if ".." in PurePosixPath(logo).parts:
        errors.append(f"{PLUGIN_JSON_LABEL}: logo がプラグインディレクトリ外を参照しています")
        return
    if not logo.endswith(PLUGIN_JSON_LOGO_EXTENSIONS):
        errors.append(
            f"{PLUGIN_JSON_LABEL}: logo の拡張子は "
            ".png, .svg, .jpg, .jpeg, .webp のいずれかである必要があります"
        )
        return
    if root is not None:
        root_resolved = root.resolve()
        target = (root / logo).resolve()
        try:
            target.relative_to(root_resolved)
        except ValueError:
            errors.append(f"{PLUGIN_JSON_LABEL}: logo がプラグインディレクトリ外を参照しています")
            return
        if not target.is_file():
            errors.append(f"{PLUGIN_JSON_LABEL}: logo のファイルが見つかりません: {logo}")


def validate_plugin_json(data: object, root: Optional[Path] = None) -> List[str]:
    """plugin.json の必須項目と公式仕様 10 フィールドの型と制約を検査する。"""
    errors: List[str] = []
    if not isinstance(data, dict):
        return [f"{PLUGIN_JSON_LABEL}: JSON のトップレベルがオブジェクトではありません"]

    for key in sorted(set(data.keys()) - PLUGIN_JSON_ALLOWED_KEYS):
        errors.append(f"{PLUGIN_JSON_LABEL}: 公式仕様外のトップレベルキー {key!r} があります")

    for key in PLUGIN_JSON_REQUIRED_STRING_FIELDS:
        if key not in data:
            errors.append(f"{PLUGIN_JSON_LABEL}: {key} がありません")
            continue
        value = data[key]
        if not isinstance(value, str):
            errors.append(f"{PLUGIN_JSON_LABEL}: {key} は文字列である必要があります")
        elif not value.strip():
            errors.append(f"{PLUGIN_JSON_LABEL}: {key} がありません")

    name = data.get("name")
    if isinstance(name, str) and name.strip() and not NAME_PATTERN.match(name):
        errors.append(
            f"{PLUGIN_JSON_LABEL}: name は小文字英数字とハイフンのみである必要があります"
        )

    version = data.get("version")
    if isinstance(version, str) and version.strip() and semver_tuple(version) is None:
        errors.append(
            f"{PLUGIN_JSON_LABEL}: version が SemVer(X.Y.Z) ではありません({version})"
        )

    if "displayName" in data and not _is_non_empty_string(data["displayName"]):
        errors.append(f"{PLUGIN_JSON_LABEL}: displayName は空でない文字列である必要があります")

    if "logo" in data:
        _check_plugin_logo(data["logo"], root, errors)

    if "homepage" in data and not _is_https_url(data["homepage"]):
        errors.append(
            f"{PLUGIN_JSON_LABEL}: homepage は https:// で始まる URL である必要があります"
        )

    if "repository" in data:
        repo = data["repository"]
        if isinstance(repo, str):
            if not _is_https_url(repo):
                errors.append(
                    f"{PLUGIN_JSON_LABEL}: repository は https:// で始まる URL である必要があります"
                )
        elif isinstance(repo, dict):
            for key in sorted(set(repo.keys()) - PLUGIN_JSON_REPOSITORY_ALLOWED_KEYS):
                errors.append(
                    f"{PLUGIN_JSON_LABEL}: repository に公式仕様外のキー {key!r} があります"
                )
            if not _is_https_url(repo.get("url")):
                errors.append(
                    f"{PLUGIN_JSON_LABEL}: repository.url は https:// で始まる URL である必要があります"
                )
            if "type" in repo and not _is_non_empty_string(repo["type"]):
                errors.append(
                    f"{PLUGIN_JSON_LABEL}: repository.type は空でない文字列である必要があります"
                )
        else:
            errors.append(
                f"{PLUGIN_JSON_LABEL}: repository は https:// URL または url を持つオブジェクトである必要があります"
            )

    if "author" in data:
        author = data["author"]
        if isinstance(author, str):
            if not author.strip():
                errors.append(
                    f"{PLUGIN_JSON_LABEL}: author は空でない文字列またはオブジェクトである必要があります"
                )
        elif isinstance(author, dict):
            for key in sorted(set(author.keys()) - PLUGIN_JSON_AUTHOR_ALLOWED_KEYS):
                errors.append(
                    f"{PLUGIN_JSON_LABEL}: author に公式仕様外のキー {key!r} があります"
                )
            if not _is_non_empty_string(author.get("name")):
                errors.append(
                    f"{PLUGIN_JSON_LABEL}: author.name は空でない文字列である必要があります"
                )
            if "url" in author and not _is_https_url(author["url"]):
                errors.append(
                    f"{PLUGIN_JSON_LABEL}: author.url は https:// で始まる URL である必要があります"
                )
        else:
            errors.append(
                f"{PLUGIN_JSON_LABEL}: author は空でない文字列またはオブジェクトである必要があります"
            )

    if "suggestedPrompts" in data:
        prompts = data["suggestedPrompts"]
        if not isinstance(prompts, list) or not all(
            _is_non_empty_string(prompt) for prompt in prompts
        ):
            errors.append(
                f"{PLUGIN_JSON_LABEL}: suggestedPrompts は空でない文字列の配列である必要があります"
            )
        elif len(prompts) > 3:
            errors.append(
                f"{PLUGIN_JSON_LABEL}: suggestedPrompts は最大 3 件までです"
            )

    if "disabled" in data and not isinstance(data["disabled"], bool):
        errors.append(f"{PLUGIN_JSON_LABEL}: disabled は真偽値である必要があります")

    return errors


def check_plugin_json(root: Path = REPO_ROOT) -> List[str]:
    path = root / PLUGIN_JSON_PATH
    if not path.is_file():
        return [f"{PLUGIN_JSON_LABEL} がありません"]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return [f"{PLUGIN_JSON_LABEL}: JSON として解釈できません({e})"]
    return validate_plugin_json(data, root=root)


def _tokenize_hook_command(command: str) -> Optional[List[str]]:
    """コマンド文字列をバックスラッシュを保持したままトークン分割する。

    未閉鎖クォートがある場合は None を返す。
    """
    tokens: List[str] = []
    buf: List[str] = []
    in_token = False
    quote: Optional[str] = None
    i = 0
    n = len(command)

    while i < n:
        ch = command[i]
        if quote is not None:
            if quote == "'" and ch == "'":
                quote = None
                i += 1
                continue
            if quote == '"':
                if ch == "\\" and i + 1 < n and command[i + 1] == '"':
                    buf.append('"')
                    i += 2
                    continue
                if ch == '"':
                    quote = None
                    i += 1
                    continue
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

        if ch in ("'", '"'):
            quote = ch
            in_token = True
            i += 1
            continue

        two = command[i : i + 2]
        if two in ("&&", "||"):
            if in_token:
                tokens.append("".join(buf))
                buf = []
                in_token = False
            tokens.append(two)
            i += 2
            continue

        if ch in (";", "|", "&"):
            if in_token:
                tokens.append("".join(buf))
                buf = []
                in_token = False
            tokens.append(ch)
            i += 1
            continue

        buf.append(ch)
        in_token = True
        i += 1

    if quote is not None:
        return None
    if in_token:
        tokens.append("".join(buf))
    return tokens


def _has_unexpanded_plugin_root(token: str) -> bool:
    return (
        token.startswith("$PLUGIN_ROOT")
        or token.startswith("${PLUGIN_ROOT}")
        or token.startswith("%PLUGIN_ROOT%")
    )


def _is_direct_script_token(token: str) -> bool:
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://", token):
        return False
    if token.startswith(("./", "../", ".\\", "..\\")):
        return True
    if _has_unexpanded_plugin_root(token):
        return True
    if "/" in token and not token.startswith("/"):
        return True
    if "\\" in token and not re.match(r"^(?:[A-Za-z]:\\|\\\\)", token):
        return True
    return token.lower().endswith(HOOK_SCRIPT_EXTENSIONS)


def _extract_hook_script_paths(command: str) -> Tuple[List[str], List[str]]:
    """hook command からスクリプトパス候補と構文エラーを抽出する。"""
    tokens = _tokenize_hook_command(command)
    if tokens is None:
        return [], ["command の引用符が閉じられていません"]

    segments: List[List[str]] = []
    current: List[str] = []
    for tok in tokens:
        if tok in HOOK_SHELL_SEPARATORS:
            if current:
                segments.append(current)
                current = []
        else:
            current.append(tok)
    if current:
        segments.append(current)

    candidates: List[str] = []
    errors: List[str] = []

    for seg in segments:
        idx = 0
        while idx < len(seg) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", seg[idx]):
            idx += 1
        if idx >= len(seg):
            continue

        cmd_tok = seg[idx]
        cmd_name = Path(cmd_tok.replace("\\", "/")).name.lower()
        if cmd_name.endswith(".exe"):
            cmd_name = cmd_name[:-4]

        candidate: Optional[str] = None
        if cmd_name in HOOK_SCRIPT_RUNNERS:
            j = idx + 1
            while j < len(seg):
                arg = seg[j]
                arg_lower = arg.lower()
                if arg_lower in HOOK_RUNNER_INLINE_FLAGS:
                    break
                if arg_lower == "-file":
                    if j + 1 < len(seg):
                        candidate = seg[j + 1]
                    break
                if arg_lower in HOOK_RUNNER_VALUE_FLAGS:
                    j += 2
                    continue
                if cmd_name in {"python", "python3", "py"} and (
                    arg_lower.startswith("-c") or arg_lower.startswith("-m")
                ):
                    break
                if (
                    cmd_name in {"python", "python3", "py", "bash", "sh", "zsh"}
                    and arg.startswith("-")
                    and not arg.startswith("--")
                    and len(arg) > 2
                    and any(ch in arg[1:].lower() for ch in ("c", "m", "e"))
                ):
                    break
                if arg == "--":
                    if j + 1 < len(seg):
                        candidate = seg[j + 1]
                    break
                if arg.startswith("-"):
                    j += 1
                    continue
                candidate = arg
                break
        elif _is_direct_script_token(cmd_tok):
            candidate = cmd_tok

        if candidate is None:
            continue
        if _has_unexpanded_plugin_root(candidate):
            errors.append(
                f"command で $PLUGIN_ROOT/%PLUGIN_ROOT% は変数置換されないため、"
                f"プラグインルートからの相対パスを指定してください ({candidate!r})"
            )
        else:
            candidates.append(candidate)

    return candidates, errors


def _check_hook_command_scripts(
    command: str, label: str, root: Path, errors: List[str]
) -> None:
    candidates, parse_errors = _extract_hook_script_paths(command)
    for err in parse_errors:
        errors.append(f"{label}: {err}")

    root_resolved = root.resolve()
    for candidate in candidates:
        if "\\" in candidate:
            errors.append(
                f"{label}: スクリプトパス {candidate!r} にバックスラッシュ '\\' は使えません"
                "(POSIX 相対パス '/' を使用してください)"
            )
            continue
        if candidate.startswith("/") or re.match(r"^[A-Za-z]:", candidate):
            errors.append(
                f"{label}: スクリプトパス {candidate!r} はプラグインルートからの相対パスである必要があります"
            )
            continue
        target = (root / candidate).resolve()
        try:
            target.relative_to(root_resolved)
        except ValueError:
            errors.append(
                f"{label}: スクリプトパス {candidate!r} がプラグインディレクトリ外を参照しています"
            )
            continue
        if not target.is_file():
            errors.append(f"{label}: 参照スクリプトが見つかりません: {candidate}")


def _validate_hook_handler(
    handler: object, label: str, root: Optional[Path], errors: List[str]
) -> None:
    if not isinstance(handler, dict):
        errors.append(f"{label} はオブジェクトである必要があります")
        return
    for key in sorted(set(handler.keys()) - HOOKS_HANDLER_ALLOWED_KEYS):
        errors.append(f"{label} に未知のキー {key!r} があります")

    if "type" in handler:
        handler_type = handler["type"]
        if not isinstance(handler_type, str) or handler_type not in HOOKS_ALLOWED_HANDLER_TYPES:
            errors.append(f"{label}.type は 'command' のみ指定できます")

    has_valid_command = False
    if "command" not in handler or not _is_non_empty_string(handler["command"]):
        errors.append(f"{label}.command は空でない文字列である必要があります")
    else:
        has_valid_command = True

    if "timeout" in handler:
        timeout = handler["timeout"]
        if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
            errors.append(f"{label}.timeout は正の整数である必要があります")

    if has_valid_command and root is not None:
        _check_hook_command_scripts(handler["command"], label, root, errors)


def validate_hooks_json(data: object, root: Optional[Path] = None) -> List[str]:
    """hooks.json の公式仕様スキーマと参照スクリプト実在を検査する。"""
    errors: List[str] = []
    if not isinstance(data, dict):
        return [f"{HOOKS_JSON_LABEL}: JSON のトップレベルがオブジェクトではありません"]

    for hook_name, spec in data.items():
        if not _is_non_empty_string(hook_name):
            errors.append(f"{HOOKS_JSON_LABEL}: フック名は空でない文字列である必要があります")
            continue
        hook_label = f"{HOOKS_JSON_LABEL}.{hook_name}"
        if not isinstance(spec, dict):
            errors.append(f"{hook_label} はオブジェクトである必要があります")
            continue

        for key in sorted(set(spec.keys()) - HOOKS_SPEC_ALLOWED_KEYS):
            errors.append(f"{hook_label} に未知のキー {key!r} があります")

        if "enabled" in spec and not isinstance(spec["enabled"], bool):
            errors.append(f"{hook_label}.enabled は真偽値である必要があります")

        for event in sorted(HOOKS_GROUPED_EVENTS):
            if event not in spec:
                continue
            groups = spec[event]
            event_label = f"{hook_label}.{event}"
            if not isinstance(groups, list):
                errors.append(f"{event_label} は配列である必要があります")
                continue
            for g_idx, group in enumerate(groups):
                group_label = f"{event_label}[{g_idx}]"
                if not isinstance(group, dict):
                    errors.append(f"{group_label} はオブジェクトである必要があります")
                    continue
                for key in sorted(set(group.keys()) - HOOKS_GROUP_ALLOWED_KEYS):
                    errors.append(f"{group_label} に未知のキー {key!r} があります")
                if "matcher" not in group or not isinstance(group["matcher"], str):
                    errors.append(f"{group_label}.matcher は文字列である必要があります")
                if "hooks" not in group or not isinstance(group["hooks"], list):
                    errors.append(f"{group_label}.hooks は配列である必要があります")
                    continue
                for h_idx, handler in enumerate(group["hooks"]):
                    _validate_hook_handler(
                        handler, f"{group_label}.hooks[{h_idx}]", root, errors
                    )

        for event in sorted(HOOKS_FLAT_EVENTS):
            if event not in spec:
                continue
            handlers = spec[event]
            event_label = f"{hook_label}.{event}"
            if not isinstance(handlers, list):
                errors.append(f"{event_label} は配列である必要があります")
                continue
            for h_idx, handler in enumerate(handlers):
                _validate_hook_handler(
                    handler, f"{event_label}[{h_idx}]", root, errors
                )

    return errors


def check_hooks_json(root: Path = REPO_ROOT) -> List[str]:
    """hooks.json の存在時検査(未配置は許容)を行う。"""
    path = root / HOOKS_JSON_PATH
    if not path.exists():
        return []
    if not path.is_file():
        return [f"{HOOKS_JSON_LABEL} がファイルではありません"]
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        return [f"{HOOKS_JSON_LABEL}: JSON として解釈できません({e})"]
    return validate_hooks_json(data, root=root)


def check_version_bump(base_ref: str, root: Path = REPO_ROOT) -> List[str]:
    """base ref と version を比較し、規約通りのバンプかを検査する

    guidelines.md の規約: 追加と修正はパッチ、既存ファイルの移動・改名・削除を
    含む変更はマイナーを上げる。等しくないことだけの確認では降格や非 SemVer の
    任意文字列を通してしまうため、SemVer の単調増加と変更種別の整合を検査する。
    """
    base, base_err = version_at_ref(root, base_ref)
    if base_err is not None:
        return [base_err]
    path = root / PLUGIN_JSON_PATH
    try:
        current = json.loads(path.read_text(encoding="utf-8"))["version"]
    except (json.JSONDecodeError, KeyError, FileNotFoundError, TypeError) as e:
        return [f"plugin.json の version を比較できません({e})"]

    base_t = semver_tuple(base)
    current_t = semver_tuple(current)
    if base_t is None or current_t is None:
        return [
            f"plugin.json の version が SemVer ではありません({base} -> {current})。"
            "X.Y.Z 形式にしてください"
        ]
    if current_t == base_t:
        return [
            f"plugin.json の version が {base_ref} から変わっていません({base})。"
            "追加・修正はパッチ、移動・改名・削除を含む変更はマイナーを上げてください"
        ]
    if current_t < base_t:
        return [
            f"plugin.json の version が {base_ref} より下がっています({base} -> {current})。"
            "version は単調増加させてください"
        ]

    # プラグイン中身の移動・改名・削除(D/R)があればマイナー以上のバンプを要求する。
    has_structural, diff_err = has_structural_changes(root, base_ref)
    if diff_err is not None:
        return [f"差分を取得できません({diff_err})"]
    if has_structural and current_t[:2] <= base_t[:2]:
        return [
            f"plugin.json の version が規約に合いません({base} -> {current})。"
            "移動・改名・削除を含む変更はマイナー以上を上げてください"
        ]
    return []


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description="shared-skills プラグインの構造検査")
    parser.add_argument(
        "--version-base",
        metavar="REF",
        help="指定した git ref の plugin.json と version を比較し、変更がなければエラーにする",
    )
    args = parser.parse_args()

    checks: List[Tuple[str, List[str]]] = [
        ("rules/*.md", check_rules()),
        ("skills/*/SKILL.md", check_skills()),
        ("rules/AGENTS.md", check_agents()),
        ("README.md", check_readme()),
    ]
    if (REPO_ROOT / "docs").is_dir():
        checks.append(("docs/*.md", check_docs()))
    checks.extend(
        [
            ("plugin.json", check_plugin_json()),
            ("hooks.json", check_hooks_json()),
        ]
    )
    if args.version_base:
        checks.append(("version bump", check_version_bump(args.version_base)))

    total = 0
    for label, errors in checks:
        if errors:
            total += len(errors)
            for e in errors:
                print(f"[FAIL] {e}")
        else:
            print(f"[PASS] {label}")
    if total:
        print(f"\n{total} 件の違反があります")
        return 1
    print("\nすべての構造検査を通過しました")
    return 0


if __name__ == "__main__":
    sys.exit(main())
