#!/usr/bin/env python3
"""discover_contract_scope.py - 契約抽出対象ディレクトリの決定論的スコープ探索 CLI。

指定ルート配下を `os.scandir(..., follow_symlinks=False)` の幅優先探索（BFS）で走査し、
除外ディレクトリ・テスト専用ディレクトリ・`.gitignore`・`.env` 系秘密ファイル・
ロックファイル・スタイルシート・非 UTF-8 バイナリを除外したうえでボトムアップ剪定を行い、
後行順（leaf -> intermediate -> root）の対象ディレクトリ一覧と行予算ベースのチャンク計画を出力する。

外部依存を持たず Python 標準ライブラリのみで動作する。
"""

from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass, field
import fnmatch
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Iterable, Sequence

_DECISIONS_SCRIPTS_DIR = (
    Path(__file__).resolve().parents[2] / "gemini-decisions-api" / "scripts"
)
if str(_DECISIONS_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_DECISIONS_SCRIPTS_DIR))

from decision_hygiene import configure_utf8_stdio, is_blocked_env_path  # noqa: E402

DEFAULT_MAX_DIRS_WITHOUT_APPROVAL = 15
DEFAULT_CHUNK_LINES = 1500
DIRECT_MODE_MAX_DIRS = 5

DEFAULT_EXCLUDED_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".antigravity",
        ".venv",
        "venv",
        "node_modules",
        "dist",
        "build",
        "target",
        "__pycache__",
        "third_party",
        ".mypy_cache",
        ".pytest_cache",
    }
)

TEST_DIR_NAMES: frozenset[str] = frozenset(
    {
        "tests",
        "test",
        "__tests__",
        "spec",
        "specs",
    }
)

LOCKFILE_NAMES: frozenset[str] = frozenset(
    {
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "Cargo.lock",
        "poetry.lock",
        "uv.lock",
        "Gemfile.lock",
        "composer.lock",
        "go.sum",
        "Pipfile.lock",
        "bun.lockb",
        "bun.lock",
        "flake.lock",
        "npm-shrinkwrap.json",
        "shrinkwrap.json",
    }
)

STYLESHEET_EXTS: frozenset[str] = frozenset(
    {
        ".css",
        ".scss",
        ".sass",
        ".less",
        ".styl",
    }
)

SCHEMA_IDL_EXTS: frozenset[str] = frozenset(
    {
        ".proto",
        ".sql",
        ".graphql",
        ".gql",
        ".thrift",
        ".avsc",
        ".fbs",
        ".capnp",
        ".prisma",
        ".smithy",
        ".wsdl",
        ".xsd",
    }
)

BUILD_EXTS: frozenset[str] = frozenset(
    {
        ".cmake",
        ".gradle",
        ".cabal",
        ".csproj",
        ".fsproj",
        ".vbproj",
        ".sln",
        ".tf",
        ".hcl",
        ".bzl",
    }
)

BUILD_FILENAMES: frozenset[str] = frozenset(
    {
        "package.json",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "requirements.txt",
        "Pipfile",
        "Cargo.toml",
        "go.mod",
        "go.work",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "CMakeLists.txt",
        "Makefile",
        "GNUmakefile",
        "Justfile",
        "justfile",
        "meson.build",
        "BUILD",
        "BUILD.bazel",
        "WORKSPACE",
        "WORKSPACE.bazel",
        "MODULE.bazel",
        "Dockerfile",
        "compose.yaml",
        "compose.yml",
        "docker-compose.yml",
        "docker-compose.yaml",
        "tsconfig.json",
        "deno.json",
        "deno.jsonc",
        "Gemfile",
        "composer.json",
        "mix.exs",
        "stack.yaml",
        "package.yaml",
        "pubspec.yaml",
        "flake.nix",
        "plugin.json",
        "hooks.json",
        "mcp_config.json",
    }
)

SOURCE_EXTS: frozenset[str] = frozenset(
    {
        ".py",
        ".pyi",
        ".pyx",
        ".js",
        ".mjs",
        ".cjs",
        ".jsx",
        ".ts",
        ".mts",
        ".cts",
        ".tsx",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".kts",
        ".scala",
        ".groovy",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".cxx",
        ".hpp",
        ".hh",
        ".hxx",
        ".cs",
        ".fs",
        ".vb",
        ".rb",
        ".php",
        ".swift",
        ".m",
        ".mm",
        ".dart",
        ".ex",
        ".exs",
        ".erl",
        ".hrl",
        ".hs",
        ".lhs",
        ".ml",
        ".mli",
        ".clj",
        ".cljs",
        ".cljc",
        ".lua",
        ".r",
        ".R",
        ".jl",
        ".zig",
        ".nim",
        ".v",
        ".sv",
        ".sh",
        ".bash",
        ".zsh",
        ".fish",
        ".ps1",
        ".psm1",
        ".bat",
        ".cmd",
        ".sol",
        ".move",
        ".cairo",
        ".wgsl",
        ".glsl",
        ".hlsl",
        ".vue",
        ".svelte",
        ".astro",
    }
)

ENTRYPOINT_STEMS: frozenset[str] = frozenset({"main", "index", "lib", "mod"})

_TEST_SUFFIX_RE = re.compile(r"(?:_test|Test|\.spec|\.test)\.[^.]+$")


class ScopeDiscoveryError(Exception):
    """探索ルートや設定の不正を表すエラー。"""


@dataclass(frozen=True)
class GitignoreRule:
    """単一の簡易 `.gitignore` ルール。"""

    base_rel: str
    pattern: str
    negated: bool
    dir_only: bool
    anchored: bool
    has_slash: bool


@dataclass(frozen=True)
class FileEntry:
    """対象として採用された 1 ファイルのメタデータ。"""

    rel_path: str
    name: str
    lines: int
    tier: int
    priority: str


@dataclass
class _DirNode:
    """BFS で構築するディレクトリ木ノード。"""

    rel_path: str
    files: list[FileEntry] = field(default_factory=list)
    children: list["_DirNode"] = field(default_factory=list)


def _strip_unescaped_trailing_spaces(line: str) -> str:
    idx = len(line)
    while idx > 0 and line[idx - 1] == " ":
        if idx >= 2 and line[idx - 2] == "\\":
            break
        idx -= 1
    return line[:idx]


def parse_gitignore_lines(lines: Iterable[str], base_rel: str) -> list[GitignoreRule]:
    """`.gitignore` の行群を簡易ルール列へ変換する。"""
    rules: list[GitignoreRule] = []
    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line or line.lstrip().startswith("#"):
            continue
        line = _strip_unescaped_trailing_spaces(line)
        if not line:
            continue
        negated = False
        if line.startswith("!"):
            negated = True
            line = line[1:]
        elif line.startswith(r"\!") or line.startswith(r"\#"):
            line = line[1:]
        if not line:
            continue
        dir_only = line.endswith("/")
        if dir_only:
            line = line.rstrip("/")
        if not line:
            continue
        anchored = line.startswith("/")
        if anchored:
            line = line.lstrip("/")
        has_slash = "/" in line
        rules.append(
            GitignoreRule(
                base_rel=base_rel,
                pattern=line,
                negated=negated,
                dir_only=dir_only,
                anchored=anchored,
                has_slash=has_slash,
            )
        )
    return rules


def _match_gitignore_rule(rule: GitignoreRule, rel_posix: str, is_dir: bool) -> bool:
    if rule.dir_only and not is_dir:
        return False
    if rule.base_rel == ".":
        local_rel = rel_posix
    elif rel_posix.startswith(rule.base_rel + "/"):
        local_rel = rel_posix[len(rule.base_rel) + 1 :]
    else:
        return False

    if not rule.anchored and not rule.has_slash:
        name = local_rel.rsplit("/", 1)[-1]
        return fnmatch.fnmatchcase(name, rule.pattern)

    if fnmatch.fnmatchcase(local_rel, rule.pattern):
        return True
    if "**/" in rule.pattern:
        collapsed = rule.pattern.replace("**/", "")
        if fnmatch.fnmatchcase(local_rel, collapsed):
            return True
    return False


def is_ignored_by_gitignore(
    rules: Sequence[GitignoreRule], rel_posix: str, *, is_dir: bool
) -> bool:
    """`.gitignore` ルール列を順に評価し、対象が除外されるかを返す。"""
    ignored = False
    for rule in rules:
        if _match_gitignore_rule(rule, rel_posix, is_dir):
            ignored = not rule.negated
    return ignored


def is_test_filename(name: str) -> bool:
    """テストファイル命名規則（`test_*.py`, `*_test.*`, `*Test.*`, `*.spec.*`, `*.test.*`）を判定する。"""
    if name.startswith("test_") and name.endswith(".py"):
        return True
    return bool(_TEST_SUFFIX_RE.search(name))


def classify_production_file(name: str) -> tuple[int, str] | None:
    """ファイルの優先度（1: schema_build, 2: entrypoint, 3: source）を返す。対象外は None。"""
    if is_blocked_env_path(name):
        return None
    if name in LOCKFILE_NAMES:
        return None
    if is_test_filename(name):
        return None

    ext = PurePosixPath(name).suffix
    ext_lower = ext.lower()
    if ext_lower in STYLESHEET_EXTS:
        return None

    if ext_lower in SCHEMA_IDL_EXTS or ext_lower in BUILD_EXTS or name in BUILD_FILENAMES:
        return (1, "schema_build")

    if ext not in SOURCE_EXTS and ext_lower not in SOURCE_EXTS:
        return None

    stem = PurePosixPath(name).stem
    if name == "__init__.py" or stem in ENTRYPOINT_STEMS:
        return (2, "entrypoint")

    return (3, "source")


def count_utf8_lines(path: Path) -> int | None:
    """ファイルを厳密 UTF-8 として読み込み行数を返す。NUL バイトやデコード不可は None。"""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return len(text.splitlines())


def pack_file_chunks(files: Sequence[FileEntry], chunk_lines: int) -> list[dict[str, object]]:
    """優先順ファイル列を `chunk_lines` 以内でチャンク分割する（単一超過ファイルは分割しない）。"""
    chunks: list[dict[str, object]] = []
    current_files: list[FileEntry] = []
    current_lines = 0

    def _flush() -> None:
        nonlocal current_files, current_lines
        if not current_files:
            return
        chunks.append(
            {
                "chunk_index": len(chunks) + 1,
                "total_lines": current_lines,
                "files": [
                    {
                        "path": f.rel_path,
                        "lines": f.lines,
                        "priority": f.priority,
                    }
                    for f in current_files
                ],
            }
        )
        current_files = []
        current_lines = 0

    for entry in files:
        if current_files and current_lines + entry.lines > chunk_lines:
            _flush()
        current_files.append(entry)
        current_lines += entry.lines

    _flush()
    return chunks


def _load_dir_gitignore(abs_dir: Path, base_rel: str) -> list[GitignoreRule]:
    gi_path = abs_dir / ".gitignore"
    try:
        if gi_path.is_symlink() or not gi_path.is_file():
            return []
        text = gi_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return parse_gitignore_lines(text.splitlines(), base_rel)


def discover_scope(
    root: Path,
    *,
    max_dirs_without_approval: int = DEFAULT_MAX_DIRS_WITHOUT_APPROVAL,
    chunk_lines: int = DEFAULT_CHUNK_LINES,
) -> dict[str, object]:
    """BFS 走査、ボトムアップ剪定、後行順出力、チャンク計画を実行して辞書で返す。"""
    if not root.exists():
        raise ScopeDiscoveryError(f"ルートディレクトリが存在しません: {root}")
    if root.is_symlink() or not root.is_dir():
        raise ScopeDiscoveryError(f"ルートが通常のディレクトリではありません: {root}")
    if max_dirs_without_approval < 0:
        raise ScopeDiscoveryError("--max-dirs-without-approval は 0 以上で指定してください")
    if chunk_lines <= 0:
        raise ScopeDiscoveryError("--chunk-lines は 1 以上で指定してください")

    resolved_root = root.resolve()
    root_node = _DirNode(rel_path=".")
    queue: deque[tuple[Path, _DirNode, tuple[GitignoreRule, ...]]] = deque(
        [(resolved_root, root_node, ())]
    )

    while queue:
        abs_dir, node, inherited_rules = queue.popleft()
        local_rules = _load_dir_gitignore(abs_dir, node.rel_path)
        active_rules = inherited_rules + tuple(local_rules)

        try:
            with os.scandir(abs_dir) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError:
            continue

        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = False if is_dir else entry.is_file(follow_symlinks=False)
            except OSError:
                continue

            rel_posix = entry.name if node.rel_path == "." else f"{node.rel_path}/{entry.name}"

            if is_dir:
                if entry.name in DEFAULT_EXCLUDED_DIRS or entry.name in TEST_DIR_NAMES:
                    continue
                if is_ignored_by_gitignore(active_rules, rel_posix, is_dir=True):
                    continue
                child_node = _DirNode(rel_path=rel_posix)
                node.children.append(child_node)
                queue.append((Path(entry.path), child_node, active_rules))
            elif is_file:
                if is_ignored_by_gitignore(active_rules, rel_posix, is_dir=False):
                    continue
                classified = classify_production_file(entry.name)
                if classified is None:
                    continue
                lines = count_utf8_lines(Path(entry.path))
                if lines is None:
                    continue
                tier, priority = classified
                node.files.append(
                    FileEntry(
                        rel_path=rel_posix,
                        name=entry.name,
                        lines=lines,
                        tier=tier,
                        priority=priority,
                    )
                )

    emitted: list[dict[str, object]] = []

    def _prune_and_emit(node: _DirNode) -> bool:
        retained_children = 0
        for child in node.children:
            if _prune_and_emit(child):
                retained_children += 1

        if not node.files and retained_children == 0:
            return False

        ordered_files = sorted(node.files, key=lambda f: (f.tier, f.name))
        total_lines = sum(f.lines for f in ordered_files)
        chunks = pack_file_chunks(ordered_files, chunk_lines)
        if node.rel_path == ".":
            kind = "root"
        elif retained_children == 0:
            kind = "leaf"
        else:
            kind = "intermediate"

        emitted.append(
            {
                "path": node.rel_path,
                "kind": kind,
                "total_lines": total_lines,
                "chunks": chunks,
            }
        )
        return True

    _prune_and_emit(root_node)

    dir_count = len(emitted)
    requires_approval = dir_count > max_dirs_without_approval
    recommended_mode = "direct" if dir_count <= DIRECT_MODE_MAX_DIRS else "delegated"

    return {
        "root": resolved_root.as_posix(),
        "dir_count": dir_count,
        "requires_approval": requires_approval,
        "recommended_mode": recommended_mode,
        "max_dirs_without_approval": max_dirs_without_approval,
        "chunk_lines": chunk_lines,
        "directories": emitted,
    }


def format_table(payload: dict[str, object]) -> str:
    """探索結果を人間が読みやすい表形式で整形する。"""
    dirs = payload["directories"]
    assert isinstance(dirs, list)
    lines = [
        f"root: {payload['root']}",
        (
            f"dir_count: {payload['dir_count']} | "
            f"requires_approval: {payload['requires_approval']} | "
            f"recommended_mode: {payload['recommended_mode']} | "
            f"chunk_lines: {payload['chunk_lines']}"
        ),
        "",
    ]
    if not dirs:
        lines.append("対象となる本番ソース/スキーマ/ビルドディレクトリはありませんでした。")
        return "\n".join(lines)

    lines.append("| # | path | kind | files | total_lines | chunks |")
    lines.append("| ---: | --- | --- | ---: | ---: | ---: |")
    for idx, item in enumerate(dirs, start=1):
        chunks = item["chunks"]
        file_count = sum(len(c["files"]) for c in chunks)
        lines.append(
            f"| {idx} | `{item['path']}` | {item['kind']} | "
            f"{file_count} | {item['total_lines']} | {len(chunks)} |"
        )
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="契約抽出向けの対象ディレクトリ・チャンク計画を探索する CLI"
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("."),
        help="探索対象のルートディレクトリ (既定: .)",
    )
    parser.add_argument(
        "--max-dirs-without-approval",
        type=int,
        default=DEFAULT_MAX_DIRS_WITHOUT_APPROVAL,
        help=f"確認なしで続行できるディレクトリ数上限 (既定: {DEFAULT_MAX_DIRS_WITHOUT_APPROVAL})",
    )
    parser.add_argument(
        "--chunk-lines",
        type=int,
        default=DEFAULT_CHUNK_LINES,
        help=f"1 チャンクあたりの最大行数予算 (既定: {DEFAULT_CHUNK_LINES})",
    )
    parser.add_argument(
        "--format",
        choices=("json", "table"),
        default="json",
        help="出力形式 (既定: json)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    configure_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        payload = discover_scope(
            args.root,
            max_dirs_without_approval=args.max_dirs_without_approval,
            chunk_lines=args.chunk_lines,
        )
    except ScopeDiscoveryError as exc:
        print(f"エラー: {exc}", file=sys.stderr)
        return 2

    if args.format == "table":
        print(format_table(payload))
    else:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
