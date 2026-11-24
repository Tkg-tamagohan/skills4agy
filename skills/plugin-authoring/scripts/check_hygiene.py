#!/usr/bin/env python3
"""check_hygiene.py - リポジトリ横断の構文と文字コードと競合マーカーと文体の衛生検査 CLI。"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import py_compile
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, List, Optional, Pattern, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
SLOP_LINT_PATH = (
    Path(__file__).resolve().parents[2] / "japanese-tech-writing" / "scripts" / "slop_lint.py"
)
TEXT_EXTS = frozenset({".md", ".py", ".json", ".yml", ".yaml", ".txt"})
EXCLUDED_WALK_DIRS = frozenset(
    {
        ".git",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".venv",
        "venv",
        "node_modules",
    }
)
CONFLICT_RE = re.compile(r"^(<{7}|={7}$|>{7})", re.MULTILINE)
ALWAYS_EXCLUDED_SLOP_SUFFIXES = ("references/slop-catalog.md",)

_SLOP_LINT_MODULE: Optional[Any] = None


def reject_non_json_constant(value: str) -> None:
    """JSON 非標準定数（NaN / Infinity / -Infinity）を拒否する。"""
    raise ValueError(f"Invalid JSON constant: {value}")


def _load_slop_lint() -> Any:
    """slop_lint.py をプロセス内へ 1 度だけ読み込む。"""
    global _SLOP_LINT_MODULE
    if _SLOP_LINT_MODULE is not None:
        return _SLOP_LINT_MODULE
    if not SLOP_LINT_PATH.is_file():
        raise FileNotFoundError(f"slop_lint.py が見つかりません: {SLOP_LINT_PATH}")
    spec = importlib.util.spec_from_file_location("_shared_skills_slop_lint", SLOP_LINT_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"slop_lint.py を読み込めません: {SLOP_LINT_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    _SLOP_LINT_MODULE = module
    return module


def _get_git_toplevel(root: Path) -> Optional[Path]:
    """root が Git 作業ツリー内であればトップレベルの解決済み Path を返す。"""
    inside = subprocess.run(
        ["git", "rev-parse", "--is-inside-work-tree"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if inside.returncode != 0 or inside.stdout.decode("utf-8", errors="replace").strip() != "true":
        return None
    proc = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=root,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        return None
    toplevel = proc.stdout.decode("utf-8", errors="replace").strip()
    if not toplevel:
        return None
    try:
        return Path(toplevel).resolve()
    except OSError:
        return None


def collect_target_files(root: Path, *, tracked_only: bool = False) -> List[str]:
    """Git 管理下では追跡済み（tracked_only=False 時は未追跡も含む）の実在ファイル、非 Git では再帰走査結果を返す。"""
    if _get_git_toplevel(root) is not None:
        cmd = ["git", "-c", "core.quotePath=false", "ls-files", "-z", "--cached"]
        if not tracked_only:
            cmd.extend(["--others", "--exclude-standard"])
        proc = subprocess.run(
            cmd,
            cwd=root,
            capture_output=True,
            check=False,
        )
        if proc.returncode == 0:
            rels = sorted({p.decode("utf-8") for p in proc.stdout.split(b"\x00") if p})
            return [rel for rel in rels if (root / rel).is_file()]

    found: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDED_WALK_DIRS)
        base = Path(dirpath)
        for name in sorted(filenames):
            full = base / name
            if full.is_file():
                found.append(full.relative_to(root).as_posix())
    return sorted(found)


def check_py_compile(root: Path, files: List[str]) -> Tuple[int, List[str]]:
    """対象 .py ファイルの構文を TemporaryDirectory 経由で検査する（__pycache__ 非生成）。"""
    py_files = [rel for rel in files if rel.lower().endswith(".py")]
    if not py_files:
        return 0, ["no Python files found"]
    errors: List[str] = []
    with tempfile.TemporaryDirectory(prefix="hygiene-pyc-") as tmpdir:
        tmp = Path(tmpdir)
        for idx, rel in enumerate(py_files):
            try:
                py_compile.compile(
                    str(root / rel),
                    cfile=str(tmp / f"{idx}.pyc"),
                    doraise=True,
                )
            except py_compile.PyCompileError as exc:
                errors.append(f"{rel}: {exc.msg}")
    return len(py_files), errors


def check_json_files(root: Path, files: List[str]) -> Tuple[int, List[str]]:
    """対象 .json ファイルを厳密 JSON として構文検査する。"""
    json_files = [rel for rel in files if rel.lower().endswith(".json")]
    if not json_files:
        return 0, ["no JSON files found"]
    errors: List[str] = []
    for rel in json_files:
        path = root / rel
        try:
            text = path.read_text(encoding="utf-8")
            json.loads(text, parse_constant=reject_non_json_constant)
        except (UnicodeDecodeError, ValueError) as exc:
            errors.append(f"{rel}: {exc}")
    return len(json_files), errors


def check_text_hygiene(root: Path, files: List[str]) -> Tuple[int, List[str]]:
    """対象テキストファイルの UTF-8、U+FFFD、競合マーカーを検査する。"""
    errors: List[str] = []
    checked = 0
    for rel in files:
        p = Path(rel)
        if p.suffix.lower() not in TEXT_EXTS:
            continue
        full = root / rel
        if not full.is_file():
            continue
        checked += 1
        try:
            content = full.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            errors.append(f"{rel}: UTF-8 decode error: {exc}")
            continue
        if "\ufffd" in content:
            errors.append(f"{rel}: contains U+FFFD replacement character")
        if CONFLICT_RE.search(content):
            errors.append(f"{rel}: contains conflict marker")
    return checked, errors


def _normalize_sloplint_ignore_line(raw: str) -> Optional[str]:
    """gitignore 互換で .sloplintignore の 1 行を正規化する（空白行とコメントは None）。"""
    line = raw.rstrip("\r\n")
    end = len(line)
    while end > 0 and line[end - 1] == " ":
        bs = 0
        j = end - 2
        while j >= 0 and line[j] == "\\":
            bs += 1
            j -= 1
        if bs % 2 == 1:
            break
        end -= 1
    line = line[:end]
    if not line.strip() or line.startswith("#"):
        return None
    if line.startswith("!./"):
        return "!/" + line[3:]
    if line.startswith("./"):
        return "/" + line[2:]
    return line


def load_sloplint_ignore(root: Path) -> List[str]:
    """.sloplintignore から gitignore 互換の除外パターン一覧を読み込む。"""
    ignore_path = root / ".sloplintignore"
    if not ignore_path.is_file():
        return []
    patterns: List[str] = []
    for raw in ignore_path.read_text(encoding="utf-8", errors="replace").splitlines():
        norm = _normalize_sloplint_ignore_line(raw)
        if norm is not None:
            patterns.append(norm)
    return patterns


def _has_trailing_unescaped_slash(pat: str) -> bool:
    if not pat.endswith("/"):
        return False
    bs = 0
    i = len(pat) - 2
    while i >= 0 and pat[i] == "\\":
        bs += 1
        i -= 1
    return bs % 2 == 0


def _contains_unescaped_slash(pat: str) -> bool:
    i = 0
    while i < len(pat):
        if pat[i] == "\\":
            i += 2
            continue
        if pat[i] == "/":
            return True
        i += 1
    return False


def _compile_gitignore_pattern(
    raw_pat: str,
) -> Optional[Tuple[bool, bool, Pattern[str]]]:
    """gitignore 形式 1 行を (negated, dir_only, compiled_regex) へ変換する。不正パターンは None。"""
    negated = False
    pat = raw_pat
    if pat.startswith("!"):
        negated = True
        pat = pat[1:]
    if not pat:
        return None

    dir_only = _has_trailing_unescaped_slash(pat)
    if dir_only:
        pat = pat[:-1]
    if not pat:
        return None

    anchored = _contains_unescaped_slash(pat)
    if pat.startswith("/"):
        pat = pat[1:]

    parts: List[str] = []
    i = 0
    n = len(pat)
    while i < n:
        if pat[i] == "\\":
            if i + 1 < n:
                parts.append(re.escape(pat[i + 1]))
                i += 2
            else:
                parts.append(re.escape("\\"))
                i += 1
        elif pat.startswith("**/", i) and (i == 0 or pat[i - 1] == "/"):
            parts.append("(?:.*/)?")
            i += 3
        elif pat.startswith("/**", i) and i + 3 == n:
            parts.append("/.+")
            i += 3
        elif pat.startswith("**", i):
            parts.append(".*")
            i += 2
        elif pat[i] == "*":
            parts.append("[^/]*")
            i += 1
        elif pat[i] == "?":
            parts.append("[^/]")
            i += 1
        elif pat[i] == "[":
            j = i + 1
            if j < n and pat[j] in ("!", "^"):
                j += 1
            if j < n and pat[j] == "]":
                j += 1
            closed = False
            while j < n:
                if pat[j] == "\\" and j + 1 < n:
                    j += 2
                    continue
                if pat[j] == "]":
                    closed = True
                    break
                j += 1
            if not closed:
                return None
            inner = pat[i + 1 : j]
            if inner.startswith(("!", "^")):
                parts.append(f"[^{inner[1:]}/]")
            else:
                parts.append(f"(?!/)[{inner}]")
            i = j + 1
        else:
            parts.append(re.escape(pat[i]))
            i += 1

    prefix = "^" if anchored else "^(?:.*/)?"
    try:
        regex = re.compile(prefix + "".join(parts) + "$")
    except re.error:
        return None
    return negated, dir_only, regex


def is_slop_ignored(rel: str, ignore_patterns: List[str]) -> bool:
    """対象 Markdown が .sloplintignore または恒久除外サフィックスに該当するか判定する（親ディレクトリ除外優先）。"""
    if any(rel.endswith(suffix) for suffix in ALWAYS_EXCLUDED_SLOP_SUFFIXES):
        return True
    rules = [
        compiled
        for raw_pat in ignore_patterns
        if (compiled := _compile_gitignore_pattern(raw_pat)) is not None
    ]
    if not rules:
        return False

    parts = rel.split("/")
    for idx in range(1, len(parts)):
        dir_rel = "/".join(parts[:idx])
        dir_ignored = False
        for negated, _dir_only, regex in rules:
            if regex.match(dir_rel):
                dir_ignored = not negated
        if dir_ignored:
            return True

    file_ignored = False
    for negated, dir_only, regex in rules:
        if dir_only:
            continue
        if regex.match(rel):
            file_ignored = not negated
    return file_ignored


def _collect_git_slop_ignored(
    root: Path, *, tracked_only: bool = False
) -> Optional[Set[str]]:
    """Git 管理下かつ .sloplintignore 実在時は正規化済みパターンで git 自身の除外判定結果を返す。"""
    toplevel = _get_git_toplevel(root)
    if toplevel is None:
        return None
    try:
        resolved_root = root.resolve()
    except OSError:
        return None

    is_toplevel = resolved_root == toplevel
    if is_toplevel:
        ignore_file = resolved_root / ".sloplintignore"
        if not ignore_file.is_file():
            return set()
        git_cwd = resolved_root
        rel_prefix = ""
    else:
        if (resolved_root / ".sloplintignore").is_file():
            return None
        ignore_file = toplevel / ".sloplintignore"
        if not ignore_file.is_file():
            return set()
        git_cwd = toplevel
        rel_prefix = resolved_root.relative_to(toplevel).as_posix() + "/"

    norm_lines = load_sloplint_ignore(ignore_file.parent)
    if not norm_lines:
        return set()

    with tempfile.TemporaryDirectory(prefix="hygiene-ignore-") as tmpdir:
        tmp_ignore = Path(tmpdir) / "sloplintignore"
        tmp_ignore.write_text("\n".join(norm_lines) + "\n", encoding="utf-8", newline="\n")
        cmd = ["git", "-c", "core.quotePath=false", "ls-files", "-z", "--cached"]
        if not tracked_only:
            cmd.append("--others")
        cmd.extend(["--ignored", f"--exclude-from={tmp_ignore}"])
        proc = subprocess.run(cmd, cwd=git_cwd, capture_output=True, check=False)
        if proc.returncode != 0:
            return None
        raw_paths = {p.decode("utf-8") for p in proc.stdout.split(b"\x00") if p}
        if not rel_prefix:
            return raw_paths
        return {
            p[len(rel_prefix) :] for p in raw_paths if p.startswith(rel_prefix)
        }


def check_slop_lint(
    root: Path, files: List[str], *, tracked_only: bool = False
) -> Tuple[int, List[str]]:
    """除外対象を除く全 Markdown に slop_lint --strict（warn/error）を適用する。"""
    git_ignored = _collect_git_slop_ignored(root, tracked_only=tracked_only)
    ignore_patterns = [] if git_ignored is not None else load_sloplint_ignore(root)
    md_files: List[str] = []
    for rel in files:
        if not rel.lower().endswith(".md"):
            continue
        if any(rel.endswith(suffix) for suffix in ALWAYS_EXCLUDED_SLOP_SUFFIXES):
            continue
        if git_ignored is not None:
            if rel in git_ignored:
                continue
        elif is_slop_ignored(rel, ignore_patterns):
            continue
        md_files.append(rel)
    if not md_files:
        return 0, []

    slop_lint = _load_slop_lint()
    try:
        words = slop_lint.resolve_words(str(root), None, False)
    except Exception as exc:
        return 0, [f"slop_lint word config error: {exc}"]

    errors: List[str] = []
    for rel in md_files:
        try:
            text = (root / rel).read_text(encoding="utf-8")
        except UnicodeDecodeError:
            # UTF-8 破損は check_text_hygiene で報告されるため重複させない
            continue
        result = slop_lint.lint_text(text, words=words)
        counts = result.get("counts", {})
        err_cnt = int(counts.get("error", 0))
        warn_cnt = int(counts.get("warn", 0))
        if err_cnt > 0 or warn_cnt > 0:
            samples = [
                f"L{f.get('line', '?')}:{f.get('rule', '?')}"
                for f in result.get("findings", [])
                if f.get("severity") in ("error", "warn")
            ][:5]
            detail = f" [{', '.join(samples)}]" if samples else ""
            errors.append(
                f"{rel}: slop_lint --strict failed (error={err_cnt}, warn={warn_cnt}){detail}"
            )
    return len(md_files), errors


def run_hygiene_checks(
    root: Path = REPO_ROOT,
    *,
    skip_slop_lint: bool = False,
    tracked_only: bool = False,
) -> List[Tuple[str, int, List[str]]]:
    """全衛生検査を実行し、[(検査名, 件数, エラーリスト), ...] を返す。"""
    files = collect_target_files(root, tracked_only=tracked_only)
    py_count, py_errors = check_py_compile(root, files)
    json_count, json_errors = check_json_files(root, files)
    text_count, text_errors = check_text_hygiene(root, files)

    results: List[Tuple[str, int, List[str]]] = [
        ("py_compile", py_count, py_errors),
        ("json.loads", json_count, json_errors),
        ("text hygiene (UTF-8 / U+FFFD / conflict markers)", text_count, text_errors),
    ]
    if not skip_slop_lint:
        slop_count, slop_errors = check_slop_lint(root, files, tracked_only=tracked_only)
        results.append(("slop_lint --strict", slop_count, slop_errors))
    return results


def main(argv: Optional[List[str]] = None) -> int:
    """CLI エントリポイント。"""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="リポジトリの構文、文字コード、競合マーカー、文体衛生を検査する"
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="検査対象のルートディレクトリ（既定: リポジトリルート）",
    )
    parser.add_argument(
        "--skip-slop-lint",
        action="store_true",
        help="Markdown に対する slop_lint --strict 検査を省略する",
    )
    parser.add_argument(
        "--tracked-only",
        action="store_true",
        help="Git 管理下で未追跡ファイルを除外し、追跡済みファイルのみを検査する",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    results = run_hygiene_checks(
        root, skip_slop_lint=args.skip_slop_lint, tracked_only=args.tracked_only
    )

    total_errors = 0
    for label, count, errors in results:
        if errors:
            total_errors += len(errors)
            for err in errors:
                print(f"[FAIL] {err}")
        else:
            print(f"[PASS] {label}: {count} files")

    if total_errors:
        print(f"\n{total_errors} 件の衛生検査違反があります")
        return 1
    print("\nすべての衛生検査を通過しました")
    return 0


if __name__ == "__main__":
    sys.exit(main())
