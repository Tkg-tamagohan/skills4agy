#!/usr/bin/env python3
"""
run_all_tests.py - shared-skills 全スキル横断の単体テスト実行ランナー

skills/ 配下に __init__.py を置かない構成のまま、各スキルの test_*.py を
昇順で探索し、ファイルごとに独立した一時作業ディレクトリ上で
`python -B -m unittest discover -s <dir> -t <dir> -p <file>` を順次実行する。

主な機能:
- 兄弟インポート前提のテストを壊さずに全スキルを自動発見・実行する
- 一時ファイル (dir=".") を作成するテストが作業ツリーを汚さないよう隔離する
- `Ran 0 tests` またはテスト 0 件を終了コード 1 で失敗扱いとし、空振りを防ぐ

実行:
  python skills/plugin-authoring/scripts/run_all_tests.py
  python skills/plugin-authoring/scripts/run_all_tests.py --skill plugin-authoring -v
  python skills/plugin-authoring/scripts/run_all_tests.py --format json
標準ライブラリのみで動作する。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
RAN_TESTS_RE = re.compile(r"^Ran (\d+) tests? in ", re.MULTILINE)


class DiscoveryError(Exception):
    """テスト探索または引数指定のエラーを表す。"""


@dataclass(frozen=True)
class TestFileResult:
    """1 本のテストファイルの実行結果を表す。"""

    skill: str
    rel_path: str
    ran_tests: int
    passed: bool
    returncode: int
    duration_sec: float
    failure_reason: Optional[str] = None
    output: str = ""


def configure_utf8_stdio() -> None:
    """標準出力・標準エラーを UTF-8 (errors='replace') に再設定する。"""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def _parse_skills_filter(raw_skills: Optional[Sequence[str]]) -> Optional[List[str]]:
    if not raw_skills:
        return None
    selected: List[str] = []
    seen = set()
    for item in raw_skills:
        for part in item.split(","):
            name = part.strip()
            if name and name not in seen:
                seen.add(name)
                selected.append(name)
    return selected or None


def discover_test_files(
    root: Path, skills_filter: Optional[Sequence[str]] = None
) -> List[Tuple[str, Path]]:
    """root / 'skills' 配下の test_*.py を POSIX パス昇順で収集する。"""
    skills_dir = root / "skills"
    if not skills_dir.is_dir():
        raise DiscoveryError(f"skills ディレクトリが見つかりません: {skills_dir}")

    available_skills = {
        d.name: d
        for d in sorted(skills_dir.iterdir(), key=lambda p: p.name)
        if d.is_dir() and not d.name.startswith(".") and d.name != "__pycache__"
    }

    parsed_filter = _parse_skills_filter(skills_filter)
    if parsed_filter is not None:
        unknown = [name for name in parsed_filter if name not in available_skills]
        if unknown:
            raise DiscoveryError(f"存在しないスキルが指定されました: {', '.join(unknown)}")
        target_skills = [(name, available_skills[name]) for name in sorted(parsed_filter)]
    else:
        target_skills = list(available_skills.items())

    discovered: List[Tuple[str, Path]] = []
    for skill_name, skill_dir in target_skills:
        candidates: List[Path] = []
        for path in skill_dir.rglob("test_*.py"):
            if not path.is_file():
                continue
            rel_parts = path.relative_to(skill_dir).parts
            if any(part.startswith(".") or part == "__pycache__" for part in rel_parts):
                continue
            candidates.append(path)
        candidates.sort(key=lambda p: p.relative_to(root).as_posix())
        for path in candidates:
            discovered.append((skill_name, path))

    discovered.sort(key=lambda item: item[1].relative_to(root).as_posix())
    return discovered


def run_test_file(
    skill: str, test_file: Path, root: Path, *, verbose: bool = False
) -> TestFileResult:
    """1 本のテストファイルを一時作業ディレクトリ上で独立実行する。"""
    rel_path = test_file.relative_to(root).as_posix()
    cmd = [
        sys.executable,
        "-B",
        "-m",
        "unittest",
        "discover",
        "-s",
        str(test_file.parent),
        "-t",
        str(test_file.parent),
        "-p",
        test_file.name,
    ]
    if verbose:
        cmd.append("-v")

    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    start = time.monotonic()
    with tempfile.TemporaryDirectory(
        prefix="shared-skills-test-", ignore_cleanup_errors=True
    ) as tmpdir:
        proc = subprocess.run(
            cmd,
            cwd=tmpdir,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    duration_sec = time.monotonic() - start

    output = "\n".join(part for part in (proc.stdout, proc.stderr) if part).strip()
    matches = RAN_TESTS_RE.findall(output)
    ran_tests = int(matches[-1]) if matches else 0

    failure_reason: Optional[str] = None
    if proc.returncode != 0:
        passed = False
        failure_reason = f"exit code {proc.returncode}"
    elif not matches:
        passed = False
        failure_reason = "unittest 実行件数 ('Ran N tests') を取得できませんでした"
    elif ran_tests == 0:
        passed = False
        failure_reason = "0 件のテストしか実行されませんでした"
    else:
        passed = True

    return TestFileResult(
        skill=skill,
        rel_path=rel_path,
        ran_tests=ran_tests,
        passed=passed,
        returncode=proc.returncode,
        duration_sec=round(duration_sec, 3),
        failure_reason=failure_reason,
        output=output,
    )


def format_table_report(results: Sequence[TestFileResult], *, verbose: bool = False) -> str:
    """実行結果を test-conventions 準拠の Markdown 表形式で整形する。"""
    if not results:
        return "0 件のテストファイルしか見つかりませんでした (合計 0 件)。"

    lines = [
        "| スキル | テストファイル | 件数 | 時間(s) | 結果 |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for res in results:
        status = "PASS" if res.passed else f"FAIL ({res.failure_reason})"
        lines.append(
            f"| `{res.skill}` | `{res.rel_path}` | {res.ran_tests} | {res.duration_sec:.2f} | {status} |"
        )

    total_tests = sum(r.ran_tests for r in results)
    passed_files = sum(1 for r in results if r.passed)
    failed_files = len(results) - passed_files
    lines.append("")
    lines.append(
        f"合計: {len(results)} ファイル / {total_tests} 件 (PASS {passed_files}, FAIL {failed_files})"
    )

    detail_sections: List[str] = []
    for res in results:
        if not res.passed or verbose:
            label = "PASS" if res.passed else f"FAIL: {res.failure_reason}"
            body = res.output or "(出力なし)"
            detail_sections.append(f"\n=== {res.rel_path} [{label}] ===\n{body}")

    return "\n".join(lines) + "".join(detail_sections)


def format_json_report(root: Path, results: Sequence[TestFileResult]) -> str:
    """実行結果を JSON 形式で整形する。"""
    total_tests = sum(r.ran_tests for r in results)
    passed_files = sum(1 for r in results if r.passed)
    failed_files = len(results) - passed_files
    ok = bool(results) and total_tests > 0 and failed_files == 0
    payload = {
        "root": root.as_posix(),
        "total_files": len(results),
        "total_tests": total_tests,
        "passed_files": passed_files,
        "failed_files": failed_files,
        "ok": ok,
        "results": [asdict(r) for r in results],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="shared-skills 全スキル横断の単体テストランナー"
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="プラグインルートディレクトリ (既定: スクリプト位置から自動解決)",
    )
    parser.add_argument(
        "--skill",
        action="append",
        dest="skills",
        help="対象スキル名 (複数回指定またはカンマ区切り可)",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="出力形式 (既定: table)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="各テストファイルの詳細出力も表示する",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    configure_utf8_stdio()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    root = args.root.resolve()

    try:
        test_files = discover_test_files(root, args.skills)
    except DiscoveryError as e:
        print(f"エラー: {e}", file=sys.stderr)
        return 2

    results = [
        run_test_file(skill, path, root, verbose=args.verbose)
        for skill, path in test_files
    ]

    if args.format == "json":
        print(format_json_report(root, results))
    else:
        print(format_table_report(results, verbose=args.verbose))

    total_tests = sum(r.ran_tests for r in results)
    if not results or total_tests == 0:
        return 1
    if any(not r.passed for r in results):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
