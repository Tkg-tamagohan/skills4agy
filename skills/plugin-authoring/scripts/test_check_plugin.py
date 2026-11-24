"""check_plugin.py の plugin.json 検査の回帰テスト

テストケースの ID 採番と報告は rule `test-conventions` に従う。
ID は CP-<連番>。

実行: `python3 test_check_plugin.py`(同ディレクトリから)
"""

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import check_plugin

BASE_MANIFEST = {
    "name": "shared-skills",
    "version": "0.2.44",
    "description": "test plugin",
}


def valid_manifest(**overrides):
    data = copy.deepcopy(BASE_MANIFEST)
    data.update(overrides)
    return data


class TestPluginJsonValidation(unittest.TestCase):
    """plugin.json の型検査(CP-01, CP-02, CP-04〜CP-07, CP-12, CP-30〜CP-34)"""

    def assert_valid(self, data, *, root=None):
        self.assertEqual([], check_plugin.validate_plugin_json(data, root=root))

    def assert_invalid(self, data, *needles, root=None):
        errors = check_plugin.validate_plugin_json(data, root=root)
        self.assertTrue(errors)
        for needle in needles:
            self.assertTrue(
                any(needle in error for error in errors),
                f"{needle!r} を含むエラーがありません: {errors}",
            )

    def test_cp_01_必須項目だけのmanifestは有効(self):
        self.assert_valid(BASE_MANIFEST)

    def test_cp_02_公式仕様の10フィールドのみを含むmanifestは有効(self):
        self.assert_valid(
            valid_manifest(
                displayName="Shared Skills",
                logo="assets/logo.png",
                suggestedPrompts=["プロンプト1", "プロンプト2"],
                disabled=False,
                author={
                    "name": "Tkg-tamagohan",
                    "url": "https://example.com",
                },
                homepage="https://github.com/Tkg-tamagohan/devin-plugins",
                repository={
                    "type": "git",
                    "url": "https://github.com/Tkg-tamagohan/devin-plugins",
                },
            )
        )

    def test_cp_04_必須項目の欠落を検出する(self):
        for key in ("name", "version", "description"):
            with self.subTest(key=key):
                data = copy.deepcopy(BASE_MANIFEST)
                del data[key]
                self.assert_invalid(data, f"{key} がありません")

    def test_cp_05_必須項目の型違反を検出する(self):
        for key in ("name", "version", "description"):
            with self.subTest(key=key):
                self.assert_invalid(
                    valid_manifest(**{key: 123}), f"{key} は文字列である必要があります"
                )

    def test_cp_06_authorの型違反を検出する(self):
        self.assert_valid(valid_manifest(author="Tkg-tamagohan"))
        self.assert_valid(valid_manifest(author={"name": "Tkg-tamagohan"}))
        self.assert_invalid(
            valid_manifest(author=""),
            "author は空でない文字列またはオブジェクトである必要があります",
        )
        self.assert_invalid(
            valid_manifest(author=123),
            "author は空でない文字列またはオブジェクトである必要があります",
        )
        self.assert_invalid(
            valid_manifest(author={"name": 123}),
            "author.name は空でない文字列である必要があります",
        )
        self.assert_invalid(
            valid_manifest(author={"url": "https://example.com"}),
            "author.name は空でない文字列である必要があります",
        )
        self.assert_invalid(
            valid_manifest(author={"name": "Tkg", "url": ""}),
            "author.url は https:// で始まる URL である必要があります",
        )

    def test_cp_07_文字列メタデータとAGY独自フィールドの型違反を検出する(self):
        for bad in (123, ""):
            with self.subTest(key="displayName", value=bad):
                self.assert_invalid(
                    valid_manifest(displayName=bad),
                    "displayName は空でない文字列である必要があります",
                )
        self.assert_valid(valid_manifest(homepage="https://example.com"))
        self.assert_invalid(
            valid_manifest(homepage="http://example.com"),
            "homepage は https:// で始まる URL である必要があります",
        )
        self.assert_valid(valid_manifest(repository="https://example.com/repo.git"))
        self.assert_invalid(
            valid_manifest(repository=""),
            "repository は https:// で始まる URL である必要があります",
        )
        self.assert_invalid(
            valid_manifest(repository=123),
            "repository は https:// URL または url を持つオブジェクトである必要があります",
        )
        self.assert_invalid(
            valid_manifest(repository={"type": "git"}),
            "repository.url は https:// で始まる URL である必要があります",
        )
        self.assert_invalid(
            valid_manifest(repository={"type": "", "url": "https://example.com/repo.git"}),
            "repository.type は空でない文字列である必要があります",
        )
        self.assert_invalid(
            valid_manifest(suggestedPrompts="prompt"),
            "suggestedPrompts は空でない文字列の配列である必要があります",
        )
        self.assert_invalid(
            valid_manifest(suggestedPrompts=["ok", ""]),
            "suggestedPrompts は空でない文字列の配列である必要があります",
        )
        self.assert_invalid(
            valid_manifest(suggestedPrompts=["1", "2", "3", "4"]),
            "suggestedPrompts は最大 3 件までです",
        )
        self.assert_invalid(
            valid_manifest(disabled="true"),
            "disabled は真偽値である必要があります",
        )

    def test_cp_12_トップレベルがオブジェクトでない場合を検出する(self):
        for data in ([], "plugin.json", None):
            with self.subTest(data=data):
                self.assert_invalid(data, "JSON のトップレベルがオブジェクトではありません")

    def test_cp_30_versionがSemVer形式でない場合は検出する(self):
        for bad in (
            "0.4.14-beta",
            "1.2",
            "1.2.x",
            "v1.2.3",
            " 1.2.3 ",
            "0.4.015",
            "01.2.3",
            "0.04.14",
            "０.4.14",
            "0.４.14",
            "0.4.14\n",
        ):
            with self.subTest(bad=bad):
                self.assert_invalid(valid_manifest(version=bad), "SemVer(X.Y.Z)")
        for good in ("0.0.0", "0.4.14", "1.0.0", "10.20.30"):
            with self.subTest(good=good):
                self.assert_valid(valid_manifest(version=good))

    def test_cp_31_公式10キー以外のトップレベルキーを拒否する(self):
        for key, value in (
            ("license", "MIT"),
            ("keywords", ["agy"]),
            ("platforms", ["cloud"]),
            ("skills", ["skills"]),
            ("requiredPlugins", ["owner/repo"]),
            ("optionalPlugins", ["owner/repo"]),
            ("forbiddenPlugins", ["owner/repo"]),
            ("mcpServers", {"linear": {"command": "npx"}}),
            ("unknownField", "x"),
        ):
            with self.subTest(key=key):
                self.assert_invalid(
                    valid_manifest(**{key: value}),
                    f"公式仕様外のトップレベルキー {key!r} があります",
                )

    def test_cp_32_plugin_jsonのnameのケバブケース違反を検出する(self):
        for bad in ("SharedSkills", "shared_skills", "shared skills"):
            with self.subTest(name=bad):
                self.assert_invalid(
                    valid_manifest(name=bad),
                    "name は小文字英数字とハイフンのみである必要があります",
                )

    def test_cp_33_logoの形式違反と未存在ファイルを検出し実在ファイルを通過させる(self):
        for bad, needle in (
            ("", "logo は空でない文字列である必要があります"),
            (123, "logo は空でない文字列である必要があります"),
            ("https://example.com/logo.png", "logo に URL は指定できません"),
            ("//example.com/logo.png", "logo に URL は指定できません"),
            ("assets\\logo.png", "logo にバックスラッシュ"),
            ("/assets/logo.png", "logo に絶対パスは指定できません"),
            ("C:/logo.png", "logo に絶対パスは指定できません"),
            ("../logo.png", "logo がプラグインディレクトリ外を参照しています"),
            ("assets/logo.gif", "logo の拡張子は"),
            ("assets/logo.PNG", "logo の拡張子は"),
        ):
            with self.subTest(logo=bad):
                self.assert_invalid(valid_manifest(logo=bad), needle)

        root = Path(tempfile.mkdtemp(prefix="cp-logo-test-"))
        self.addCleanup(shutil.rmtree, root, True)
        self.assert_invalid(
            valid_manifest(logo="assets/logo.png"),
            "logo のファイルが見つかりません",
            root=root,
        )
        (root / "assets").mkdir()
        (root / "assets" / "logo.png").write_bytes(b"png")
        self.assert_valid(valid_manifest(logo="assets/logo.png"), root=root)

    def test_cp_34_homepageとrepositoryとauthorのURLおよび未知キー違反を検出する(self):
        self.assert_invalid(
            valid_manifest(homepage="http://example.com"),
            "homepage は https:// で始まる URL である必要があります",
        )
        self.assert_invalid(
            valid_manifest(repository="http://example.com/repo.git"),
            "repository は https:// で始まる URL である必要があります",
        )
        self.assert_invalid(
            valid_manifest(repository={"type": "git", "url": "http://example.com", "branch": "main"}),
            "repository に公式仕様外のキー 'branch' があります",
            "repository.url は https:// で始まる URL である必要があります",
        )
        self.assert_invalid(
            valid_manifest(author={"name": "Tkg", "email": "a@example.com", "url": "http://example.com"}),
            "author に公式仕様外のキー 'email' があります",
            "author.url は https:// で始まる URL である必要があります",
        )


SAMPLE_README = """# test plugin

## 収録内容

### ルール

| ルール | 読み込まれる状況 |
| --- | --- |
| `sample-rule` | 説明 |

### スキル

| スキル | 内容 |
| --- | --- |
| `sample-skill` | 説明 |
"""

SAMPLE_RULE = """---
trigger: always_on
description: テスト用のルール
---

# テスト用のルール

## 手順

1. 手順

## 対象外

- なし
"""

SAMPLE_SKILL = """---
name: sample-skill
description: テスト用のスキル
---

# テスト用のスキル
"""


def write_plugin_json(root: Path, data: dict) -> None:
    path = root / "plugin.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def make_valid_repo(*, init_git: bool = False) -> Path:
    """構造検査を通過する最小のプラグインリポジトリを一時ディレクトリに作る。"""
    root = Path(tempfile.mkdtemp(prefix="check-plugin-test-"))
    (root / "rules").mkdir()
    (root / "rules" / "AGENTS.md").write_text(
        "# AGENTS.md\n\n## 方針\n1 行目\n", encoding="utf-8"
    )
    (root / "rules" / "sample-rule.md").write_text(SAMPLE_RULE, encoding="utf-8")
    (root / "skills" / "sample-skill").mkdir(parents=True)
    (root / "skills" / "sample-skill" / "SKILL.md").write_text(
        SAMPLE_SKILL, encoding="utf-8"
    )
    (root / "README.md").write_text(SAMPLE_README, encoding="utf-8")
    write_plugin_json(root, valid_manifest(version="1.2.3"))
    if init_git:
        for args in (
            ("init", "-q"),
            ("config", "user.email", "test@example.com"),
            ("config", "user.name", "test"),
            ("add", "-A"),
            ("commit", "-qm", "init"),
            ("tag", "base"),
        ):
            subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)
    return root


class TestCheckPluginStructure(unittest.TestCase):
    """構造検査、状態行検査、README 双方向同期、version バンプ検査(CP-13〜CP-22, CP-35〜CP-37)"""

    def make_repo(self, *, init_git: bool = False) -> Path:
        root = make_valid_repo(init_git=init_git)
        self.addCleanup(shutil.rmtree, root, True)
        return root

    def run_git(self, root: Path, *args: str) -> None:
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)

    def test_cp_13_最小有効リポジトリは全構造検査を通過する(self):
        root = self.make_repo()
        self.assertEqual([], check_plugin.check_rules(root))
        self.assertEqual([], check_plugin.check_skills(root))
        self.assertEqual([], check_plugin.check_agents(root))
        self.assertEqual([], check_plugin.check_readme(root))
        self.assertEqual([], check_plugin.check_docs(root))
        self.assertEqual([], check_plugin.check_plugin_json(root))
        self.assertEqual([], check_plugin.check_hooks_json(root))

    def test_cp_14_ルール規約違反とPOSIXパス表記を検出する(self):
        root = self.make_repo()
        (root / "rules" / "Bad_Name.md").write_text(
            "\n".join(["本文"] * 31) + "\n", encoding="utf-8"
        )
        (root / "rules" / "partial-rule.md").write_text(
            "---\nother: value\n---\n\n# 見出し\n\n## 対象外\n",
            encoding="utf-8",
        )
        errors = check_plugin.check_rules(root)
        for needle in (
            "rules/Bad_Name.md: ファイル名が小文字英数字とハイフンのみではありません",
            "rules/Bad_Name.md: frontmatter がありません",
            "rules/Bad_Name.md: 31 行は上限 30 行を超えています",
            "rules/Bad_Name.md: 命令形の見出し(# ...)がありません",
            "rules/Bad_Name.md: 「## 手順」節がありません",
            "rules/Bad_Name.md: 「## 対象外」節がありません",
            "rules/partial-rule.md: frontmatter に trigger がありません",
            "rules/partial-rule.md: frontmatter に description がありません",
            "rules/partial-rule.md: 「## 手順」節がありません",
        ):
            self.assertIn(needle, errors)
        self.assertTrue(all("\\" not in e.split(":", 1)[0] for e in errors))

    def test_cp_15_スキル規約違反を検出する(self):
        root = self.make_repo()
        (root / "skills" / "Bad_Skill").mkdir()
        long_body = "\n".join(["本文"] * 201) + "\n"
        (root / "skills" / "wrong-skill").mkdir()
        (root / "skills" / "wrong-skill" / "SKILL.md").write_text(
            f"---\nname: other-name\n---\n{long_body}",
            encoding="utf-8",
        )
        errors = check_plugin.check_skills(root)
        for needle in (
            "skills/Bad_Skill: ディレクトリ名が小文字英数字とハイフンのみではありません",
            "skills/Bad_Skill: SKILL.md がありません",
            "skills/wrong-skill/SKILL.md: frontmatter の name(other-name)がディレクトリ名(wrong-skill)と一致しません",
            "skills/wrong-skill/SKILL.md: frontmatter に description がありません",
            "skills/wrong-skill/SKILL.md: 204 行は上限 200 行を超えています",
        ):
            self.assertIn(needle, errors)
        self.assertTrue(all("\\" not in e.split(":", 1)[0] for e in errors))

    def test_cp_16_agents_mdの節行数上限超過を検出する(self):
        root = self.make_repo()
        body_ok = "\n".join(f"{i} 行目" for i in range(1, 6))
        body_over = "\n".join(f"{i} 行目" for i in range(1, 7))
        (root / "rules" / "AGENTS.md").write_text(
            f"# AGENTS.md\n\n## 許可節\n{body_ok}\n\n\n## 超過節\n{body_over}\n",
            encoding="utf-8",
        )
        errors = check_plugin.check_agents(root)
        self.assertEqual(
            ["rules/AGENTS.md: 節「超過節」の本文 6 行は上限 5 行を超えています"],
            errors,
        )

    def test_cp_17_readme収録一覧の掲載漏れを検出する(self):
        root = self.make_repo()
        (root / "rules" / "missing-rule.md").write_text(SAMPLE_RULE, encoding="utf-8")
        (root / "skills" / "missing-skill").mkdir()
        (root / "skills" / "missing-skill" / "SKILL.md").write_text(
            SAMPLE_SKILL, encoding="utf-8"
        )
        errors = check_plugin.check_readme(root)
        self.assertEqual(
            [
                "README.md: ルール `missing-rule` が収録一覧の表にありません",
                "README.md: スキル `missing-skill` が収録一覧の表にありません",
            ],
            errors,
        )

    def test_cp_18_readme収録一覧の孤立行を双方向検査で検出する(self):
        root = self.make_repo()
        readme = (root / "README.md").read_text(encoding="utf-8")
        readme = readme.replace(
            "| `sample-rule` | 説明 |",
            "| `ghost-rule` | 孤立ルール |\n| `sample-rule` | 説明 |",
        ).replace(
            "| `sample-skill` | 説明 |",
            "| `ghost-skill` | 孤立スキル |\n| `sample-skill` | 説明 |\n\n#### 例\n\n| 表 |\n| --- |\n| `ignored-example` |\n",
        )
        (root / "README.md").write_text(readme, encoding="utf-8")
        errors = check_plugin.check_readme(root)
        self.assertEqual(
            [
                "README.md: 収録一覧のルール `ghost-rule` に対応するファイルが rules/ にありません",
                "README.md: 収録一覧のスキル `ghost-skill` に対応するディレクトリが skills/ にありません",
            ],
            errors,
        )

    def test_cp_19_docs計画書の状態行の有無と進行中矛盾を検出する(self):
        root = self.make_repo()
        docs_dir = root / "docs"
        docs_dir.mkdir()
        (docs_dir / "notes.md").write_text("# ノート\n\n通常本文のみ\n", encoding="utf-8")
        (docs_dir / "no-status.md").write_text("# 計画A\n\n- [ ] 未完了\n", encoding="utf-8")
        (docs_dir / "stale.md").write_text(
            "# 計画B\n\n状態: 進行中\n\n- [x] 完了済み\n", encoding="utf-8"
        )
        (docs_dir / "done.md").write_text(
            "# 計画C\n\n状態: 完了\n\n- [x] 完了済み\n", encoding="utf-8"
        )
        errors = check_plugin.check_docs(root)
        self.assertEqual(
            [
                "docs/no-status.md: チェックリストを持つ計画書に`状態:` 行(進行中/完了/中断)がありません",
                "docs/stale.md: 全項目がチェック済みですが `状態: 進行中` のままです。完了か中断へ更新してください",
            ],
            errors,
        )

    def test_cp_20_追加と修正はパッチバンプで通過し未更新と降格と非semverを拒否する(self):
        root = self.make_repo(init_git=True)
        (root / "rules" / "added-rule.md").write_text(SAMPLE_RULE, encoding="utf-8")
        self.run_git(root, "add", "-A")
        self.run_git(root, "commit", "-qm", "add rule")

        unchanged = check_plugin.check_version_bump("base", root)
        self.assertTrue(any("変わっていません" in e for e in unchanged), unchanged)

        write_plugin_json(root, valid_manifest(version="1.2.2"))
        downgrade = check_plugin.check_version_bump("base", root)
        self.assertTrue(any("下がっています" in e for e in downgrade), downgrade)

        for bad_ver in ("1.2.x", "1.2.04", "1.2.４", "1.2.4\n"):
            with self.subTest(bad_ver=bad_ver):
                write_plugin_json(root, valid_manifest(version=bad_ver))
                non_semver = check_plugin.check_version_bump("base", root)
                self.assertTrue(
                    any("SemVer ではありません" in e for e in non_semver), non_semver
                )

        missing_ref = check_plugin.check_version_bump("no-such-ref", root)
        self.assertTrue(any("取得できません" in e for e in missing_ref), missing_ref)

        write_plugin_json(root, valid_manifest(version="1.2.4"))
        self.assertEqual([], check_plugin.check_version_bump("base", root))

    def test_cp_21_versioned_contentの削除や改名はマイナー以上のバンプを要求する(self):
        renamed_repo = self.make_repo(init_git=True)
        self.run_git(renamed_repo, "mv", "rules/sample-rule.md", "rules/renamed-rule.md")
        self.run_git(renamed_repo, "commit", "-qm", "rename rule")

        write_plugin_json(renamed_repo, valid_manifest(version="1.2.4"))
        errors = check_plugin.check_version_bump("base", renamed_repo)
        self.assertTrue(any("マイナー以上を上げてください" in e for e in errors), errors)

        write_plugin_json(renamed_repo, valid_manifest(version="1.3.0"))
        self.assertEqual([], check_plugin.check_version_bump("base", renamed_repo))

        removed_repo = self.make_repo(init_git=True)
        self.run_git(removed_repo, "rm", "-q", "skills/sample-skill/SKILL.md")
        self.run_git(removed_repo, "commit", "-qm", "remove skill")

        write_plugin_json(removed_repo, valid_manifest(version="1.2.4"))
        errors = check_plugin.check_version_bump("base", removed_repo)
        self.assertTrue(any("マイナー以上を上げてください" in e for e in errors), errors)

        write_plugin_json(removed_repo, valid_manifest(version="1.3.0"))
        self.assertEqual([], check_plugin.check_version_bump("base", removed_repo))

    def test_cp_22_version対象外パスの削除はパッチバンプで通過する(self):
        root = self.make_repo(init_git=True)
        (root / "docs").mkdir()
        (root / "docs" / "temp.md").write_text("# 一時文書\n", encoding="utf-8")
        self.run_git(root, "add", "-A")
        self.run_git(root, "commit", "-qm", "add doc")
        self.run_git(root, "tag", "base2")

        self.run_git(root, "rm", "-q", "docs/temp.md")
        self.run_git(root, "commit", "-qm", "rm doc")
        write_plugin_json(root, valid_manifest(version="1.2.4"))
        self.assertEqual([], check_plugin.check_version_bump("base2", root))

    def test_cp_35_コードブロックを除外して手順節とスキル見出しの有無を検査する(self):
        root = self.make_repo()
        # コードブロック内だけに # 見出しや ## 手順 がある場合は偽陽性通過させない
        (root / "rules" / "codeblock-only-rule.md").write_text(
            "---\ntrigger: model_decision\ndescription: test\n---\n\n"
            "# 見出し\n\n```markdown\n## 手順\n```\n\n## 対象外\n\n- なし\n",
            encoding="utf-8",
        )
        rule_errors = check_plugin.check_rules(root)
        self.assertIn("rules/codeblock-only-rule.md: 「## 手順」節がありません", rule_errors)

        (root / "skills" / "codeblock-only-skill").mkdir()
        (root / "skills" / "codeblock-only-skill" / "SKILL.md").write_text(
            "---\nname: codeblock-only-skill\ndescription: test\n---\n\n"
            "```markdown\n# 偽の見出し\n```\n",
            encoding="utf-8",
        )
        skill_errors = check_plugin.check_skills(root)
        self.assertIn(
            "skills/codeblock-only-skill/SKILL.md: 名詞句の見出し(# ...)がありません",
            skill_errors,
        )

    def test_cp_36_コードブロック内のスキル相対パスを禁止しportableパスとplugin_authoringを許可する(self):
        root = self.make_repo()
        # plugin-authoring は自己編集用スキルなので除外される
        (root / "skills" / "plugin-authoring").mkdir()
        (root / "skills" / "plugin-authoring" / "SKILL.md").write_text(
            "---\nname: plugin-authoring\ndescription: test\n---\n\n# タイトル\n\n"
            "```bash\npython skills/plugin-authoring/scripts/check_plugin.py\n```\n",
            encoding="utf-8",
        )
        # 他スキルは "$HOME/..." 形式なら通過する
        (root / "skills" / "portable-skill").mkdir()
        (root / "skills" / "portable-skill" / "SKILL.md").write_text(
            "---\nname: portable-skill\ndescription: test\n---\n\n# タイトル\n\n"
            '```bash\npython "$HOME/.gemini/config/plugins/shared-skills/skills/portable-skill/scripts/run.py"\n```\n',
            encoding="utf-8",
        )
        self.assertEqual([], check_plugin.check_skills(root))

        # 他スキルの SKILL.md や references/*.md のコードブロック内相対パスは拒否される
        (root / "skills" / "portable-skill" / "references").mkdir()
        (root / "skills" / "portable-skill" / "references" / "usage.md").write_text(
            "# 参照\n\n```bash\npython skills/portable-skill/scripts/run.py\n```\n"
            "~~~bash\npython skills/portable-skill/presets/p.json\n~~~\n",
            encoding="utf-8",
        )
        errors = check_plugin.check_skills(root)
        self.assertTrue(
            any("skills/portable-skill/references/usage.md:4:" in e for e in errors),
            errors,
        )
        self.assertTrue(
            any("skills/portable-skill/references/usage.md:7:" in e for e in errors),
            errors,
        )

    def test_cp_37_スキルdescriptionの複数行スカラー拒否と合計5000文字上限を検査する(self):
        root = self.make_repo()
        (root / "skills" / "multiline-skill").mkdir()
        (root / "skills" / "multiline-skill" / "SKILL.md").write_text(
            "---\nname: multiline-skill\ndescription: >-\n  folded\n---\n\n# タイトル\n",
            encoding="utf-8",
        )
        (root / "skills" / "pipe-skill").mkdir()
        (root / "skills" / "pipe-skill" / "SKILL.md").write_text(
            "---\nname: pipe-skill\ndescription: |\n  literal\n---\n\n# タイトル\n",
            encoding="utf-8",
        )
        errors = check_plugin.check_skills(root)
        self.assertTrue(
            any("skills/multiline-skill/SKILL.md: description に複数行ブロックスカラー(>)" in e for e in errors),
            errors,
        )
        self.assertTrue(
            any("skills/pipe-skill/SKILL.md: description に複数行ブロックスカラー(|)" in e for e in errors),
            errors,
        )

        # 合計 5,000 文字超過を検出する
        root_over = self.make_repo()
        (root_over / "skills" / "long-skill").mkdir()
        (root_over / "skills" / "long-skill" / "SKILL.md").write_text(
            f"---\nname: long-skill\ndescription: {'あ' * 5000}\n---\n\n# タイトル\n",
            encoding="utf-8",
        )
        over_errors = check_plugin.check_skills(root_over)
        self.assertTrue(
            any("全スキル description の合計文字数" in e and "上限 5000 文字を超えています" in e for e in over_errors),
            over_errors,
        )


class TestHooksJsonValidation(unittest.TestCase):
    """hooks.json のスキーマ検査・スクリプト実在検査・バンプ検査(CP-23〜CP-29)"""

    def make_repo(self, *, init_git: bool = False) -> Path:
        root = make_valid_repo(init_git=init_git)
        self.addCleanup(shutil.rmtree, root, True)
        return root

    def run_git(self, root: Path, *args: str) -> None:
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)

    def write_hooks(self, root: Path, data: object) -> None:
        (root / "hooks.json").write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

    def test_cp_23_有効なhooks_jsonのグループ形式とフラット形式とmatcherが通過する(self):
        root = self.make_repo()
        (root / "hooks").mkdir()
        (root / "hooks" / "guard.py").write_text("print('ok')\n", encoding="utf-8")
        (root / "hooks" / "post.sh").write_text("echo ok\n", encoding="utf-8")
        (root / "hooks" / "session.py").write_text("print('hi')\n", encoding="utf-8")
        data = {
            "guard-hook": {
                "enabled": True,
                "PreToolUse": [
                    {
                        "matcher": "*",
                        "hooks": [
                            {
                                "type": "command",
                                "command": "python hooks/guard.py",
                                "timeout": 15,
                            }
                        ],
                    },
                    {
                        "matcher": "",
                        "hooks": [{"command": "python hooks/guard.py"}],
                    },
                ],
                "PostToolUse": [
                    {
                        "matcher": "run_command|view_file",
                        "hooks": [{"type": "command", "command": "./hooks/post.sh"}],
                    }
                ],
            },
            "lifecycle-hook": {
                "SessionStart": [{"command": "python hooks/session.py"}],
                "PreInvocation": [{"command": "echo pre"}],
                "PostInvocation": [{"command": "echo post", "timeout": 5}],
                "Stop": [{"command": "echo stop"}],
            },
        }
        self.write_hooks(root, data)
        self.assertEqual([], check_plugin.check_hooks_json(root))

    def test_cp_24_不正なJSONとトップレベル型違反と空フック名を検出する(self):
        root = self.make_repo()
        (root / "hooks.json").write_text("{invalid json", encoding="utf-8")
        errors = check_plugin.check_hooks_json(root)
        self.assertTrue(any("JSON として解釈できません" in e for e in errors), errors)

        for bad in ([], "hooks"):
            with self.subTest(data=bad):
                errors = check_plugin.validate_hooks_json(bad)
                self.assertTrue(
                    any("トップレベルがオブジェクトではありません" in e for e in errors),
                    errors,
                )

        errors = check_plugin.validate_hooks_json({"": {}, "bad-spec": []})
        self.assertTrue(any("フック名は空でない文字列" in e for e in errors), errors)
        self.assertTrue(any("hooks.json.bad-spec はオブジェクト" in e for e in errors), errors)

    def test_cp_25_未知イベントと未知キーとグループフラット誤用を検出する(self):
        data = {
            "bad-hook": {
                "enabled": "true",
                "UnknownEvent": [],
                "PreToolUse": [
                    {"type": "command", "command": "echo flat-in-grouped"},
                    {"matcher": "*", "hooks": [{"command": "echo ok", "async": True}], "extra": 1},
                ],
                "SessionStart": [
                    {"matcher": "*", "hooks": [{"command": "echo grouped-in-flat"}]}
                ],
            }
        }
        errors = check_plugin.validate_hooks_json(data)
        for needle in (
            "enabled は真偽値である必要があります",
            "未知のキー 'UnknownEvent'",
            "PreToolUse[0] に未知のキー 'command'",
            "PreToolUse[0].matcher は文字列",
            "PreToolUse[0].hooks は配列",
            "PreToolUse[1] に未知のキー 'extra'",
            "PreToolUse[1].hooks[0] に未知のキー 'async'",
            "SessionStart[0] に未知のキー 'matcher'",
            "SessionStart[0].command は空でない文字列",
        ):
            self.assertTrue(any(needle in e for e in errors), f"{needle!r} missing in {errors}")

    def test_cp_26_ハンドラのtypeとcommandとtimeoutの型違反を検出する(self):
        data = {
            "h": {
                "PreInvocation": [
                    {"type": "http", "command": "   ", "timeout": True},
                    {"command": "echo ok", "timeout": 0},
                    {"command": "echo ok", "timeout": -3},
                    {"command": "echo ok", "timeout": "10"},
                ]
            }
        }
        errors = check_plugin.validate_hooks_json(data)
        self.assertTrue(any("type は 'command' のみ" in e for e in errors), errors)
        self.assertTrue(any("command は空でない文字列" in e for e in errors), errors)
        self.assertEqual(
            4, sum(1 for e in errors if "timeout は正の整数である必要があります" in e), errors
        )

    def test_cp_27_コマンド文字列内のスクリプト実在検査と誤検出防止を確認する(self):
        root = self.make_repo()
        (root / "hooks").mkdir()
        (root / "hooks" / "ok.py").write_text("print('ok')\n", encoding="utf-8")

        valid_data = {
            "ok-commands": {
                "PreInvocation": [
                    {"command": "python hooks/ok.py || exit 0"},
                    {"command": "python -m unittest"},
                    {"command": 'python -c "print(1)"'},
                    {"command": 'python -Bc "print(1)"'},
                    {"command": "echo ok"},
                ]
            }
        }
        self.write_hooks(root, valid_data)
        self.assertEqual([], check_plugin.check_hooks_json(root))

        bad_commands = [
            ("python hooks/missing.py", "参照スクリプトが見つかりません"),
            ("python ../outside.py", "プラグインディレクトリ外を参照しています"),
            (r"python hooks\ok.py", "バックスラッシュ"),
            ("python $PLUGIN_ROOT/hooks/ok.py", "$PLUGIN_ROOT"),
            ("python %PLUGIN_ROOT%/hooks/ok.py", "%PLUGIN_ROOT%"),
            ('python "hooks/ok.py', "引用符が閉じられていません"),
        ]
        for cmd, needle in bad_commands:
            with self.subTest(command=cmd):
                self.write_hooks(
                    root, {"bad": {"PreInvocation": [{"command": cmd}]}}
                )
                errors = check_plugin.check_hooks_json(root)
                self.assertTrue(
                    any(needle in e for e in errors),
                    f"{needle!r} missing for {cmd!r}: {errors}",
                )

    def test_cp_28_無効化フックでも構文違反とスクリプト欠損を検出する(self):
        root = self.make_repo()
        data = {
            "disabled-hook": {
                "enabled": False,
                "PreToolUse": [
                    {
                        "matcher": "run_command",
                        "hooks": [
                            {
                                "type": "invalid",
                                "command": "python hooks/missing.py",
                            }
                        ],
                    }
                ],
            }
        }
        self.write_hooks(root, data)
        errors = check_plugin.check_hooks_json(root)
        self.assertTrue(any("type は 'command' のみ" in e for e in errors), errors)
        self.assertTrue(any("参照スクリプトが見つかりません" in e for e in errors), errors)

    def test_cp_29_hooks_json削除改名時のマイナーバンプ要求と実リポジトリ検査を確認する(self):
        self.assertEqual([], check_plugin.check_hooks_json(check_plugin.REPO_ROOT))

        root = self.make_repo(init_git=True)
        (root / "hooks").mkdir()
        (root / "hooks" / "guard.py").write_text("print('ok')\n", encoding="utf-8")
        self.write_hooks(
            root,
            {"g": {"PreInvocation": [{"command": "python hooks/guard.py"}]}},
        )
        self.run_git(root, "add", "-A")
        self.run_git(root, "commit", "-qm", "add hooks")
        self.run_git(root, "tag", "base-hooks")

        # 削除時はパッチバンプを拒否し、マイナーバンプで通過する
        removed_repo = root
        self.run_git(removed_repo, "rm", "-q", "hooks.json")
        self.run_git(removed_repo, "commit", "-qm", "remove hooks")
        write_plugin_json(removed_repo, valid_manifest(version="1.2.4"))
        errors = check_plugin.check_version_bump("base-hooks", removed_repo)
        self.assertTrue(any("マイナー以上を上げてください" in e for e in errors), errors)

        write_plugin_json(removed_repo, valid_manifest(version="1.3.0"))
        self.assertEqual([], check_plugin.check_version_bump("base-hooks", removed_repo))

        # 改名時も同様にマイナーバンプを要求する
        renamed_repo = self.make_repo(init_git=True)
        (renamed_repo / "hooks").mkdir()
        (renamed_repo / "hooks" / "guard.py").write_text("print('ok')\n", encoding="utf-8")
        self.write_hooks(
            renamed_repo,
            {"g": {"PreInvocation": [{"command": "python hooks/guard.py"}]}},
        )
        self.run_git(renamed_repo, "add", "-A")
        self.run_git(renamed_repo, "commit", "-qm", "add hooks")
        self.run_git(renamed_repo, "tag", "base-hooks-mv")
        self.run_git(renamed_repo, "mv", "hooks.json", "hooks.bak.json")
        self.run_git(renamed_repo, "commit", "-qm", "rename hooks")
        write_plugin_json(renamed_repo, valid_manifest(version="1.2.4"))
        errors = check_plugin.check_version_bump("base-hooks-mv", renamed_repo)
        self.assertTrue(any("マイナー以上を上げてください" in e for e in errors), errors)

        write_plugin_json(renamed_repo, valid_manifest(version="1.3.0"))
        self.assertEqual([], check_plugin.check_version_bump("base-hooks-mv", renamed_repo))


if __name__ == "__main__":
    unittest.main()
