# AGENTS.md

本ファイルは `skills4agy` リポジトリ固有の運用手順を定める。
全 Antigravity セッションへ常時適用される共通ルールは `rules/AGENTS.md` を参照する。

## ディレクトリ分離構成

| 役割 | パス | 運用ルール |
| --- | --- | --- |
| プラグイン稼働先（本番） | `C:\Users\meshi\.gemini\config\plugins\shared-skills` | `main` ブランチ固定。直接編集やフィーチャーブランチへの切替を行わない |
| PR 作業用クローン | `E:\Documents\code\skills4agy` | 通常の編集、コミット、ブランチ作成、PR 作成はこちらで行う |

## 次回以降の変更手順

1. `E:\Documents\code\skills4agy` で `main` ブランチを最新化する（`git checkout main` → `git pull --ff-only origin main`）。
2. 作業ブランチを作成する（`git checkout -b <branch>`）。
3. ルールやスキルの追加・変更時はスキル `plugin-authoring` に従い、`plugin.json` の `version` と `README.md` の収録一覧を同期する。
4. コミット前に UTF-8 環境変数を設定して検証スクリプトを実行し、全項目と全テストの通過を確認する（プラグイン中身〔`rules/`、`skills/`、`AGENTS.md`、`README.md`、`hooks.json`〕または `plugin.json` の `version` を変更する場合は `--version-base origin/main` を付与し、`.github/` や `.gitignore` のみ変更する場合は省略する）。
   ```powershell
   $env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
   # プラグイン中身または plugin.json の version を変更する場合
   python skills/plugin-authoring/scripts/check_plugin.py --version-base origin/main
   # .github/ や .gitignore のみ変更する場合
   python skills/plugin-authoring/scripts/check_plugin.py
   python skills/plugin-authoring/scripts/run_all_tests.py
   ```
5. 作業ブランチを `git push -u origin <branch>` で push し、PR を作成する。
6. GitHub Actions CI（集約チェック `ci-summary`）および Devin Review の指摘を確認・対応したうえで `main` へマージする。

## PR マージ後の本番反映

- 本番プラグインディレクトリ（`C:\Users\meshi\.gemini\config\plugins\shared-skills`）で以下を実行し、最新 `main` を取り込む。
  ```powershell
  git pull --ff-only origin main
  ```
- 取り込んだルール・スキルは Antigravity の次のターンから自動的に読み込まれる。
