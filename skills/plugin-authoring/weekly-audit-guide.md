# 週次 SKILL 監査ガイド

本ガイドは `shared-skills` プラグインのルールとスキルを毎週点検し、肥大化や陳腐化を早期に抑える手順を定める。
CI（`check_plugin.py`、`check_hygiene.py`、`run_all_tests.py`）は形式と単体テストを毎 PR で担保するため、週次監査では時間経過や実運用でしか現れない 6 つの主眼を扱う。

## 監査の 6 主眼と実行周期

| 主眼 | 扱う対象 | 実行周期 | 一次計測の手段 |
| --- | --- | --- | --- |
| 1. 利用率とコンテキスト収支（重点） | 直近 7 日と 28 日の実利用回数、0 回利用候補、`description` 予算（上限 5,000 文字）、セッション KPI | 毎週 | `audit_skills_weekly.py --include-context-audit` |
| 2. トリガー競合と境界整合 | `description` 語彙重複ペア、委譲リンク切れ、条件ルール 12 件上限の棚卸し | 毎週（競合精査は月次） | `audit_skills_weekly.py` |
| 3. ドリフトと陳腐化 | 文書内 `--flag` と実装 AST の乖離、前提日付と更新経過日数、外部 CLI 仕様変更 | 毎週（外部仕様は月次） | `audit_skills_weekly.py`、任意で `screen_drift_decision1.py docs` |
| 4. 共有結合とフック健全性 | 横断 `import` マップ、テスト件数、`hooks.json` と `pretool_guard` フォールバック回数 | 毎週（テスト棚卸しは月次） | `audit_skills_weekly.py`、`run_all_tests.py` |
| 5. 機械化、統合、廃止（重点） | 決定論的工程のスクリプト化候補、低利用スキルの統合や廃止、開発と本番の同期、放置ブランチ | 毎週 | `audit_skills_weekly.py`、任意で `screen_drift_decision1.py docs` |
| 6. CI 死角の文書衛生 | `rules/AGENTS.md` との重複、`REVIEW.md` 除外パスや `.sloplintignore` の残骸、設計例外の有効性 | 毎週（例外見直しは月次） | `audit_skills_weekly.py`、`check_hygiene.py` |

## 実行手順

1. まず決定論的計測 CLI をオフラインで実行し、全 6 主眼の定量データを取得する。

```powershell
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
python "$HOME/.gemini/config/plugins/shared-skills/skills/plugin-authoring/scripts/audit_skills_weekly.py" `
  --repo "E:\Documents\code\skills4agy" `
  --prod-root "$HOME\.gemini\config\plugins\shared-skills" `
  --days 7 `
  --window-days 28 `
  --include-context-audit `
  --format markdown
```

2. 構造検査、文体衛生、単体テストの現行状態を確認する。

```powershell
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
python "$HOME/.gemini/config/plugins/shared-skills/skills/plugin-authoring/scripts/check_plugin.py"
python "$HOME/.gemini/config/plugins/shared-skills/skills/plugin-authoring/scripts/check_hygiene.py"
python "$HOME/.gemini/config/plugins/shared-skills/skills/plugin-authoring/scripts/run_all_tests.py"
```

3. 環境変数 `GEMINI_API_KEY` が設定されている場合のみ、Decision 1 による陳腐化と機械化の一次スクリーニングを追加する。
   - 送信前に `--dry-run` で件数と文字数を確かめる。
   - キー未設定または通信失敗時はこの段階を省略し、その旨をレポートへ記録して完了する。

```powershell
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
python "$HOME/.gemini/config/plugins/shared-skills/skills/repo-drift-audit/scripts/screen_drift_decision1.py" docs --repo "E:\Documents\code\skills4agy" --dry-run --format table
python "$HOME/.gemini/config/plugins/shared-skills/skills/repo-drift-audit/scripts/screen_drift_decision1.py" docs --repo "E:\Documents\code\skills4agy" --format table
```

4. 取得した定量値と該当スキルの実ファイル照合に基づき、重点 2 軸の判定を下して週次監査レポート Artifact を生成する。

## 重点 2 軸の判定基準

### 利用率とコンテキスト収支

| 観測パターン | 推奨処置 | 確認事項 |
| --- | --- | --- |
| 28 日実利用あり、かつ収支良好 | 維持 | 週次 KPI（`turns_to_first_edit` 等）の悪化がないか追う |
| 28 日実利用あり、かつ `desc_chars > 220` | `description` 圧縮 | 直交スキルへの委譲文を本文 `## 責任範囲の境界` へ移す |
| 28 日実利用あり、かつ `body_lines >= 180` | 補助ファイル分離 | 詳細リファレンスやテンプレートを別ファイルへ逃がす |
| 28 日実利用ゼロ、かつ特定案件特化 | リポジトリ固有化 | 共有プラグインから対象リポジトリの `.agents/skills/` へ移す |
| 28 日実利用ゼロ、かつ隣接スキルと重複 | 統合または廃止 | `guidelines.md` の統合基準に沿って片方へ吸収する |

### 機械化、統合、廃止の判定基準

- **機械化の候補**：手順が番号付きで定型化されており、入力と規約から出力が一意に決まる工程だけをスクリプト化する。
- **モデル側へ残す工程**：仕様の解釈、文章の推敲、文脈に応じた優先順位判断はスクリプト化せず `SKILL.md` に残す。
- **定期実行時の安全制約**：定期実行（`Weekly Skill Audit`）は読み取り専用とし、レポート Artifact の生成だけを行ってコード変更、コミット、PR 作成、本番 `git pull` は自動で行わない。

## 週次監査レポートの標準構成

1. 監査サマリ（実施日時、計測窓、アクティブセッション数、総評）
2. 主眼 1：利用率と常時コンテキスト収支（予算残量、週次 KPI、0 回利用と高コスト一覧）
3. 主眼 5：機械化、統合、廃止の候補と開発同期状態（推奨処置と理由）
4. 主眼 2、3、4、6 の所見（競合ペア、フラグ乖離、結合、フックフォールバック、衛生残骸）
5. 次のアクション分類（自律修正候補、要協議候補と推奨案、先送り事項と再検討条件）
