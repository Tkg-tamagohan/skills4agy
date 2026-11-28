---
name: invariant-gate
description: git diff とルール文書を Gemini Decision 1 で一括突合し、規約違反候補を抽出する。PR 前や実装完了時の差分検査、または invariants.json や --questions-file 用の質問作成や改訂時に使用する。API 仕様は gemini-decisions-api、常駐システム監査は systems-pre-pr-audit に委ねる。
---

# Gemini Decision 1 による汎用不変条件検査

任意のリポジトリの `git diff` とルール文書を 1 回の `gemini-decision-1` 呼び出し（出力トークン 0、最大 1,000 問並列）で突合し、違反候補と警告を抽出する。
対象リポジトリ側の事前設定は不要であり、候補が挙がった項目だけを実コードと照合して二次精査することで、レビューの見落としと確認コストを同時に抑える。

## 責任範囲の境界

- **Decisions API の一般仕様と汎用バッチ CLI**：`gemini-decisions-api` に委ねる。
  - 本スキルは `git diff` とルール文書の突合に特化し、REST 送信と事前検証の共通処理は `skills/gemini-decisions-api/scripts/run_decisions.py` を再利用する。
- **常駐システム境界の監査観点**：`systems-pre-pr-audit` に委ねる。
  - `--preset systems-pre-pr`（または `--rules`）で同スキルの Markdown を追加投入できる。
- **API キーの発行と環境変数設定**：`scoped-secret-provisioning` に委ねる。
  - 環境変数 `GEMINI_API_KEY` を前提とし、CLI 引数やファイルへ平文で渡さない。
- **Windows シェルの文字コードと引用作法**：`windows-cli-pitfalls` に委ねる。

## 3 層のルール収集と差分ガード

同梱スクリプト `scripts/check_invariants_decision1.py` は以下の 3 層で質問を構築する。

1. **自動検出（第 1 層）**：対象リポジトリルートから `AGENTS.md`、`GEMINI.md`、`CLAUDE.md`、`.agents/rules/*.md`、`.agent/rules/*.md`、`_agents/rules/*.md`、`_agent/rules/*.md` を昇順で読み込む。
   リポジトリルートにネイティブプラグインのマニフェスト（`plugin.json`、`.antigravity-plugin/plugin.json`、`.gemini-plugin/plugin.json`）または `rules/AGENTS.md` が存在する場合は、`rules/AGENTS.md`、`rules/GEMINI.md`、`rules/*.md` も重複を除いて読み込む。
   いずれも YAML frontmatter、フェンス付きコードブロック内、および除外見出し（`## 対象外`、`## Out of Scope`、`## Non-Goals` 等）節を除いて見出しまたはトップレベル箇条書き単位で抽出する。
2. **追加指定（第 2 層）**：`--rules <path...>` または `--preset systems-pre-pr` で外部や同梱スキルの Markdown（例：`skills/systems-pre-pr-audit/SKILL.md`）を追加投入できる。
3. **カスタム定義（第 3 層）**：対象リポジトリに `.agents/invariants.json`（または `--questions-file <path>`）があれば読み込み、既存キーの上書き、`path_globs` による変更ファイル限定、個別の `threshold` と `warn_threshold` を適用する。

```json
{
  "questions": {
    "py_no_bare_except": {
      "instructions": "Does the Git diff introduce a bare except clause in Python code?",
      "path_globs": ["src/**/*.py"],
      "threshold": 0.75,
      "warn_threshold": 0.45
    }
  }
}
```

カスタム質問（`.agents/invariants.json` や `--questions-file`）を作成または改訂するときは、条件付きガードの適用境界（特定条件の限定対象など）と網羅的禁止条件を実コードと突き合わせ、`instructions`（冒頭質問と本文）および `criteria`（`true_description` / `false_description`）の双方へ一貫して記述する。
`instructions` の冒頭質問や本文と `criteria` の間で条件の抜けや範囲の食い違いがあると、Decision 1（自動判定モデル）の偽陽性や偽陰性を招く。

差分取得では `git -c core.quotePath=false diff --no-ext-diff --unified=15` を UTF-8 で実行し、バイナリ差分とロックファイル（`Cargo.lock`、`package-lock.json`、`pnpm-lock.yaml`、`yarn.lock`、`uv.lock`、`poetry.lock`）を既定除外する。
変更ファイルに `.env` 系（`.env.example` 等の雛形を除く）が含まれる場合、または追加行や文脈行に秘密鍵ヘッダ（`BEGIN ... PRIVATE KEY` 等）や主要 API トークン形式（`AIza...`、`ghp_` や `github_pat_` 等の GitHub トークン、`sk-...`、`AKIA...`、`cog_...`）が含まれる場合は、API 送信前に終了コード `2` で遮断する（エラー出力に実値は出さない）。
テスト用のダミーキーは秘密トークン判定長を下回る短い文字列（例: AIza 以降 20 文字未満）にし、誤って遮断（終了コード 2）を踏まないようにする。
入力文字数が既定上限 `400,000` 文字を超える場合、または質問数が `1,000` 問を超える場合は無言で切り詰めず、終了コード `2` で `--paths` や `--rules` による分割を案内する。

## 実行手順

Windows の PowerShell では実行前に `$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"` を設定する。

```powershell
# 1. キー不要のドライラン（抽出ルールと検証済みペイロードの確認）
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
python "$HOME/.gemini/config/plugins/shared-skills/skills/invariant-gate/scripts/check_invariants_decision1.py" --dry-run

# 2. 現在の作業ツリー差分（git diff HEAD、初期コミット前は --cached）を検査
python "$HOME/.gemini/config/plugins/shared-skills/skills/invariant-gate/scripts/check_invariants_decision1.py"

# 3. PR 向けに main との差分を検査し、JSON 形式で出力
python "$HOME/.gemini/config/plugins/shared-skills/skills/invariant-gate/scripts/check_invariants_decision1.py" --base main --format json

# 4. 常駐システム境界プリセットを追加し、対象パスを絞って厳格モードで検査
python "$HOME/.gemini/config/plugins/shared-skills/skills/invariant-gate/scripts/check_invariants_decision1.py" `
  --base main --paths "src/**" --preset systems-pre-pr --strict

# 5. 任意の外部ルールファイルを直接追加して検査
python "$HOME/.gemini/config/plugins/shared-skills/skills/invariant-gate/scripts/check_invariants_decision1.py" `
  --base main --paths "src/**" --rules "$HOME/.gemini/config/plugins/shared-skills/skills/systems-pre-pr-audit/SKILL.md" --strict
```

`--base <ref>` はコミット済み差分（`base...HEAD`）のみを対象とし、未コミットの変更だけでは `skipped_empty_diff` になるため、追跡済みファイルの未コミット変更には引数なし実行（ステージ済みなら `--staged`）や `--diff-file` を、未追跡ファイルも含む作業ツリー全体の検査には `pr_ops.py invariant-check` を使う。
呼び出し経路は `--backend auto`（既定）で `google-genai >= 3.2.0`（`api_version="v1beta"`）を優先し、`ImportError` または `client.decisions` 不在時は `run_decisions.py` 経由の REST へ自動で切り替える。

## 閾値と終了コード

| 条件 | 分類 | 終了コード |
| --- | --- | --- |
| 空差分、またはルール 0 件（通常時） | スキップ | `0` |
| `--dry-run` 検証成功 | ドライラン完了 | `0` |
| 全項目が `noul < 0.40` | 通過 | `0` |
| `0.40 <= noul < 0.70` が 1 件以上（違反候補なし） | 警告 | `0`（`--strict` 時は `1`） |
| `noul >= 0.70` が 1 件以上 | 違反候補 | `1` |
| `GEMINI_API_KEY` 未設定、秘密情報遮断、上限超過、安全フィルタ遮断、通信失敗、ルール 0 件（`--strict` 時） | 実行エラー | `2` |

## 候補検出時の二次精査手順

`gemini-decision-1` は確率に基づく一次スクリーニングであり、出力をそのまま断定してはいけない。
違反候補（終了コード `1`）または警告が返ったときは、以下の順で実物を裏取りする。

1. 出力された `source_file:start_line-end_line` を開き、該当ルールの原文と適用条件（例外規定や対象範囲）を確認する。
2. `matched_files` の差分と周辺の実コードを読み、ルール違反が実際に成立しているかを一次事実で判定する。
3. 真陽性であれば修正案または修正を実施し、偽陽性であれば理由を簡潔に記録する（繰り返し偽陽性が出る項目は `.agents/invariants.json` の `path_globs` や `threshold` で調整する）。
4. 終了コード `2` が返った場合は原因（キー未設定、`.env` や秘密鍵および API トークンの混入、上限超過、安全遮断）を解消してから再実行する。

## 原則

- 送信前の秘密情報遮断と上限チェックを迂回せず、超過時は `--paths` や `--rules` で分割して実行する。
- 一次スクリーニングの確率だけで違反を断定せず、候補となったルール原文と実コードを必ず照合してから報告または修正する。
- API キーは環境変数 `GEMINI_API_KEY` のみから読み込み、コマンド履歴やログへ露出させない。
