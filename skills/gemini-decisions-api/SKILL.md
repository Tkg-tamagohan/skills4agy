---
name: gemini-decisions-api
description: Gemini Decision 1 によるゼロ出力トークンの確率判定とローカル CLI を扱う。Decisions API の組み込み、質問設計、バッチ判定やドライランを行うときに使用する。不変条件検査は invariant-gate、生成や構造化出力は gemini-api-dev、音声映像は gemini-live-api-dev、動画は gemini-omni-flash-api に委ねる。
---

# Gemini Decision 1（Decisions API）の実装と運用

Decisions API は共有入力に対して型付きの質問マップを 1 回の順伝播で独立評価し、校正済み確率と信頼度を返す。
テキストトークンを生成しないため出力トークン数は常に 0 となり、分岐やルーティングを低遅延かつ低コストに実装できる。
詳細なフィールド定義、対応 MIME タイプ一覧、言語別の完全なコード例は [api-reference.md](references/api-reference.md) を参照する。

## 構成の現在地（2026年11月版）

- **エンドポイント**：`POST https://generativelanguage.googleapis.com/v1beta/decisions`（Beta 提供のため `v1beta` 固定）。
- **モデル ID**：`gemini-decision-1` のみ対応する。
- **SDK 要件**：Python は `google-genai >= 3.2.0`、JavaScript / TypeScript は `@google/genai >= 3.2.0` を要する。
- **上限と課金**：コンテキスト上限は 262,144 トークン、1 リクエスト最大 1,000 問、出力トークンは 0 である。
- **入力トークンの扱い**：共有 `input` は質問数にかかわらず 1 回だけ計上され、各質問は自身の `instructions` と `criteria` の分だけ加算される。
- **非対応機能**：Context Caching、Batch API、Flex / Priority 推論、会話履歴ブロック、thought / tool-call ブロックは使えない。

## 責任範囲の境界

- **git diff とリポジトリ内ルール文書の突合による不変条件の自動検査**：`invariant-gate` に委ねる。
- **テキスト生成、要約、構造化抽出、関数呼び出し**：`gemini-api-dev`（Interactions API）に委ねる。
- **双方向音声と映像のリアルタイム処理**：`gemini-live-api-dev`（Live API）に委ねる。
- **動画の生成と編集**：`gemini-omni-flash-api` に委ねる。
- **API キーの発行手順と環境変数登録**：`scoped-secret-provisioning` に委ねる。
- **Windows シェルでの引用符と文字コード対策**：`windows-cli-pitfalls` に委ねる。

## 3 種の質問型と出力構造

すべての質問は共有 `input` に対して並列かつ独立に評価され、質問同士は互いの内容を参照できない。

| 質問型 | 用途 | `criteria` の指定 | 主な返却フィールド |
| --- | --- | --- | --- |
| `noul` | Yes/No の二値判定 | 任意（`true_description`、`false_description`） | `noul`（`0.01`–`0.99`）、`confidence`（`max(noul, 1 - noul)`） |
| `choice` | 固定候補からの単一選択 | 必須（2–255 個の `key: description` マップ、自明なら `""` 可） | `choice`、`probabilities`、`confidence` |
| `score` | 順序付きルーブリック採点 | 必須（0 始まりの 2–255 段階の非空文字列配列、2–10 段階を推奨） | `score`（確率重み付き期待値）、`legend`、`probabilities`、`confidence` |

`score` の期待値は異なる確率分布から同じ値になりうる。
離散レベルが必要な場面では `probabilities` の最大キーから `legend` を引き、段階数が異なる指標を横並び比較するときは `score / (len(legend) - 1)` で `0.0`–`1.0` に正規化する。

## 実装と質問設計の急所

実装ミスが起きやすい 5 箇所を NG / OK 対比で示す。

### 1. 質問型 `bool` の誤指定と `v1beta` 漏れ

- **NG**：`type: "bool"` を指定する、または既定 API バージョンで `client.decisions.create` を呼ぶ。
- **OK**：二値質問は `type: "noul"` を指定し、クライアント初期化時に `api_version: "v1beta"`（JS は `apiVersion: "v1beta"`）を明示する。

### 2. `noul` の確率上限を超えたデッドコード閾値

- **NG**：`if answer.noul > 0.99:` のように `0.99` 超または `0.01` 未満の条件を書く。
- **OK**：`noul` は `0.01`–`0.99` の範囲に収まるため、ラベル付きデータで偽陽性と偽陰性のコストを比べた上で範囲内に閾値を置く。

### 3. `choice` の UTF-8 バイト順ソートと受け皿設計

API は評価前に選択肢キーを UTF-8 バイト順で整列し、確率が完全に同率のときは辞書順先頭のキーを選ぶ。

- **NG**：位置に依存するキー名 `none_of_the_above` を末尾のつもりで置く（`shipping` や `technical` より前に並ぶ）。
- **OK**：受け皿には位置に依存しない `other` を明示的な説明付きで置くか、`confidence` の閾値判定とスコープ確認の `noul` 質問を組み合わせる。

### 4. モデルに見えないキー名、否定疑問、指数スケール

- **NG**：キー名 `is_not_gold` に頼って `instructions` を省く、否定疑問で尋ねる、または `criteria` を `1, 10, 100, 1000` のような指数スケールにする。
- **OK**：モデルから質問キー名や変数名は見えないため、`instructions` に完全な肯定文の問いを書き、否定が必要なときはコード側で `1 - noul` を計算する。
  - `score` の段階は 0 始まりの線形スケールに揃える。

### 5. 安全フィルタ遮断の二経路対応

安全フィルタによる遮断は、HTTP 400 エラーと HTTP 200 応答の二経路で返る。

- **NG**：HTTP 200 だけを見て `response["answers"]["key"]` を直接参照し、`KeyError` で落とす。
- **OK**：HTTP 400 の JSON `error.code`（`safety`、`prohibited_content`、`blocklist`、`image_safety`、`content_blocked`）と、HTTP 200 の `prompt_feedback.block_reason`（`answers` は空）の両方を検査してフォールバック処理へ渡す。

## 同梱 CLI（`scripts/run_decisions.py`）の使い方

Python 標準ライブラリのみで動作し、送信前のスキーマ検証、`--dry-run`、信頼度閾値によるエスカレーション判定、表形式出力を備える。
API キーは環境変数 `GEMINI_API_KEY` からのみ読み取り、CLI 引数では受け取らない。
誤送信防止のため、`--text-file` と `--questions` に `.env` 系ファイル（`.env.example` 等の雛形を除く）を指定した場合は終了コード `2` で遮断する。

```powershell
# 1. API キー未設定でも可能なドライラン（事前バリデーションとペイロード確認）
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
python "$HOME/.gemini/config/plugins/shared-skills/skills/gemini-decisions-api/scripts/run_decisions.py" `
  --text "注文した青いマグカップが割れて届きました。" `
  --noul "is_damaged=商品は破損して届きましたか？" `
  --choice "queue=どの窓口へ振り分けますか？|billing:請求や返金|replacements:破損や誤配送の交換|other:その他" `
  --dry-run

# 2. 実 API 呼び出し（--min-confidence 未満の回答に needs_escalation を付与）
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
python "$HOME/.gemini/config/plugins/shared-skills/skills/gemini-decisions-api/scripts/run_decisions.py" `
  --text-file ticket.txt --media photo.jpg --resolution low `
  --questions questions.json --min-confidence 0.75 --format table
```

### ハイブリッド PreToolUse ガード（`scripts/pretool_guard.py`）

プラグインルートの `hooks.json`（キー名 `decision1-pretool-guard`、`"enabled": true`）は、`run_command` 実行前に `scripts/pretool_guard.py` を呼び出す。
第 1 段の決定論的ローカル判定が純粋な読み取り、単体テスト、および厳格条件を満たす `origin` 非保護ブランチへの明示的な通常 push（`git push origin <branch>` 等）を即時 `allow`、破壊的操作（force push、既定ブランチ push、`--delete` / `:branch` / `--mirror` 等）を `force_ask`、機密ファイルや `env:` ドライブの外部送信を `deny` で処理し、境界上の曖昧なコマンドだけを機密マスク後に第 2 段の Decision 1 判定へ渡す。
引数を省略した `git push` 単体や `git push origin HEAD` はコマンド文字列から対象ブランチを確定できないため意図的に第 1 段ホワイトリスト外とし、第 2 段判定（要確認）へ送る。
第 1 段のホワイトリスト判定では、`PYTHONUTF8` や `PYTHONIOENCODING` などの安全な定数リテラル環境変数プレフィックス、ローカル FS パス限定の `Set-Location` / `cd` 類（PSDrive、UNC パス、ワイルドカード、`.ssh` や `.aws` 等の機密ディレクトリを除外）、PowerShell 5.1 の定型 fail-fast ガード（`if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }` 等）、`;` と `&&` による許可コマンドの単純連結、および `python -B -m unittest` などの無害な短縮フラグを許容する。
一方で、`git commit` など他の状態変更コマンドや一般の制御構文を 1 回の `run_command` へ混在させると第 1 段の即時許可や IDE 側のコマンド単位許可が適用されにくくなるため、変更系と確認系は別呼び出しへ分離する。
API キー未設定や通信障害時は `ask` へ安全にフォールバックする。

```powershell
# ドライラン確認（API キー不要）
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
python "$HOME/.gemini/config/plugins/shared-skills/skills/gemini-decisions-api/scripts/pretool_guard.py" --dry-run --command "git status"
python "$HOME/.gemini/config/plugins/shared-skills/skills/gemini-decisions-api/scripts/pretool_guard.py" --dry-run --command "git push --force origin feature"
python "$HOME/.gemini/config/plugins/shared-skills/skills/gemini-decisions-api/scripts/pretool_guard.py" --dry-run --command "npm run deploy"
```

フックを一時停止したい場合は `hooks.json` の `"enabled"` を `false` へ切り替え、設定変更後は事前にドライランで判定結果を確認する。

## Interactions API（Structured Outputs）との使い分け

| 判断軸 | Decisions API（`gemini-decision-1`） | Interactions API（Structured Outputs） |
| --- | --- | --- |
| 欲しい結果 | Yes/No 確率、固定候補の選択、段階ルーブリック採点 | 自由文、要約、理由説明、任意スキーマの値抽出 |
| 確率と閾値制御 | 校正済み確率と `confidence` を直接閾値判定できる | 確率分布は得られず、文字列や JSON 出力に依存する |
| 多数ルールの並列検査 | 同一入力に最大 1,000 問を 1 回の呼び出しで独立評価 | 質問を増やすほど出力トークンと遅延が線形に増える |
| 推論とツール実行 | 単発の軽量判定に特化し出力トークン 0 | 多段推論や引数付きツール呼び出しに対応 |

## 原則

- 数値比較、日付差、期間判定はコード側で計算し、結果や区分名をテキストとして `input` へ渡す。
- 関連のない情報を含めると精度が落ちるため、質問に必要なフィールドだけを `input` へ絞る。
- ユーザー入力は自身の分類を誘導する文言を含みうる前提で扱い、高リスクな操作（返金実行やアカウント停止）には `confidence` 閾値と人手確認を残す。
- 隣接する `text` ブロックは区切り文字なしで連結されるため、ブロック間に明示的な改行や空白を入れる。
