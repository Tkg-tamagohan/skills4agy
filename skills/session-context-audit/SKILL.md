---
name: session-context-audit
description: Antigravity 過去ログを横断解析し、トークン消費、キャッシュ率、ルール遵守、品質非退行と Decision 1 層別比較を集計する手順。導入効果の定量確認や消費過多の診断時に使用する。引き継ぎメモ作成は session-handoff、可視化形式選択は output-format-escalation に委ねる。
---

# 過去セッションのコンテキスト監査と効果測定

ローカルに蓄積された Antigravity の過去セッションログを横断解析し、コンテキスト制御ルールや運用変更による効果を定量測定する。
既定では外部通信を行わず、Python 標準ライブラリのみでコスト、行動、品質非退行の 3 軸を集計する。
オプトインの `--classify-decision1` を付けると、タスク種別の偏りや文脈不足の兆候を出力トークン 0 で層別比較できる。

## 責任範囲の境界

- **進行中セッションの引き継ぎ**：現在の会話を区切って次セッションへ渡す軽量メモ作成は `session-handoff` に委ねる。
- **過去セッションの語句検索**：別会話で下した決定、却下案、エラー原因の原文を探す作業は `session-log-search` に委ねる。
- **Decisions API の一般仕様**：エンドポイント仕様や質問型の詳細は `gemini-decisions-api` に委ねる。
- **API キーの発行と登録**：`GEMINI_API_KEY` の取得と環境変数設定の案内は `scoped-secret-provisioning` に委ねる。
- **Windows シェルの実行制約**：UTF-8 設定やパス引用の回避策は `windows-cli-pitfalls` に委ねる。
- **出力形式の選択と使い捨て納品**：Markdown 表から対話的可視化へ上げる判断と使い捨て成果物の扱いは `output-format-escalation` に委ねる。
- **HTML ウィジェットの作成規約**：単一ファイル HTML の構成とテーマ変数は builtin の `generative_ui` に委ねる。

## 前提とするログ仕様（2026-11 版）

- **対象ディレクトリ**：既定で `~/.gemini/antigravity/brain/<conversation-id>/.system_generated/logs/transcript.jsonl`（および大出力の実サイズ参照用の `transcript_full.jsonl`）を読み込む。
- **トークン計算**：各 `PLANNER_RESPONSE` の `input_tokens` が新規入力分、`cache_read_tokens` がキャッシュ読込分であるため、総コンテキストは両者の和、キャッシュヒット率は `cache_read_tokens / (input_tokens + cache_read_tokens)` で算出する。
- **親子分離**：`.system_generated/subagents/<id>.json` の存在と `USER_INPUT` 数、Swarm ツール有無により、通常親、Swarm 親、通常サブエージェント、Swarm ワーカー、空セッションを排他分類する。

## 手順

1. まず既定の第 1 段（オフライン集計）を実行し、全体傾向と前後比較を確認する。
   - ルール変更のコミット時刻などを基準に `--cutoff`（タイムゾーン付き ISO 8601）を指定する。
   - 親セッションと子セッションの混在を避けるため、既定の `--scope parent` を維持し、必要なら `--only-with-edits` で編集を含むセッションへ絞る。

```powershell
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
# 全体および編集あり限定での前後比較（Markdown 出力）
python "$HOME/.gemini/config/plugins/shared-skills/skills/session-context-audit/scripts/audit_context_metrics.py" `
  --cutoff 2026-11-21T10:13:36Z `
  --scope parent `
  --format markdown

# 特定モデルへの絞り込みと JSON 出力
python "$HOME/.gemini/config/plugins/shared-skills/skills/session-context-audit/scripts/audit_context_metrics.py" `
  --cutoff 2026-11-21T10:13:36Z `
  --scope parent `
  --only-with-edits `
  --model gemini-4-neon `
  --format json
```

2. 特定セッションの消費過多を掘り下げるときは、`top_offenders` に出た ID を `--session-id` へ渡して単一診断する。
   - `transcript_full.jsonl` の遅延参照を省いて高速化したい場合だけ `--no-full-lookup` を併用する。
   - サブエージェント側の消費内訳を確認するときは `--scope subagent` を実行し、`by_subagent_type` 表で組み込み `DeepCoder*` 系ワーカーと `research` や Swarm ワーカーの比率を切り分ける。

3. タスク種別の交絡バイアスを除いた比較や文脈不足の兆候を見たいときは、先に `--dry-run` でチャンク数と推定文字数を確かめてから `--classify-decision1` を実行する。
   - 1 チャンクは `--chunk-size`（範囲 `1`〜`200`、既定 `100`）と `160,000` 文字上限、および総ペイロード文字数上限 `280,000`（256K トークン上限対策）で分割され、既定の `--max-chunks` は `10`、出力トークンは `0` である。
   - 採用信頼度閾値の既定値は全 3 指標とも `0.70` であり、`--min-confidence` 単独明示時は全指標へその値を適用し、`--task-type-min-confidence` 指定時は `task_type` のみ個別に上書きできる。
   - 親セッション 200 件規模なら、既定の `--chunk-size 100` で 2〜3 チャンク（入力トークン目安数万〜十数万、実アカウントの無料枠対象可否は実行前に `--dry-run` で規模確認すること）で完了し、小チャンク分割が必要な場合のみ `--chunk-size 40` などを指定する。
   - 安全フィルタ遮断時は該当チャンクのみ最大深さ 2 で二分再送し（連続二分下限 `min(10, max(1, chunk_size // 2))`）、隔離できない最小単位だけを `blocked` とする。
   - API キー未設定や通信障害時は警告を標準エラーへ出し、第 1 段レポートを出力して終了コード `3` で抜ける。

```powershell
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
# 送信前の事前検査（API キー不要）
python "$HOME/.gemini/config/plugins/shared-skills/skills/session-context-audit/scripts/audit_context_metrics.py" `
  --cutoff 2026-11-21T10:13:36Z `
  --scope parent `
  --classify-decision1 `
  --dry-run

# 実 API 呼び出し（環境変数 GEMINI_API_KEY を参照、既定閾値は全指標 0.70）
python "$HOME/.gemini/config/plugins/shared-skills/skills/session-context-audit/scripts/audit_context_metrics.py" `
  --cutoff 2026-11-21T10:13:36Z `
  --scope parent `
  --classify-decision1

# task_type 閾値だけを個別に緩和または厳格化する場合
python "$HOME/.gemini/config/plugins/shared-skills/skills/session-context-audit/scripts/audit_context_metrics.py" `
  --cutoff 2026-11-21T10:13:36Z `
  --scope parent `
  --classify-decision1 `
  --min-confidence 0.75 `
  --task-type-min-confidence 0.65
```

### インタラクティブ HTML レポートの構成ガイド（使い捨て運用）

Before/After の多軸比較やモデル別フィルタを操作して確認したいときは、専用ジェネレータをリポジトリへ常設せず、`--format json` の出力を入力にして使い捨て HTML Artifact を作成する。
形式選択と配置先は `output-format-escalation`、テーマ変数や描画規約は builtin の `generative_ui` に従う。

- **Before/After 3 軸 KPI カード**：`comparison.before` と `comparison.after`（および `*_with_edits`）の P50 と `delta_pct` を恩恵、行動、対価の 3 軸で並べる。
- **モデル別フィルタと `[low-n]` バッジ**：`comparison.by_model` をモデル名で絞り込み、`low_sample: true` の行へ注意バッジを表示する。
- **`by_subagent_type` 構成比**：`--scope subagent` や `all` の結果があるときに `token_share`、加重キャッシュ率、ピーク P50 の内訳を示す。
- **`top_offenders` のソートと絞り込み表**：`peak_context_tokens`、`redundant_rereads`、`large_cmd_outputs`、`turns_to_first_edit` で並べ替えて `--session-id` 診断対象を絞る。

## 出力指標と意思決定の読み方

| 区分 | 指標 | 確認する意味 |
| --- | --- | --- |
| **恩恵** | 初回編集前コンテキストとピーク P50 | 編集着手前の過剰先読みとセッション上限圧迫が抑えられたかを測る |
| **恩恵** | キャッシュヒット率（セッション別と加重） | プロンプトキャッシュが維持されているかを測る |
| **行動** | 200 行超コード盲目読込率 | `StartLine` と `EndLine` なしでのコード全読みが減ったかを測る（仕様書や設定 JSON は除外） |
| **行動** | 検索先行率、並列バースト、10 KB 超コマンド率 | 狭い検索から入る規律とターミナル出力制御が守られているかを測る |
| **内訳** | サブエージェント種別内訳（`by_subagent_type`） | 種別ごとのトークン占有率、加重キャッシュ率、ピーク P50 から負荷源を切り分ける |
| **対価** | 初回編集ターン数と秒数 | 分割読込や事前検索で往復が増えすぎていないかを監視する |
| **対価** | 重複再読セッション率と編集失敗率 | 順方向の 200 行分割、非重複の前方ジャンプ、および `edit_file` や `write_file` 成功後の確認再読は除外し、未編集ファイルへの重複範囲再読と文脈不足による失敗増を監視する |

- **判断基準**：初回編集前コンテキストやピークの P50 が下がり、同時に `turns_to_first_edit` の悪化や `edit_error_rate`、`redundant_reread_rate`、`context_starvation` の急増がない状態を有効とみなす。
- **交絡対策**：モデル構成比や作業内容の偏りを無視して単一数値だけで結論付けず、編集あり限定、主要モデル別、`by_task_type`、および `[low-n]` 注記を並べて判断する。

## 原則

- 既定レポート（Markdown、JSON、標準エラー）には生プロンプト、`thinking`、ファイル本文、フルパス、シークレットを含めない。
- 過去ログの自然比較には交絡が残るため、全件平均ではなく中央値（P50）、P90、モデル別内訳、編集あり層を併記して解釈する。
- Decision 1 はオプトインに留め、`--max-chunks` 超過時は比較バイアスを防ぐため切り捨てずに停止する。
