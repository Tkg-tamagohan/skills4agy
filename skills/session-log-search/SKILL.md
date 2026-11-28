---
name: session-log-search
description: 終了済み会話のトランスクリプト、作成物、docs、git 履歴を語句検索し、理由、却下案、エラー前後のやり取りを時系列で抜き出す。以前の経緯や障害原因を調べるときに使用する。引き継ぎ作成は session-handoff、消費監査は session-context-audit に委ねる。
---

# 過去会話ログと作成物のステートレス語句検索

過去の Antigravity 会話ログやアーティファクトから、過去の決定理由、却下案、エラー原因を外部依存や永続 DB なしで横断検索する。
ゴールは、呼び出し元の同義語展開と 768 文字窓の Hybrid BM25 を組み合わせ、前後ターンを含む最小限の文脈を 4,500 トークン予算内で時系列に復元することである。

## 責任範囲の境界

- **進行中セッションの引き継ぎ**：現在の会話を区切って次セッションへ渡すメモの作成は `session-handoff` に委ねる。
- **過去セッション横断の定量監査**：蓄積されたセッション群のトークン消費、キャッシュ率、行動指標の集計は `session-context-audit` に委ねる。
- **Windows シェルの実行制約**：UTF-8 環境変数や引用符の扱いに関する回避策は `windows-cli-pitfalls` に委ねる。

## 手順

1. 検索語を 3〜6 語へ展開する。
   - 単一語の完全一致に頼ると表記揺れを取りこぼすため、同義語、症状語、コード識別子、日本語と英語の両表記を並べる。
   - 例として、設計判断を探すなら `却下 理由 なぜ` を、文字化け障害なら `cp932 UnicodeEncodeError PYTHONUTF8` を選ぶ。

2. UTF-8 を有効化して同梱 CLI を実行する。
   - 作業ディレクトリに依存しないよう `"$HOME/.gemini/config/plugins/shared-skills/..."` 形式で呼び出し、自身の会話を除外するため `--exclude-conversation-id` を付ける。
   - ハイフン始まりの検索語をフラグと誤認させないため、検索語の前には必ず `--` を置く。

```powershell
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
# 自分の会話を除外して語句検索する基本例
python "$HOME/.gemini/config/plugins/shared-skills/skills/session-log-search/scripts/search_session_logs.py" `
  --exclude-conversation-id <自分の Conversation ID> `
  -- 却下 理由 なぜ

# リポジトリの docs と直近コミットも合わせて時期を絞る例
python "$HOME/.gemini/config/plugins/shared-skills/skills/session-log-search/scripts/search_session_logs.py" `
  --repo "E:\Documents\code\skills4agy" `
  --since 2026-11-01 `
  --max-primary 8 `
  --max-turns 15 `
  --budget-tokens 4500 `
  -- std::io::ErrorKind "--min-steps"
```

3. 必要に応じて原文の前後を読み足す。
   - 出力の各ターン見出しには `conv_id` と物理行番号（`match L<n>` があればその一致行、なければ `L<line_idx>`）、および `[session](conversation://<id>)` が付く。
   - 抜粋に省略された詳細を確認したいときだけ、該当 `transcript.jsonl` を `read_file`（`StartLine` は `match_line_idx + 1` または `line_idx + 1`）で局所読み込みする。

4. 0 件のときは 1 回だけ語を変えて再検索する。
   - 事前フィルタと行選別は casefold した原文の部分一致で行い、NFKC 正規化は採点時だけに適用するため、全角と半角の表記揺れがある語は両表記を展開語に含める。
   - 完全版ログ（`transcript_full.jsonl`）は短縮版でヒットしたエラー出力の補足に限定されるため、完全版側にしか残っていない語は検索対象外となる。
   - 展開語を変えて再実行しても 0 件であれば、短縮ログ上では該当履歴なしと報告して探索を終える。

## 対象と除外の方針

- **検索対象**：`os.scandir` で直接列挙する `brain/<uuid>/.system_generated/logs/transcript.jsonl` と `brain/<uuid>/*.md`、および `--repo` 指定時の `docs/*.md` と `git log`（直近 200 件）。
- **厳格ブロックリスト**：`.system_generated/logs/chunks/`、`.system_generated/steps/`、`conversation_summaries.db*`、`conversations/*.db*`、`*.pb`、`oauth_creds.json`、`google_accounts.json`、および実値の `.env*` は列挙しない。
- **ノイズ除外と先行マスク**：`read_file`、`view_file`、`read_board`、`update_focus`、`update_steps`、定型 exit-0 短小出力、本スクリプト自身の呼び出し履歴は索引から省き、窓分割や抜粋切り出しの前段でシークレットと Bearer トークンを `[REDACTED]` へマスクする。

## 原則

- 外部 API 呼び出しや永続インデックス DB を作らず、実行ごとのステートレス走査にとどめる。
- UI の巻き戻しによる `step_index` 重複に影響されないよう、同定と復元順序には物理行 `line_idx` と UTC 正規化時刻を使う。
- `--budget-tokens` は出力の上限として扱い、超過時は一致位置を中心に抜粋半径を縮小する（最小抜粋 60 文字でも収まらない場合のみ主ヒット件数を優先して警告を出す）。
