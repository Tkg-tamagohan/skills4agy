# ワーカープロンプトとスキーマ定型

`run_workflow` の `agent()` や `invoke_subagent` でワーカーへ渡すプロンプトの骨格と、完了時の `finish` 用 JSON Schema である。
`<...>` は対象ごとに埋める。
リポジトリ固有の規約（仕様の正となる文書、廃止用語、文体スキル、禁止する git 操作、lint、typecheck、test のコマンド）は共通規約の節にまとめ、全ワーカーへ同じ内容を付ける。

## 計画ワーカー

### プロンプト定型

```text
あなたはリポジトリ <repo_path> の監査計画を担当するワーカーである。
対象項目は「<項目名>」である。
下記の証拠は第一走査で得たものだが、行番号ずれや誤検出がありうるため、着手前に現行ブランチで自分でも対象箇所を確認し、対象の範囲を深く走査して計画書を作成する。

## 証拠
<第一走査で得た証拠：ファイル、行番号、観測した症状>
（Decision 1 一次スクリーニング由来の候補では、確率や分類ラベルを参考情報にとどめ、行番号と実態を現行ブランチで確認する）

## 計画書に含めるもの
- 対象の確定した範囲と、変更しないもの
- 自律適用で進められる修正と、仕様やユーザー向けの判断が要る要協議事項（各項目に ID と推奨案を付ける）
- 変更予定ファイルの正確な一覧（実装フェーズの排他境界設計に使う）
- 実施手順と受け入れ条件
- 採番が絡む場合は仮採番と明記する

## 対象外の発見
担当項目の範囲外で見つけた問題は、修正も計画もせず out_of_scope_findings に記録して返す。

## 完了条件
- 計画書を <Artifact Directory Path>/scratch/plans/<slug>.md に write_file で保存する（リポジトリ内には残さない）
- finish ツールで {summary, plan_path, recommendation, requires_discussion, out_of_scope_findings} を返す
```

### `run_workflow` 用 JSON Schema 例

```python
PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "plan_path": {"type": "string"},
        "recommendation": {"type": "string"},
        "requires_discussion": {
            "type": "array",
            "items": {"type": "string"},
        },
        "out_of_scope_findings": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": [
        "summary",
        "plan_path",
        "recommendation",
        "requires_discussion",
        "out_of_scope_findings",
    ],
}
```

## 実装ワーカー

### プロンプト定型

```text
あなたはリポジトリ <repo_path> の実装トラック「<トラック名>」を担当するワーカーである。
計画書 <plan_path> を read_file で読み、それを正として実装する。
計画書は現行ブランチで検証済みだが、着手前に自分でも対象箇所を確認すること。

## 排他ファイル境界
- 変更してよいファイル：<許可ファイル一覧>
- 変更してはいけないファイル：上記以外のすべてのファイル
- 他トラック所有ファイルの変更を避けられない呼び出しは、公開シグネチャを維持したファサード化（薄い委譲層の追加）で吸収する

## 共通規約
- 作業用ブランチ（例：audit/<slug>）で作業し、既定ブランチへの直接 push、--no-verify、force push は禁止する
- コミットメッセージ、PR タイトル、PR 本文は日本語で書く
- `gh pr create` を使う場合は、バッククォート展開による本文欠落を防ぐためインラインの `--body` ではなく `--body-file` で本文を渡す
- 作業前にリポジトリの規約文書（<AGENTS.md、仕様の正となる文書>）を読む
- 日本語文書を書く、または直すときは `japanese-tech-writing` スキルに従う
- コードを変えたら <lint、typecheck、test のコマンド> を実行して全パスを確認する
- 任意でコミットや PR 作成前に `invariant-gate` による実装差分の規約違反確認を併用できる
- 担当範囲外の実バグを見つけた場合は勝手に直さず notes で親へ報告する

## 完了条件
- 担当トラックの作業をブランチにコミット（指示がある場合は PR 作成まで）し、テスト結果を記録する
- finish ツールで {summary, branch_or_pr, test_status, notes, blockers} を返す
```

### `run_workflow` 用 JSON Schema 例

```python
IMPL_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "branch_or_pr": {"type": "string"},
        "test_status": {"type": "string"},
        "notes": {"type": "array", "items": {"type": "string"}},
        "blockers": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["summary", "branch_or_pr", "test_status", "notes", "blockers"],
}
```

## `run_workflow` 呼び出しの注意

- 計画フェーズは読み取り中心のため `workspace="inherit"`（または `invoke_subagent` の `TypeName="research"`）でよい。
- 実装フェーズは複数ワーカーが同時にファイルを編集するため、必ず `workspace="share"`（独立クローンで PR まで作る場合は `workspace="branch"`）を指定する。
- ワークフローのワーカーは親とコンテキストを共有しないため、`<Artifact Directory Path>`、対象リポジトリパス、共通規約はプロンプト本文へすべて展開して渡す。
- 実装フェーズでワーカーが `workspace="share"` や `"branch"` で作成したコミットは、ワークフロー終了後に親が確認して統合する（または PR 作成後に確認する）。
