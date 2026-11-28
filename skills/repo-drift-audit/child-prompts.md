# ワーカープロンプトとスキーマ定型

`run_workflow` の `agent()` や `invoke_subagent` でワーカーへ渡すプロンプトの骨格と、完了時の `finish` 用 JSON Schema である。
`<...>` は対象ごとに埋める。
リポジトリ固有の規約（仕様の正となる文書、廃止用語、文体スキル、禁止する git 操作、lint、typecheck、test のコマンド）は共通規約の節にまとめ、全ワーカーへ同じ内容を付ける。
ワーカーへ渡す Evidence は親が要約した伝言にせず、ポインタ（`#seq`、`file:L-L`、`ADR-ID`）と未加工の抜粋 5〜15 箇所を時系列順に並べたエビデンスパックとし、抜粋の合計は日本語とスタックトレースを含めて 9,000 文字（約 4,500 トークン）以内に収め、シークレットはマスクする。

## 計画ワーカー

### プロンプト定型

```text
You are an audit planning worker for repository <repo_path>.
Target item: "<item_name>".
The evidence below comes from the first pass and may have line offsets or false positives. Verify the target files on the current branch before writing the plan, then inspect the full scope deeply.

## Evidence
<First-pass evidence pack: pointers first (#seq, file:L-L, ADR-ID), then 5-15 verbatim excerpts in chronological order (max 9,000 characters total, about 4,500 tokens). Do not paraphrase or summarize the excerpts.>
(For preflight scan or Decision 1 pre-screening candidates, treat probabilities and labels as hints only; confirm actual lines and behavior on the current branch.)

## Plan Contents (write in Japanese, following `japanese-tech-writing`)
- Verdict (`confirmed`, `false_positive`, or `already_resolved`) with branch verification notes
- Confirmed scope and explicit non-goals (what will NOT be changed)
- Autonomous fixes vs. items requiring user discussion (assign each discussion item an ID and recommended option)
- Exact list of POSIX relative file paths to modify (`target_files`, used by `preflight_drift.py plan-tracks` for exclusive boundaries; use `[]` when verdict is not `confirmed`)
- Execution steps and acceptance criteria
- List any provisional Phase, spec decision, or test IDs in `provisional_ids` and mark them as provisional in the plan text

## Out-of-Scope Findings
Do not fix or plan issues outside your assigned scope; record them in `out_of_scope_findings`.

## Completion Criteria
- Determine `verdict` (`confirmed`, `false_positive`, or `already_resolved`), `target_files` (POSIX relative paths, `[]` if not `confirmed`), and `provisional_ids`
- Resolve your own `<Worker Artifact Directory>/scratch/plans/<slug>.md`, save the plan there via `write_file` (never leave plan files inside the repository), and record that concrete saved absolute path as `plan_path`
- Return `{summary, verdict, plan_path, target_files, provisional_ids, recommendation, requires_discussion, out_of_scope_findings}` via `finish` (all JSON summary strings in Japanese, following `japanese-tech-writing`)
```

### `run_workflow` 用 JSON Schema 例

```python
PLAN_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string"},
        "verdict": {
            "type": "string",
            "enum": ["confirmed", "false_positive", "already_resolved"],
        },
        "plan_path": {"type": "string"},
        "target_files": {
            "type": "array",
            "items": {"type": "string"},
        },
        "provisional_ids": {
            "type": "array",
            "items": {"type": "string"},
        },
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
        "verdict",
        "plan_path",
        "target_files",
        "provisional_ids",
        "recommendation",
        "requires_discussion",
        "out_of_scope_findings",
    ],
}
```

## 実装ワーカー

実装フェーズは `workspace` の指定とコミット担当に応じてモード A（既定）とモード B を使い分ける。

### モード A プロンプト定型（既定：`workspace="branch"`、独立クローンでブランチ作成、コミット、PR 完結）

```text
You are an implementation worker (Mode A: isolated clone) for track "<track_name>" in repository <repo_path>.
Read the plan `<plan_path>` via `read_file` and treat it as authoritative.
Confirm the target locations on the current branch before editing.

## Exclusive File Boundaries
- Allowed files: <allowed_files>
- Forbidden files: all other files outside the allowed list
- If a call into another track's file is unavoidable, keep its public signature intact and wrap it via a thin delegation facade

## Shared Rules
- Create and work on dedicated branch `audit/<slug>` inside your isolated clone; never push directly to the default branch, never use `--no-verify`, and never force push
- Write commit messages, PR titles, and PR bodies in Japanese (following `japanese-tech-writing`)
- When using `gh pr create`, pass the body via `--body-file` instead of inline `--body` to avoid backtick expansion
- Read the repository rules (`<AGENTS.md, authoritative spec docs>`) before editing
- Follow `japanese-tech-writing` whenever writing or editing Japanese documentation
- After code changes, run `<lint, typecheck, test commands>` and verify all pass
- Optionally run `invariant-gate` before committing or creating a PR to check diff compliance
- Do not fix real bugs outside your scope; report them to the parent in `notes`

## Completion Criteria
- Commit your track's changes on `audit/<slug>`, then either create a PR or push the branch via `git push -u origin audit/<slug>` (unpushed local commits inside an isolated clone cannot be referenced directly from the parent repository) and record test results
- Return `{summary, branch_or_pr, test_status, notes, blockers}` via `finish` (set `branch_or_pr` to the pushed remote branch or PR URL; all JSON summary strings in Japanese, following `japanese-tech-writing`)
```

### モード B プロンプト定型（`workspace="share"` のローカル専用ブランチ、または単一ワークスペースの未コミット返却）

```text
You are an implementation worker (Mode B: <worktree-local-branch | single-workspace-uncommitted>) for track "<track_name>" in repository <repo_path>.
Read the plan `<plan_path>` via `read_file` and treat it as authoritative.
Confirm the target locations on the current branch before editing.

## Exclusive File Boundaries
- Allowed files: <allowed_files>
- Forbidden files: all other files outside the allowed list
- If a call into another track's file is unavoidable, keep its public signature intact and wrap it via a thin delegation facade

## Shared Rules
- If running in `workspace="share"` (isolated worktree sharing `.git`): commit verified edits to your worker-specific local branch `<worker_branch>` (e.g., `audit/<slug>`) for in-workflow integration, and NEVER push, create a PR, touch other branches, use `--no-verify`, or force push
- If running sequentially in a single shared workspace: do NOT switch branches, create branches, commit, or push (leave verified edits uncommitted in the working tree for the parent)
- Read the repository rules (`<AGENTS.md, authoritative spec docs>`) before editing
- Follow `japanese-tech-writing` whenever writing or editing Japanese documentation
- After code changes, run `<lint, typecheck, test commands>` and verify all pass
- Optionally inspect your `git diff` against `invariant-gate` rules before reporting completion
- Do not fix real bugs outside your scope; report them to the parent in `notes`

## Completion Criteria
- In `workspace="share"`, commit on `<worker_branch>` without pushing and set `branch_or_pr` to `<worker_branch>` for the post-`parallel()` integration and verification agent in the same `run_workflow` (which merges or cherry-picks each `<worker_branch>` into an integration branch, runs integration tests, and returns `{integrated_branch, merge_status, test_status}` to the parent); in single-workspace sequential mode, leave edits uncommitted and set `branch_or_pr` to `"working-tree (uncommitted)"`
- Return `{summary, branch_or_pr, test_status, notes, blockers}` via `finish` (list edited files and test results; write all JSON strings in Japanese, following `japanese-tech-writing`)
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
- 計画ワーカーの `finish` 出力からユーザーが採択した項目（いずれも `verdict == "confirmed"`）だけを抽出した JSON 配列を `preflight_drift.py plan-tracks` へ渡し、`target_files` 連結成分から排他トラックを算出する。
- `workspace="branch"` はリポジトリの完全独立クローンをワーカーごとに作成するため、並列ブランチ作成（`audit/<slug>`）、コミット、push、PR 作成が他ワーカーの作業や `.git` と干渉せず、PR または `git push -u origin audit/<slug>` 済みリモートブランチから親が確定ブランチを回収できる（一時クローン内の未 push ローカルコミットのみでは親リポジトリから直接参照できない）。
  並列ブランチ運用は `workspace="branch"`（モード A）へ統一して既定とする。
- `workspace="share"` は作業ツリーを分離しつつ下層 `.git` を共有するため、ワーカー同士が同一ブランチを更新したり push したりすると競合を招きやすい。
  `workspace="share"` でワーカー専用のローカル作業ブランチへコミットする方式（モード B、push と PR 作成は禁止）を採る場合、`run_workflow` 終了後にワーカーのローカルブランチが親から参照できるかは実行基盤依存で未検証のため、同 `run_workflow` の `parallel()` 後段に統合と検証の担当エージェント（各ワーカーの `<worker_branch>` を統合ブランチへマージまたは `cherry-pick` し、統合テストを実行して `{integrated_branch, merge_status, test_status}` を親へ返す役割）を設けるか、確認が必要な場合は `workspace="branch"` または単一ワークスペースでの順次実行（未コミット編集を親の作業ツリーへ残して返却）を選ぶ。
- ワークフローのワーカーは親とコンテキストを共有しないため、対象リポジトリパス、共通規約、および実装フェーズでは計画ワーカーが返した確定済み `plan_path` を親がプロンプト本文へ展開して渡す（計画書の保存先は計画ワーカー自身が `<Worker Artifact Directory>/scratch/plans/<slug>.md` を解決し、保存した実在の絶対パスを `plan_path` で返す）。
- 親は集約時に各計画ワーカーの `plan_path` を実際に読み取れることを確認し、`workspace="branch"` 等の環境制約により実装ワーカーが他ワーカーの Artifact ディレクトリを `read_file` で直接読めない場合は、確定済み計画書を親の `<Artifact Directory Path>/scratch/plans/` へ複製して渡すか、計画本文を実装ワーカーのプロンプトへ直接展開する。
- 実装フェーズで `workspace="branch"`（モード A）によりワーカーが作成したリモートブランチや PR は、ワークフロー終了後に親が差分とテスト結果を確認して統合する（`workspace="share"` の場合は後段の統合と検証担当エージェントが返した `{integrated_branch, merge_status, test_status}` を確認する）。
