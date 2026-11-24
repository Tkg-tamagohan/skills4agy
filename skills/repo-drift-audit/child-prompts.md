# ワーカープロンプトとスキーマ定型

`run_workflow` の `agent()` や `invoke_subagent` でワーカーへ渡すプロンプトの骨格と、完了時の `finish` 用 JSON Schema である。
`<...>` は対象ごとに埋める。
リポジトリ固有の規約（仕様の正となる文書、廃止用語、文体スキル、禁止する git 操作、lint、typecheck、test のコマンド）は共通規約の節にまとめ、全ワーカーへ同じ内容を付ける。

## 計画ワーカー

### プロンプト定型

```text
You are an audit planning worker for repository <repo_path>.
Target item: "<item_name>".
The evidence below comes from the first pass and may have line offsets or false positives. Verify the target files on the current branch before writing the plan, then inspect the full scope deeply.

## Evidence
<First-pass evidence: file, line numbers, observed symptoms>
(For Decision 1 pre-screening candidates, treat probabilities and labels as hints only; confirm actual lines and behavior on the current branch.)

## Plan Contents (write in Japanese, following `japanese-tech-writing`)
- Confirmed scope and explicit non-goals (what will NOT be changed)
- Autonomous fixes vs. items requiring user discussion (assign each discussion item an ID and recommended option)
- Exact list of files to modify (used for exclusive file-ownership boundaries during implementation)
- Execution steps and acceptance criteria
- Mark any Phase, decision, or test IDs as provisional numbering

## Out-of-Scope Findings
Do not fix or plan issues outside your assigned scope; record them in `out_of_scope_findings`.

## Completion Criteria
- Resolve your own `<Worker Artifact Directory>/scratch/plans/<slug>.md`, save the plan there via `write_file` (never leave plan files inside the repository), and record that concrete saved absolute path as `plan_path`
- Return `{summary, plan_path, recommendation, requires_discussion, out_of_scope_findings}` via `finish` (all JSON summary strings in Japanese, following `japanese-tech-writing`)
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
You are an implementation worker for track "<track_name>" in repository <repo_path>.
Read the plan `<plan_path>` via `read_file` and treat it as authoritative.
Confirm the target locations on the current branch before editing.

## Exclusive File Boundaries
- Allowed files: <allowed_files>
- Forbidden files: all other files outside the allowed list
- If a call into another track's file is unavoidable, keep its public signature intact and wrap it via a thin delegation facade

## Shared Rules
- Work on a dedicated branch (e.g., `audit/<slug>`); never push directly to the default branch, never use `--no-verify`, and never force push
- Write commit messages, PR titles, and PR bodies in Japanese (following `japanese-tech-writing`)
- When using `gh pr create`, pass the body via `--body-file` instead of inline `--body` to avoid backtick expansion
- Read the repository rules (`<AGENTS.md, authoritative spec docs>`) before editing
- Follow `japanese-tech-writing` whenever writing or editing Japanese documentation
- After code changes, run `<lint, typecheck, test commands>` and verify all pass
- Optionally run `invariant-gate` before committing or creating a PR to check diff compliance
- Do not fix real bugs outside your scope; report them to the parent in `notes`

## Completion Criteria
- Commit your track's changes to the branch (and create a PR if instructed) and record test results
- Return `{summary, branch_or_pr, test_status, notes, blockers}` via `finish` (all JSON summary strings in Japanese, following `japanese-tech-writing`)
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
- ワークフローのワーカーは親とコンテキストを共有しないため、対象リポジトリパス、共通規約、および実装フェーズでは計画ワーカーが返した確定済み `plan_path` を親がプロンプト本文へ展開して渡す（計画書の保存先は計画ワーカー自身が `<Worker Artifact Directory>/scratch/plans/<slug>.md` を解決し、保存した実在の絶対パスを `plan_path` で返す）。
- 親は集約時に各計画ワーカーの `plan_path` を実際に読み取れることを確認し、`workspace="branch"` 等の環境制約により実装ワーカーが他ワーカーの Artifact ディレクトリを `read_file` で直接読めない場合は、確定済み計画書を親の `<Artifact Directory Path>/scratch/plans/` へ複製して渡すか、計画本文を実装ワーカーのプロンプトへ直接展開する。
- 実装フェーズでワーカーが `workspace="share"` や `"branch"` で作成したコミットは、ワークフロー終了後に親が確認して統合する（または PR 作成後に確認する）。
