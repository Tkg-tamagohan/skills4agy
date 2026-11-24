---
name: spec-cold-review
description: 仕様書や実装計画をコールドリーダー視点で読み直し、曖昧さ、未決判断、偽のトレードオフを洗い出す手順。公開前レビューや実装着手前の準備度監査を行うときに使用する。要件定義と決定記録は requirements-definition に委ねる。
---

# 仕様書コールドレビューの手順

書き手の頭の中にある暗黙の前提が仕様書へ落ちているかを確かめるため、事前知識を持たない視点で文書だけを読ませて検査する。
初見の開発者が仕様を正しく言い換えられるかと、実装時に迷わず手を動かせるかを監査の軸にする。

## 責任範囲の境界

- **要件定義と決定記録**：協議項目の提示、推奨案の決定、決定記録ファイルへの保存は `requirements-definition` に委ねる。
- **文章の文体と機械検査**：日本語の推敲規範と `slop_lint.py` の運用は `japanese-tech-writing` に委ねる。
- **Decisions API の詳細仕様**：API の制約やオプション仕様は `gemini-decisions-api` に委ねる。
- **外部 CLI 委任と制約**：`devin -p` のモデル限定、環境変数、同時枠制御は `devin-cli-delegate` とルール `external-agent-devin` に委ねる。
- **サブエージェントの後始末**：使い切った `research` サブエージェントの終了手順はルール `subagent-cleanup` に委ねる。

## 事前準備と観点の参照

監査に入る前に、問いの基準とプロンプトの型を次の 2 文書で確認する。

- 設計の説得力と代替案の枠組みは [heilmeier-and-triz.md](references/heilmeier-and-triz.md) を参照する。
- レビュアーへ渡す定型文面と出力規約は [cold-review-prompts.md](references/cold-review-prompts.md) を参照する。

## 手順

### 1. 任意の一次スクリーニング（Decisions API）

サブエージェントを起動する前に、出力トークン 0 で基礎項目（目的、現状の限界、リスク、検証計画、未定義語）の抜けを素早く測りたい場合は、同梱プリセットを `run_decisions.py` へ渡す。
対象文書の外部送信が許されない環境では、この手順を飛ばして手順 2 へ進む。

```powershell
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
python "$HOME/.gemini/config/plugins/shared-skills/skills/gemini-decisions-api/scripts/run_decisions.py" `
  --text-file <spec.md> `
  --questions "$HOME/.gemini/config/plugins/shared-skills/skills/spec-cold-review/presets/spec_readiness_check.json" `
  --min-confidence 0.70 --format table
```

表出力で `has_undefined_project_terms` や `leaves_design_decisions_to_implementer` の `P(yes)` が高い場合、また `ESCALATE` が付いた項目がある場合は、次の段階で重点的に確認する。

### 2. 意味境界の分割とコンテキスト隔離

1 つの文書に仕様（目的、要件、外部振る舞い）と実装計画（`## 構成` や `## 実装計画` など）が同居しているときは、監査対象を 2 層へ分けて渡す。
仕様の節に対してコード行レベルの細部を突っ込ませず、計画の節に対しては「実装者へ丸投げされた未決事項がないか」を問わせる。

コールドレビューを実行する担当者には、対象文書（および 2 エージェント分割時の Agent B に限って明示指定の参照文書）だけを入力として渡す。
対象リポジトリ全体の grep や周辺コードの事前読み込みを禁止し、文書単体で意味が通るかを露呈させる。

### 3. コールドレビューの実行経路

入れ子の統合専用サブエージェント（`synthesizer`）は増やさず、親エージェントが結果を直接統合する。

- **既定経路（`invoke_subagent`）**：読み取り専用の `TypeName: "research"` で起動し、`references/cold-review-prompts.md` の 1 エージェント統合版または 2 エージェント分割版（Agent A と Agent B）を実行する。
  規模が小さい文書は 1 エージェント統合版で進め、用語の抜けと設計批判の視点を厳密に分けたい大規模文書では 2 エージェント分割版を選ぶ。
  受領と統合が終わったら、ルール `subagent-cleanup` に従い `manage_subagents` の `kill` で対象を終了する。
- **クォータ温存経路（外部送信が許可される場合のみ）**：`devin-cli-delegate` の手順で `ACP_BACKEND` を消去し、プロンプトファイル経由で標準出力を回収して親エージェントが統合する。

```powershell
Remove-Item Env:ACP_BACKEND -ErrorAction SilentlyContinue
devin --model swe-2-max -p --prompt-file "<Artifact Directory Path>\scratch\cold_review_prompt.txt"
```

### 4. 指摘の分類と収束上限

返却されたコールド言い換え（`この提案は何を作るものか` と `現行システムはどう動くと書かれているか`）と指摘一覧を受け取ったら、各指摘を次の 4 区分へ仕分ける。

- **`PROPOSE FIX`**：文書の欠落、曖昧さ、矛盾として修正案を作る指摘。
- **`CONTEST`**：対象文書または明示参照ファイル内の記述だけで反証できる誤読指摘。
- **`ESCALATE`**：コード外のチーム規約や事業判断が絡み、人間による確認を要する指摘。
- **`DECLINE`**：影響が軽微で修正対効果が見合わない指摘。

仕分けと修正では次の 2 原則を守る。

1. **言い換えのずれに反論しない**：Agent A または第 1 節の言い換えが書き手の意図とずれた場合、読み手の誤読として言い争わず、該当箇所の文書表現を書き直して明瞭にする。
2. **1 回限りの再監査上限（1-Audit Convergence Cap）**：修正後の再監査は最大 1 回までとし、2 回目の改訂後になお残る軽微な指摘は受容済みトレードオフとして扱い、実装または協議工程へ進む。

## 原則

- 事前知識のない読者が正しく言い換えられない仕様書は、実装者にも誤解されるとみなす。
- 仕様の節と実装計画の節は境界を分けて監査し、不要な細部への逸脱と未決事項の見逃しを同時に防ぐ。
- 設計に真の矛盾がないときは無理な再設計を求めず、指摘の往復は最大 1 回の再監査で打ち切る。
