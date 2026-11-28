---
name: repo-drift-audit
description: 文書、スキル、テストとコードの乖離や重複を洗い出し、決定論的プリフライトと計画と実装の 2 段ファンアウトで整理する手順。リポジトリ全体のドリフト監査を計画するときに使用する。不要テスト整理は test-suite-pruning、単発契約抽出は codebase-contract-extract、差分不変条件検査は invariant-gate に委ねる。
---

# リポジトリの網羅的ドリフト監査と 2 段ファンアウト

リポジトリの文書、スキル、テスト資産がコードからずれていないか、重複や構造上の問題がないかを網羅的に洗い出す作業は、決定論的プリフライトとサブエージェントへの 2 段の振り分けで進める。
計画フェーズで各項目の計画書を集めてユーザーに採択させ、実装フェーズで採択項目を排他ファイル単位のトラックへ分けて並列に実装させる。
洗い出しから修正までを一連の流れとして進めつつ、採否の判定をユーザーへ返す地点を一箇所に集約する。

## 責任範囲の境界

- **Decisions API の一般仕様と汎用バッチ CLI**：`gemini-decisions-api` に委ねる。
  - 本スキルでは決定論的プリフライト CLI（`scripts/preflight_drift.py`）と、文書、残課題帳簿、第一走査候補の一次スクリーニング CLI（`scripts/screen_drift_decision1.py`）を提供する。
- **実装差分の不変条件検査**：実装フェーズおよび統合後の `git diff` とリポジトリ内ルール文書の突合は `invariant-gate` に委ねる。
- **不要テストの判定と整理**：テスト資産の棚卸しにおける不要テストや重複テストの判定基準、Decision 1 保護対象フィルタ（`scripts/screen_tests_decision1.py`）、統合、孤立補助コードの掃除は `test-suite-pruning` に委ねる。
- **要協議の提示形式**：自律適用と要協議の切り分け、推奨案つき選択肢の形式は `requirements-definition` に従う。
- **並列実行と監視**：ワーカーの起動、ワークスペース分離、進捗待機、構造化出力の回収は builtin の `run-workflow`（`agent`、`parallel`、`phase`）または `invoke_subagent` に委ねる。
- **トラック分割と排他ファイル境界**：実装フェーズにおけるファイルの排他割り当てとファサード化の規則は本スキル内で定める。
- **既存設計文書がないコードベースの契約抽出**：未知ディレクトリから公開シンボル、不変条件、副作用を単発で把握したい場合は `codebase-contract-extract` に委ねる。
- **大規模監査後のフェーズ分離と引き継ぎ**：計画採択後に実装フェーズを別セッション（`/boost` や `/swarm`）へ切り離す場合は、ルール `session-phase-split` とスキル `session-handoff` に従う。
- **使い切ったサブエージェントの終了**：`invoke_subagent`（`research` や `self`）を利用した場合は、結果回収後にルール `subagent-cleanup` に従って `manage_subagents` で終了する。
- **クォータ温存時の読み取り調査委任**：第一走査や計画フェーズの軽量な読み取り専用調査を外部へ逃がす場合は、`devin-cli-delegate`（既定 `swe-2-max`、同時 2 枠上限）を併用できる。

## 走査観点

監査の第一走査で見る領域は次の 8 群である。
リポジトリの構成に合わせて取捨選択する。

- **文書ドリフト**：状況記述行の陳腐化、構造図と節番号参照のずれ、廃止用語、README の不一致。
- **残課題帳簿との突合**：解消済みの項目と、直近の作業で未記録になった項目。
- **仕様 ID と実装の機械照合**：文書側の仕様 ID とコード側の ID トークンを正規表現で両方向に抽出し、死んだ仕様行、未登録 ID、同名衝突、改番に分類する。
  - 決定論的照合で完結するため、確率判定には回さない。
- **スキル陳腐化**：`.agents/skills`、`.gemini/config`、プラグインスキル、ルール文書の記述と現行コードの比較。
  UI や運用が変わった箇所を重点的に見る。
- **重複**：ファイル単位の重複、スケルトン構造の類似、CSS セレクタなどの共有化余地。
  - ハッシュ比較や静的解析で先に検出し、全ファイル対を確率判定へ送らない。
- **構造**：大きいファイルの責務評価。
  1 PR や 1 トラックに収まる分割だけを項目化し、全面再設計が要るものは項目にしない。
- **機械化の検討**：スキルや手順書に文書化された作業手順を工程単位で点検し、出力が入力と規約から一意に決まる決定論的な工程をスクリプト化の候補として洗い出す。
  内容の判断や執筆が要る工程はモデル側に残し、配置、記帳、採番のように規約どおりに定まる作業だけを項目化する。
- **テスト資産の棚卸し**：廃止仕様のテスト、空アサーション、実装密結合、重複テスト、孤立したテスト補助コード。
  判定基準と一次フィルタ、削除や統合の手順は `test-suite-pruning` に従う。

## 手順

1. 親エージェントが第一走査を行い、各候補項目に根拠となる証拠（ファイル、行番号、観測した症状）を添えて列挙する。
   - 最初に API キー不要の決定論的プリフライト CLI `scripts/preflight_drift.py scan` を実行し、仕様 ID 双方向照合（`doc_only_ids` と `code_only_ids`）、巨大ファイル抽出（`--loc-threshold`、既定 `800`）、ファイル単位 SHA-256 ハッシュ重複、不在パスと不在 CLI フラグを一括検出する（`--spec-id-pattern` や `--exclude-glob` で調整でき、`--format` は `json`、`markdown`、`candidates-json` から選ぶ）。
   - 対象となる文書、スキル、残課題項目、または第一走査候補が多い場合（目安 10 件以上）は、続けて任意で `scripts/screen_drift_decision1.py` を使い、Gemini Decision 1（`gemini-decision-1`、出力トークン 0、`--backend auto` で SDK と REST を自動切替）で優先順位付けや事前分類を行える。
   - `docs` モードは既定の `--batch-mode chunk`（上限 `--chunk-max-docs 15`）で共有スナップショットを先頭に 1 回だけ置いて複数文書を一括評価する（`--paths` で対象を絞れ、`--batch-mode single` で従来の 1 文書 1 リクエスト動作を維持する）。
   - `backlog` モードは残課題帳簿の未完了項目（チェックボックスまたは JSON、さらに `--backlog-format` と `--include-tables` で表形式も抽出可）に見出し階層パンくずを付けて突合し、解消済み疑い項目を抽出する。
   - `candidates` モードは第一走査候補 JSON（`preflight_drift.py scan --format candidates-json` の出力を `--stdin` や `--input` で投入可、任意で `--repo`、`--facts-file`、`--git-log-limit` を併用）を既定 `--batch-mode chunk`（上限 `--chunk-max-items 50`）で評価し、`plan_worker_autonomous` や `plan_worker_discussion` や `needs_parent_review` へ振り分ける。
   - `.env` 系（雛形を除く）や秘密鍵ヘッダおよび主要 API トークンの混入時、また入力文字数や 1,000 問の上限超過時は API 送信前に終了コード `2` で遮断される。
   - Decision 1 は確率に基づく一次スクリーニングであり、出力だけで乖離の有無や行番号を断定せず、`low_priority_clean` もゼロ乖離の保証としては扱わない。
     証拠の行番号と症状は親エージェントまたは計画ワーカーが実ファイルから確定する。

```powershell
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
# 1. キー不要の決定論的プリフライト（最初に必ず実行）
python "$HOME/.gemini/config/plugins/shared-skills/skills/repo-drift-audit/scripts/preflight_drift.py" scan --repo . --format markdown
python "$HOME/.gemini/config/plugins/shared-skills/skills/repo-drift-audit/scripts/preflight_drift.py" scan --repo . --format candidates-json

# 2. Decision 1 のドライラン（キー不要、チャンク構成と入力文字数の確認）
python "$HOME/.gemini/config/plugins/shared-skills/skills/repo-drift-audit/scripts/screen_drift_decision1.py" docs --repo . --dry-run --format table
python "$HOME/.gemini/config/plugins/shared-skills/skills/repo-drift-audit/scripts/screen_drift_decision1.py" backlog --backlog docs/BACKLOG.md --repo . --backlog-format auto --dry-run --format table
python "$HOME/.gemini/config/plugins/shared-skills/skills/repo-drift-audit/scripts/screen_drift_decision1.py" candidates --input candidates.json --repo . --dry-run --format table

# 3. 実 API による一次スクリーニング（GEMINI_API_KEY を参照、--backend auto）
python "$HOME/.gemini/config/plugins/shared-skills/skills/repo-drift-audit/scripts/screen_drift_decision1.py" docs --repo . --backend auto --format table
python "$HOME/.gemini/config/plugins/shared-skills/skills/repo-drift-audit/scripts/screen_drift_decision1.py" backlog --backlog docs/BACKLOG.md --repo . --backend auto --format table
python "$HOME/.gemini/config/plugins/shared-skills/skills/repo-drift-audit/scripts/screen_drift_decision1.py" candidates --input candidates.json --repo . --backend auto --format json
```

2. 計画フェーズとして、`run_workflow` の `parallel()`（または `invoke_subagent` の `research`）で各項目を 1 ワーカーへ割り当てる。
   - プロンプトは同ディレクトリの `child-prompts.md` の計画ワーカー定型を使い、現行ブランチで証拠を再検証させたうえで計画書をワーカー自身の `<Worker Artifact Directory>/scratch/plans/<slug>.md` に書かせる。
   - `finish` スキーマ（`{summary, verdict, plan_path, target_files, provisional_ids, recommendation, requires_discussion, out_of_scope_findings}`）で構造化出力を回収する。
   - `invoke_subagent` を使った場合は結果回収後に `subagent-cleanup` へ従って終了する。
3. ワーカーから返った計画書を集約書 Artifact（`<Artifact Directory Path>/drift-audit-summary.md`）1 文書にまとめる。
   - 総表（`verdict` と `target_files` を含む）、推奨案つき要協議一覧、自律適用一覧、ワーカーの新規発見、仮採番一覧（`provisional_ids`）、実施順序と競合予測を含める。
4. ユーザーに採択を仰ぎ、採択された項目だけを実装フェーズへ進める。
   - 計画ワーカーの JSON 出力配列を `scripts/preflight_drift.py plan-tracks`（`--plans-json` または `--stdin`、`--format` は `json` か `markdown`）へ渡し、`verdict == "confirmed"` 項目の `target_files` 連結成分（Union-Find）から排他トラック境界と `provisional_ids` 衝突候補を機械算出する。
   - 大規模監査後に実装フェーズを別セッション（`/boost` や `/swarm`）へ切り離す場合は、`session-phase-split` と `session-handoff` に従って引き継ぐ。

```powershell
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
python "$HOME/.gemini/config/plugins/shared-skills/skills/repo-drift-audit/scripts/preflight_drift.py" plan-tracks --plans-json plans.json --format markdown
```

5. 実装フェーズでは算出済みの排他ファイル境界に沿って、採択項目を 1 ワーカー 1 トラックで並列に実装させる。
   - 他トラック所有のファイルを変更せずに済むか検討し、避けられない呼び出しは公開シグネチャを維持したファサード化（薄い委譲層の追加）で吸収する指定を計画へ入れる。
   - 並列実装の既定（モード A）は `run_workflow` の `parallel()` で `agent(..., workspace="branch")` を指定する。
     完全独立クローン上で専用ブランチ `audit/<slug>` を作成し、編集、テスト、コミット、必要に応じた PR 作成までワーカーが完結する。
   - `workspace="share"`（`git worktree` 相当で下層 `.git` を共有）や同一ワークスペースで親が順次コミットする運用（モード B）を選ぶ場合は、ワーカーの責務を許可ファイルの編集とテスト実行結果の返却までに限定し、ブランチ切替、コミット、push を禁止する。
   - 計画書の絶対パスをプロンプトで渡し、`child-prompts.md` の該当モード定型に沿って lint、typecheck、test の全パス、および `finish` スキーマ（`{summary, branch_or_pr, test_status, notes, blockers}`）での報告を完了条件にする。
   - 各トラックのコミットや PR 作成前には、任意で `invariant-gate`（`check_invariants_decision1.py`）を併用して実装差分の規約違反を確認できる。
6. 各ワーカーの出力を回収し、ブランチの統合（または PR 一覧、モード B では親による差分検証と順次コミット）と、見送った事項に先送り理由と再検討条件を添えた残課題をユーザーへ報告する。

## 設計の要点

- 渡した証拠はワーカーに必ず再検証させる。
  親の走査は行番号ずれや誤検出を含みうるため、ワーカーが証拠を訂正したり新規発見を加えたりすることを前提にする。
- `preflight_drift.py scan` で機械検出できる事実（仕様 ID、巨大ファイル、ハッシュ重複、不在パスと不在フラグ）を先に確定し、Decision 1 は探索順とワーカー配分の最適化に使う。
- 範囲外の発見は潰さず `out_of_scope_findings` で集約へ返させ、計画フェーズの副産物として拾う。
- Phase 番号、仕様決定 ID、テスト ID などの仮採番は `provisional_ids` に記録し、先行ブランチや先行 PR のマージ後に確定する。
- 複数トラックが同じファイルの別箇所を触る必要がある場合は `plan-tracks` で同一トラックへ統合され、集約書に共有ファイル衝突理由と統合順を添える。
- PR やコード変更以外の作業（プラグイン設定の更新、外部サービスの設定変更、ユーザー確認が必要な作業）はワーカーに振らず親エージェントが直接行う。
- 計画書は各計画ワーカー自身の `<Worker Artifact Directory>/scratch/plans/` へ、集約書は親の `<Artifact Directory Path>/` へそれぞれ置き、作業対象リポジトリに一時計画書を残さない。
- `workspace="branch"` でワーカーが作成したブランチやコミットは親が差分とテスト結果を確認して統合または PR レビューへ進み、`workspace="share"`（モード B）では親が作業ツリーの変更を確認してコミットする。

## リファクタ系トラックの検証技法

挙動不変を前提とする構造整理は、移動のみであることを機械的に示せると確認が早い。

- **行多重集合照合**：新旧ファイルの全行をソートした多重集合で diff を取り、追加行と削除行がないことを示す。
  行の増減がないことの確認にとどまり、行の並べ替えによる挙動変更は検出できないため、移動単位の内部順序が保たれていることは別途差分で確認する。
- **A/B 実機比較**：ブランチ版と基準ブランチの作業コピーを並べ、同じ操作を通して出力が完全一致することを確認する。

## 監査設計の基本姿勢

- 監査は証拠つきの候補列挙であり、第一走査で結論を確定せず、確定はワーカーの再検証とユーザーの採択に任せる。
- 2 段構成で洗い出しと掘り下げを分離し、ユーザーが採否を決める地点を一箇所に集約する。
- ワーカーが親の証拠を訂正することは設計どおりの動作であり、訂正と新規発見は集約書の「ワーカーの発見」節に集める。
- 並列実装は「このワーカーだけが触る」ファイル集合が重ならないことを前提とし、機能単位ではなく `target_files` の排他所有境界でトラックを切る。
