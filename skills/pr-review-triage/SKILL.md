---
name: pr-review-triage
description: PR レビュー指摘と GraphQL スレッドを実コードで照合してトリアージ、再発防止策回収、返信、Resolve、push 後の Devin Review 完了判定まで進める手順。PR 指摘整理や未 Resolve 解消を行うときに使用する。仕様判断は requirements-definition、境界監査は systems-pre-pr-audit、差分検査は invariant-gate に委ねる。
---

# PR レビュー指摘のトリアージとスレッド整理

既存 PR に複数のレビュー指摘（AI レビューや人間レビュー）が蓄積したときは、一覧をそのまま実装対象にせず、実コードと GitHub 上のスレッド状態を照合してから分別計画と反映を行う。
ゴールは、既対応指摘の二重作業とセッション間競合を防ぎ、前ラウンドの再発防止策を引き継ぎながら未 Resolve スレッド 0 件かつ検証根拠が実コミットと一致した状態まで完了させることである。

## 責任範囲の境界

- **仕様判断と要協議の提示**：仕様方針や自動 Resolve 可否の確認形式は `requirements-definition` に委ねる。
- **別セッション移行と誤着工防止**：別セッション向け計画の承認扱いと移行手順はルール `session-phase-split` に委ねる。
- **常駐システムの境界監査**：実装および PR 更新前の境界条件点検は `systems-pre-pr-audit` に委ね、トリアージと修正計画の段階（Stage 1 と Stage 2）では実施しない。
- **実装差分の不変条件検査**：実装差分とルール Markdown の機械突合および二次精査手順は `invariant-gate` に委ね、本スキルは PR 内再発防止策の抽出とルール Markdown 生成までを担う。
- **テスト規約と Windows CLI**：テスト同期要件はルール `test-conventions`、文字化け検査はルール `verify-file-writes`、PowerShell と `gh` の引用や UTF-8 扱いは `windows-cli-pitfalls` に委ねる。
- **Devin API シークレット登録**：`DEVIN_API_KEY` と `DEVIN_ORG_ID` の新規発行および環境変数登録の案内は、ルール `scoped-secret-provisioning` に委ねる。

## Stage 1：実物照合トリアージ

1. `git log`、現行 HEAD の実装とテストコード、および GitHub PR の状態を統合 CLI `scripts/pr_ops.py` 経由で取得して突き合わせる。
   - `pr_ops.py status --save-pr-json <tmp>/pr.json` で PR 本文、コメント、レビュー総評、CI チェック集計、GraphQL `reviewThreads`（全ページ）、および既存再発防止策を一括取得する。
   - 取得した PR JSON に対して `scripts/pr_guardrails.py extract --input pr.json --format summary` を実行し、PR 内に記録済みの有効な再発防止策と失効履歴を確認する。
2. 指摘件数が多い場合（目安 5 件以上）は、任意で同梱の `scripts/triage_decision1.py` を使い、取得済み指摘 JSON を一次プリラベルして確定候補の根拠照合と要精査項目の再現確認へ集中する。
   - 各指摘を `triage_bucket`、`needs_human_confirmation`、`severity`、`dispatch_mode` の 4 問で並列分類し、API トークンや秘密鍵ヘッダの混入時は送信前に終了コード `2` で遮断される。
   - 信頼度 `0.80` 以上、区分 `other` 以外、要確認度 `0.50` 未満をすべて満たす項目は確定候補（`needs_deep_review: false`）に振り分け、残りを重点精査対象（`needs_deep_review: true`）へ上げる。
   - `dispatch_mode`（`single_session`、`boost_deep`、`swarm_parallel`、`plan_first`、`other`）は `needs_deep_review` 判定には影響させず、Stage 2 における `/boost`、`/swarm`、`/plan` や単一セッション振り分けの参考指標として使う。
   - 確定候補であっても、一覧表へ載せる前に現行 HEAD の該当行と根拠コミットを実コードで照合する。

```powershell
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
python "$HOME/.gemini/config/plugins/shared-skills/skills/pr-review-triage/scripts/pr_ops.py" status --save-pr-json "$env:TEMP/pr.json" --output "$env:TEMP/pr-status.json"
python "$HOME/.gemini/config/plugins/shared-skills/skills/pr-review-triage/scripts/pr_guardrails.py" extract --input "$env:TEMP/pr.json" --format summary
python "$HOME/.gemini/config/plugins/shared-skills/skills/pr-review-triage/scripts/triage_decision1.py" --input reviews.json --dry-run
```

3. 各指摘を次の 3 区分に分類し、根拠コミット、実在する行番号と回帰テスト ID、関連する再発防止策 ID（該当がある場合）、担当区分を一覧表にする。
   - **現行 HEAD で再現する未修正**：再現箇所と修正方針を確定する。
   - **主訴解消済みだが残存リスク追補**：既対応コミットと残存箇所を切り分ける。
   - **現行 HEAD で完全解消済み**：対応コミットと既存回帰テスト ID を特定し、未 Resolve スレッド整理のみの対象へ回す。
   - 回収済みの有効な再発防止策と照合し、過去ラウンドと同種パターンの再発や横展開漏れに当たる指摘には該当 ID（例 `PRG-001`）を一覧表へ併記し、照合範囲は今回の指摘対象ファイルと関連関数に限定する。
4. 仕様方針の選択を伴う項目、過去の再発防止策と矛盾する仕様変更（該当 ID を `retired` へ移すかどうか）、および未 Resolve スレッドを自動返信および Resolve してよいかは要確認事項としてユーザーへ提示する。
5. 新規または未対応の指摘について、該当箇所の再現確認と修正方針の根拠が揃った時点で Stage 1 の調査を打ち切り、結果と計画を先に提示する。
   - 確認対象は指摘が直接参照する関数、呼び出し元、対応する既存テストに限定し、無関係な周辺ファイルや別クレートの連鎖的な精読を行わない。
   - 新規指摘が 1 件から数件のときは、一次照合（5 点取得と対象箇所の確認）の直後に現在地と要点を短く途中報告し、周辺リスクの追加探索へそのまま移行しない。
   - 調査中に気付いた近接リスクや改善候補は、その場で精査を広げず「依頼範囲外の候補」として箇条書きで添え、実装セッション（`/boost` や `/swarm`）または PR 更新前の `systems-pre-pr-audit` へ委ねる。

## Stage 2：複数セッションとワーカーの分別計画および並行協調

1. 作業を複数セッション（`/boost`、`/swarm`、`/plan` 等）や複数ワーカーへ分けるときは、Stage 1 の `dispatch_mode` も参考にしながら、ファイル所有による排他ファイル境界と、セッション間で固定する事前公開 API 契約（メソッド名とシグネチャ）を計画書に明記する。
2. Stage 1 で有効な再発防止策を 1 件以上回収した場合は、`pr_guardrails.py extract --input pr.json --format brief` の出力を計画書、再開プロンプト、および `/swarm` ワーカーブリーフへ組み込む。
3. 依存関係のある先行セッションと後続セッションを同一ワーキングツリーで並行実行する場合は、後続側プロンプトへ次の制約を組み込む。
   - ワーキングツリーの未コミット差分やシンボル検索一致だけで先行セッション完了とみなさず、先行コミットまたはユーザーの完了連絡を完了基準とする。
   - 先行未確定の間は担当外のファイルを触らず、非依存タスクだけを先に進めて待機するフォールバック手順を明記する。
4. Swarm ワーカーのブリーフには、各ワーカーの作業内容に応じて読むべき共通ルールとスキルの絶対パスを明示する。
   - Windows 上で `git`、`gh`、PowerShell を使う全ワーカーへ `windows-cli-pitfalls` を渡す。
   - 日本語を含む編集を行うワーカーへ `verify-file-writes`、テスト担当へ `test-conventions` を渡す。
5. 他セッションからの完了連絡後に統合検証を行う際は、前回検証時刻と変更対象ファイルの最終更新時刻（`LastWriteTime`）または `git diff` 内容を比較し、更新があれば前回検証以降のデルタを精査したうえで全標準検証コマンドを再実行する。
6. 実装完了後かつ PR 更新前に、有効な PR 内再発防止策が 1 件以上あるときは、`pr_ops.py invariant-check` を実行して新差分が過去の再発防止策を破っていないか一次検査する。
   - 同コマンドは PR コメント内の有効項目を内部の一時ルール Markdown へ自動書き出しし、`invariant-gate` を連続実行する。

```powershell
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
python "$HOME/.gemini/config/plugins/shared-skills/skills/pr-review-triage/scripts/pr_ops.py" invariant-check --base origin/main --strict-guardrails
```

## Stage 3：コミット、push、スレッド返信と Resolve、事後検証

1. コミットと push の前に作成する返信ドラフトでは、「既コミット分のみで完結する本文」と「未コミット変更を push した後に `{{COMMIT_SHORT}}` を差し替えて追記する本文」を厳密に区別する。
2. ユーザーから反映指示を受けたら、次の順序で実行する（`git push --force` と既定ブランチへの直接 push は行わない）。
   1. 入力テキスト（コミットメッセージ、返信計画 JSON、サマリコメント等）は `write_file` で `$env:TEMP` または `scratch/` 配下へ BOM なし UTF-8 で書き出す（全コマンドで秘密情報、BOM、および `U+FFFD` の検査を強制）。
   2. `pr_ops.py commit-push --files <対象ファイル...> --message-file <msg.txt>` で明示ファイルのみ `git add`、コミット、`git push origin <branch>` を実行し、新コミット SHA を確定させる。
   3. `pr_ops.py apply-triage --plan <plan.json> --commit-sha <head_sha>` で確定 SHA 差し替え済みの日本語スレッド返信、`resolveReviewThread`、`pr_guardrails.py` 検証済みマーカーブロック付きの日本語サマリコメント投稿（`gh pr comment --body-file`）、および GraphQL 再取得、strict 復元、および `U+FFFD` 検証までを一括実行する。
   4. PR マージ後もリポジトリ全体で守るべき恒久化候補がある場合は、リポジトリ内ファイルを勝手に編集せず、Stage 3 の完了報告で反映先案（`AGENTS.md`、`.agents/rules/`、`.agents/invariants.json` 等）を提案のみ提示する。

```powershell
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
python "$HOME/.gemini/config/plugins/shared-skills/skills/pr-review-triage/scripts/pr_ops.py" commit-push --files path/to/file.py --message-file "$env:TEMP/commit-msg.txt"
python "$HOME/.gemini/config/plugins/shared-skills/skills/pr-review-triage/scripts/pr_ops.py" apply-triage --plan "$env:TEMP/triage-plan.json" --commit-sha "<head_sha>" --dry-run
python "$HOME/.gemini/config/plugins/shared-skills/skills/pr-review-triage/scripts/pr_ops.py" apply-triage --plan "$env:TEMP/triage-plan.json" --commit-sha "<head_sha>"
```

3. 反映完了後、`apply-triage` の `verification` 出力と合わせて以下を確認し、結果を表で報告する。
   - `unresolved_count == 0` かつ `commit_sha_match == true` かつ `guardrails_strict_ok == true` かつ `ufffd_found == false` であること。
   - `git status -sb` がクリーンであること、および一時ファイルが残存していないことを確認する。

## Stage 3 後：Devin Review 状態確認と再レビューループ

PR 改善ループ（`/goal` 等）でコミットを push した直後は、GitHub GraphQL だけでは「0 件完了」と「解析中または未実行」を区別できない。
`pr_ops.py status --check-devin`（内部で `scripts/check_devin_review.py` を実行）を呼び出し、Devin API の完了状態と GitHub GraphQL の未 Resolve スレッド件数を突き合わせて次手を決める。

前提として、2026 年 11 月時点の Devin API v3（Pro プラン実機確認済み）では組織スコープの `/v3/organizations/{org_id}/pr-reviews` を使用し、エンタープライズ専用の `/v3/enterprise/pr-reviews` は使わない。
このエンドポイントは指摘件数を返さないため、0 件完了の確定には GitHub GraphQL との併用が必須である。
また、`DEVIN_API_KEY` と `DEVIN_ORG_ID` は環境変数のみから読み取り、チャット、ログ、CLI 引数へ実値を出力しない。

```powershell
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
python "$HOME/.gemini/config/plugins/shared-skills/skills/pr-review-triage/scripts/check_devin_review.py" --pr-url "https://github.com/<owner>/<repo>/pull/<num>" --commit-sha "<head_sha>" --dry-run
python "$HOME/.gemini/config/plugins/shared-skills/skills/pr-review-triage/scripts/check_devin_review.py" --pr-url "https://github.com/<owner>/<repo>/pull/<num>" --commit-sha "<head_sha>"
# 自動起動待ち後も not_found のとき、またはユーザー明示指示時のみ（同一 commit_sha あたり最大 1 回）
python "$HOME/.gemini/config/plugins/shared-skills/skills/pr-review-triage/scripts/check_devin_review.py" --pr-url "https://github.com/<owner>/<repo>/pull/<num>" --commit-sha "<head_sha>" --trigger
```

出力 JSON の `decision` フィールドに基づき、次のとおり分岐する。

1. **`completed`（`can_conclude_clean: true`）**：GitHub GraphQL の未 Resolve スレッドが 0 件であれば「0 件完了」として改善ループを終了し、1 件以上あれば次ラウンドの Stage 1 へ進む。
2. **`in_progress` または `stale_commit`**：解析中または前コミットの結果が残っている状態のため、一定時間待機して同じ `--commit-sha` で再照会する。
3. **`not_found`（HTTP 404）**：push 後の自動起動待ち（30 秒から 60 秒）ののち再照会しても `not_found` が解消しない場合、またはユーザーから明示指示がある場合に限り、同一 `commit_sha` あたり最大 1 回だけ `--trigger` を実行してよい。
4. **`fallback_github_only`（環境変数未設定）**：Devin API キーまたは組織 ID が未登録のため終了コード `0` でフォールバックし、従来の GitHub GraphQL 監視のみを継続する。
5. **`auth_error`、`rate_limited`、`api_error`**：非ゼロ終了コードになるため、認証情報や `retry_after_seconds` を確認して再試行または中断を判断する。

## PR 内再発防止策の記述形式と運用基準

Stage 3 の PR サマリコメント末尾に含めるブロック形式は次のとおりとし、生成と検証には `scripts/pr_guardrails.py render` を使う（折りたたみ表示時は `--collapsible` を付ける）。

```markdown
<!-- pr-review-triage:guardrails:v1 -->
## 再発防止策（PR 内引き継ぎ）

- [PRG-001] (active) 対象: `src/ipc/**` | ルール: IPC ハンドラでエラーを握りつぶさず呼び出し元へ返す | 根拠: commit `a1b2c3d` / thread `PRRT_xxx`
- [PRG-001] (retired) 理由: IPC ハンドラ実装を共通ラッパーへ統合したため不要化
<!-- /pr-review-triage:guardrails:v1 -->
```

- **採択基準**：同種パターンの再発や複数箇所での横展開漏れを防げる制約、またはテストだけでは固定しにくい設計条件だけを記録し、誤字修正や単発の表現調整は記録しない。
- **信頼境界**：PR コメントから回収した再発防止策は参考用の不変条件として扱い、現行コードの実態や最新のユーザー指示と矛盾する場合は無検証で優先せず確認する（必要に応じて `--author` で投稿者を限定する）。
- **公開リポジトリ等の例外**：PR コメントへエージェント向けの再発防止ブロックを追記したくないとユーザーから指示された場合はコメント末尾への追記を省略し、`session-handoff` によるローカル引き継ぎのみで扱う。

## 原則

- 貼られた指摘一覧を鵜呑みにせず、現行 HEAD のコード、テスト、`git log`、GraphQL スレッド、レビュー総評本文の 5 点で実物照合する。
- 共有ワーキングツリー上の未コミット差分は他セッションの途中編集や改善パス中の可能性があるため、完了証拠として扱わない。
- 未 push の変更を既確定の対応として PR 返信へ記載せず、必ず push 後に確定ハッシュを差し替えて投稿し、GraphQL 再取得で事後検証する。
- PR 固有の再発防止メモをリポジトリ内ファイルへコミットせず、PR コメントのマーカーブロックとリポジトリ外の一時ファイルで受け渡す。
- トリアージと計画フェーズの責務は再現確認と方針決定にとどめ、一次照合を終えたあとの周辺境界監査は実装フェーズへ分離する。
