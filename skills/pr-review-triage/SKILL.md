---
name: pr-review-triage
description: PR のレビュー指摘を現行コードとコミット履歴、GitHub GraphQL スレッドおよびレビュー総評本文と照合して 3 区分へトリアージし、一次照合の完了時点で調査を打ち切り、複数セッション（`/boost`、`/swarm`）へ排他ファイル境界と事前 API 契約で分別計画し、既コミットと未コミットを厳密分離した返信、コミットと push、GraphQL によるスレッド Resolve、および機械的事後検証までを進める手順。PR レビュー指摘の一括トリアージ、修正計画の分別、未 Resolve スレッド整理を行うときに使用する。仕様判断と要協議提示は requirements-definition、別セッション移行と承認誤着工防止は session-phase-split、実装および PR 更新前へ分離する常駐システム境界監査は systems-pre-pr-audit、Windows 環境での gh と git 実行は windows-cli-pitfalls に委ねる。
---

# PR レビュー指摘のトリアージとスレッド整理

既存 PR に複数のレビュー指摘（AI レビューや人間レビュー）が蓄積したときは、一覧をそのまま実装対象にせず、実コードと GitHub 上のスレッド状態を照合してから分別計画と反映を行う。
ゴールは、既対応指摘の二重作業とセッション間競合を防ぎ、未 Resolve スレッド 0 件かつ検証根拠が実コミットと一致した状態まで完了させることである。

## 責任範囲の境界

- **仕様判断と要協議の提示**：仕様方針や自動 Resolve 可否の確認形式は `requirements-definition` に委ねる。
- **別セッション移行と誤着工防止**：別セッション向け計画の承認扱いと移行手順はルール `session-phase-split` に委ねる。
- **常駐システムの境界監査**：実装および PR 更新前の境界条件点検は `systems-pre-pr-audit` に委ね、トリアージと修正計画の段階（Stage 1 と Stage 2）では実施しない。
- **テスト規約と Windows CLI**：テスト同期要件はルール `test-conventions`、文字化け検査はルール `verify-file-writes`、PowerShell と `gh` の引用や UTF-8 扱いは `windows-cli-pitfalls` に委ねる。

## Stage 1：実物照合トリアージ

1. `git log`、現行 HEAD の実装とテストコード、および GitHub PR の状態を Python スクリプト経由で取得して突き合わせる。
   - GraphQL `reviewThreads` から全スレッドの `id`、`isResolved`、`isOutdated`、対象パスと行、コメント本文を取得する。
   - あわせて `gh pr view <num> --json comments,reviews` も取得し、インラインスレッド外のレビュー総評本文に記載された diff 外指摘を見落とさない。
2. 指摘件数が多い場合（目安 5 件以上）は、任意で同梱の `scripts/triage_decision1.py` を使い、取得済み指摘 JSON を一次プリラベルして確定候補の根拠照合と要精査項目の再現確認へ集中する。
   - 各指摘を `triage_bucket`、`needs_human_confirmation`、`severity`、`dispatch_mode` の 4 問で並列分類し、API トークンや秘密鍵ヘッダの混入時は送信前に終了コード `2` で遮断される。
   - 信頼度 `0.80` 以上、区分 `other` 以外、要確認度 `0.50` 未満をすべて満たす項目は確定候補（`needs_deep_review: false`）に振り分け、残りを重点精査対象（`needs_deep_review: true`）へ上げる。
   - `dispatch_mode`（`single_session`、`boost_deep`、`swarm_parallel`、`plan_first`、`other`）は `needs_deep_review` 判定には影響させず、Stage 2 における `/boost`・`/swarm`・`/plan` や単一セッション振り分けの参考指標として使う。
   - 確定候補であっても、一覧表へ載せる前に現行 HEAD の該当行と根拠コミットを実コードで照合する。

```powershell
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
python ~/.gemini/config/plugins/shared-skills/skills/pr-review-triage/scripts/triage_decision1.py --input reviews.json --dry-run
python ~/.gemini/config/plugins/shared-skills/skills/pr-review-triage/scripts/triage_decision1.py --input reviews.json --format table
```

3. 各指摘を次の 3 区分に分類し、根拠コミット、実在する行番号と回帰テスト ID、担当区分を一覧表にする。
   - **現行 HEAD で再現する未修正**：再現箇所と修正方針を確定する。
   - **主訴解消済みだが残存リスク追補**：既対応コミットと残存箇所を切り分ける。
   - **現行 HEAD で完全解消済み**：対応コミットと既存回帰テスト ID を特定し、未 Resolve スレッド整理のみの対象へ回す。
4. 仕様方針の選択を伴う項目と、未 Resolve スレッドを自動返信および Resolve してよいかは要確認事項としてユーザーへ提示する。
5. 新規または未対応の指摘について、該当箇所の再現確認と修正方針の根拠が揃った時点で Stage 1 の調査を打ち切り、結果と計画を先に提示する。
   - 確認対象は指摘が直接参照する関数、呼び出し元、対応する既存テストに限定し、無関係な周辺ファイルや別クレートの連鎖的な精読を行わない。
   - 新規指摘が 1 件から数件のときは、一次照合（5 点取得と対象箇所の確認）の直後に現在地と要点を短く途中報告し、周辺リスクの追加探索へそのまま移行しない。
   - 調査中に気付いた近接リスクや改善候補は、その場で精査を広げず「依頼範囲外の候補」として箇条書きで添え、実装セッション（`/boost` や `/swarm`）または PR 更新前の `systems-pre-pr-audit` へ委ねる。

## Stage 2：複数セッションとワーカーの分別計画および並行協調

1. 作業を複数セッション（`/boost`、`/swarm`、`/plan` 等）や複数ワーカーへ分けるときは、Stage 1 の `dispatch_mode` も参考にしながら、ファイル所有による排他ファイル境界と、セッション間で固定する事前公開 API 契約（メソッド名とシグネチャ）を計画書に明記する。
2. 依存関係のある先行セッションと後続セッションを同一ワーキングツリーで並行実行する場合は、後続側プロンプトへ次の制約を組み込む。
   - ワーキングツリーの未コミット差分やシンボル検索一致だけで先行セッション完了とみなさず、先行コミットまたはユーザーの完了連絡を完了基準とする。
   - 先行未確定の間は担当外のファイルを触らず、非依存タスクだけを先に進めて待機するフォールバック手順を明記する。
3. Swarm ワーカーのブリーフには、各ワーカーの作業内容に応じて読むべき共通ルールとスキルの絶対パスを明示する。
   - Windows 上で `git`、`gh`、PowerShell を使う全ワーカーへ `windows-cli-pitfalls` を渡す。
   - 日本語を含む編集を行うワーカーへ `verify-file-writes`、テスト担当へ `test-conventions` を渡す。
4. 他セッションからの完了連絡後に統合検証を行う際は、前回検証時刻と変更対象ファイルの最終更新時刻（`LastWriteTime`）または `git diff` 内容を比較し、更新があれば前回検証以降のデルタを精査したうえで全標準検証コマンドを再実行する。

## Stage 3：コミット、push、スレッド返信と Resolve、事後検証

1. コミットと push の前に作成する返信ドラフトでは、「既コミット分のみで完結する本文」と「未コミット変更を push した後に `<次コミットハッシュ>` を差し替えて追記する本文」を厳密に区別する。
2. ユーザーから反映指示を受けたら、次の順序で実行する（`git push --force` と既定ブランチへの直接 push は行わない）。
   1. `git branch --show-current` と `git status -sb` で対象ブランチと変更ファイル集合が想定どおりであることを確認し、対象ファイルのみ明示的に `git add` する。
   2. リポジトリ外（`$env:TEMP` や `scratch/`）へ UTF-8（BOM なし）の一時ファイルを作成して `git commit -F` でコミットし、通常 `git push` して新コミットハッシュ（短縮とフル）を確定させる。
   3. 確定ハッシュを差し替えた日本語返信を Python の `subprocess.run(..., encoding="utf-8")` から GraphQL `addPullRequestReviewThreadReply` で投稿し、対応スレッドを `resolveReviewThread` で Resolve する。
   4. 新コミットハッシュ、対応指摘（diff 外総評指摘を含む）、追加または改訂したテスト ID 一覧、標準検証コマンドの実測結果、および未検証範囲をまとめた日本語サマリコメントを `gh pr comment --body-file` で投稿する。
3. 反映完了後、次の機械的事後検証を実行して結果を表で報告する。
   - GraphQL で PR の `headRefOid` と全 `reviewThreads` を再取得し、未 Resolve スレッドが 0 件であること、`headRefOid` が push 済みコミットと一致することを確認する。
   - 投稿した全スレッド返信と PR サマリコメントに `U+FFFD` や文字化けがないことを確認する。
   - `git status -sb` がクリーンであること、および一時ファイルが残存していないことを確認する。

## 原則

- 貼られた指摘一覧を鵜呑みにせず、現行 HEAD のコード、テスト、`git log`、GraphQL スレッド、レビュー総評本文の 5 点で実物照合する。
- 共有ワーキングツリー上の未コミット差分は他セッションの途中編集や改善パス中の可能性があるため、完了証拠として扱わない。
- 未 push の変更を既確定の対応として PR 返信へ記載せず、必ず push 後に確定ハッシュを差し替えて投稿し、GraphQL 再取得で事後検証する。
- トリアージと計画フェーズの責務は再現確認と方針決定にとどめ、一次照合を終えたあとの周辺境界監査は実装フェーズへ分離する。
