# shared-skills

Antigravity セッション全体で共有するルールとスキルをまとめたプラグインです。

## 収録内容

### ルール

| ルール | 読み込まれる状況 |
| --- | --- |
| `cloudflare-cf-cli` | Cloudflare のリソースを CLI から操作または自動化する |
| `cloudflare-pages-private-admin` | Cloudflare Pages の公開アプリに非公開の管理ツールやステージングを併設する |
| `external-agent-devin` | Antigravity から外部の Devin CLI を呼び出す際の無料モデル限定と読み取り専用制約 |
| `library-license` | 外部ライブラリやパッケージを導入する、バージョンを上げる、またはコードを転用する |
| `pre-pr-verification` | PR の作成や更新前に実装結合点、不変条件検査、境界監査、差分との説明整合を確認する手順 |
| `region-near-japan` | クラウドサービスのリソースを作成または移行する際にリージョンを選ぶ |
| `register-to-devin-plugins` | 再利用可能なルールやスキルを新規作成、保存、共有する |
| `scoped-secret-provisioning` | ユーザーにシークレットや API トークン、パスワードの登録や発行を依頼する |
| `session-phase-split` | 要件定義、設計、実装、テストなどの開発フェーズが切り替わる、または作業が長期化する |
| `subagent-cleanup` | 使い切った非 browser サブエージェントの完了後終了手順 |
| `test-conventions` | テストコードを作成または修正する、またはテストを実施して結果を報告する |
| `verify-file-writes` | `write_file` や `edit_file` でマルチバイト文字を含むファイルを大きく更新する、または文書をレビューする |

### スキル

| スキル | 内容 |
| --- | --- |
| `cf-cli` | Cloudflare 公式 CLI `cf` の実行方法、認証、コマンド検索、wrangler との使い分け |
| `chrome-extension-real-input-testing` | MV3 Chrome 拡張を実 UI（trusted イベント）で検証する際の環境対策と入力手順 |
| `cloudflare-access-setup` | Cloudflare Access（Zero Trust）で Pages サイト等を保護する設定手順 |
| `codebase-contract-extract` | 未知ディレクトリの公開シンボル、不変条件、副作用を根拠引用付きで単発抽出する軽量契約調査手順と BFS スコープ探索 CLI |
| `concise-ui-copy` | UI 作成時に冗長なガイド文や不要なセカンダリラベルを排除する基準と書き換え例、画面の視覚や文言の自動一次検査プリセット |
| `devin-cli-delegate` | Antigravity の各実行基盤から Devin CLI（ローカル非対話）へ軽量タスクを委任し統合する手順 |
| `gemini-decisions-api` | Gemini Decision 1（Decisions API）による一括確率判定の実装手順、バッチ検証 CLI、PreToolUse 安全ガードレール |
| `github-actions-ci` | GitHub Actions で必須チェックを壊さないジョブスキップ、権限とロック固定、リリース前後検証、定期監査を設計または監査する手順 |
| `invariant-gate` | 任意の Git リポジトリの git diff とルール文書を Gemini Decision 1 で突合し不変条件の違反候補を抽出する汎用検査スキルと CLI |
| `japanese-tech-writing` | 日本語の技術文書と書籍原稿の文章規範、差分検査、スロップリンター |
| `output-format-escalation` | 説明、調査、分析の成果物における表現形式（文章、図、HTML）の選択基準と納品方法 |
| `plugin-authoring` | `shared-skills` プラグインにルールやスキルを追加、変更、構造検査する手順 |
| `pr-review-triage` | PR レビュー指摘の実物照合トリアージ、Decision 1 一次プリラベル CLI、PR 内再発防止策の引き継ぎと `invariant-gate` 連携 CLI、複数セッション分別、未 Resolve スレッド整理、Stage 3 後の Devin Review 状態確認・再トリガ CLI と事後検証の手順 |
| `repo-drift-audit` | リポジトリの文書、スキル、テストとコードの乖離や重複を Decision 1 一次スクリーニングと 2 段サブエージェントで監査する手順 |
| `requirements-definition` | 要件定義書や仕様書のレビュー、協議、決定記録、実装計画への分解を進める手順 |
| `session-context-audit` | 過去セッションの transcript.jsonl を横断解析し、コンテキスト消費・キャッシュヒット率・ルール遵守・品質代理指標の前後比較と Decision 1 タスク層別診断を行う手順と CLI |
| `session-handoff` | 現在のセッションを軽量に区切り、Decision 1 による重要ステップ事前選別 CLI を使い、引き継ぎメモと再開プロンプトで次セッションへ渡す手順 |
| `spec-cold-review` | 実装前の仕様書や計画書を履歴ゼロの視点で監査する手順、Heilmeier と TRIZ の観点、Decision 1 事前検査プリセット |
| `systems-pre-pr-audit` | 常駐システムと複数モジュール境界における有界性、停止順、時間軸、原子性、認可とタイムアウトの PR 前監査 |
| `test-suite-pruning` | 既存テストスイートの保護対象一次フィルタ CLI、履歴と仕様の裏取りに基づく不要テスト削除、重複統合、孤立補助コード掃除の手順 |
| `user-work-runbook` | 実装計画内のユーザー手作業をコード裏取りに基づいて手順書化し Artifact で納品する手順 |
| `windows-cli-pitfalls` | Windows 環境（PowerShell と Git Bash）での文字コード、環境変数、引用、gh CLI の罠と回避策 |

## 構成

- `plugin.json`: プラグインのマニフェスト
- `hooks.json`: ツール実行前ガードレール（`PreToolUse`）を定義するライフサイクルフック設定（`enabled` で切り替え可能）
- `rules/AGENTS.md`: 全セッションで常時読み込まれる共通ルール
- `rules/*.md`: `trigger: model_decision` により状況に応じて読み込まれるルール
- `skills/<name>/SKILL.md`: 専門手順やリファレンス、補助スクリプトをまとめたスキル
