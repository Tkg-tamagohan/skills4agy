# Review Guidelines

本ファイルは Devin Review による PR レビューの重点方針を定める。
AGY App 側で指摘のトリアージと修正を行うため、誤検知と重複を抑え、高リスクな不具合へ集中する。
`AGENTS.md` や `rules/AGENTS.md` に記載済みの規約は本書で再掲せず、CI では判定できない規約違反はそのまま指摘対象とする。
一方、CI の機械検査（`check_plugin.py`、`check_hygiene.py`）が検知する項目は重複指摘しない。

## レビュー言語

すべてのコメント、指摘、補足は日本語で出力する。

## 重点チェック領域（Critical Areas）

以下のパスに対する変更は、影響範囲と障害コストが大きいため重点的に精査する。

- `hooks.json`、`skills/gemini-decisions-api/scripts/pretool_guard.py`（全 `run_command` 実行前のガードレール、タイムアウト 15 秒）
- `skills/gemini-decisions-api/scripts/decision_hygiene.py`、`decision_common.py`、`run_decisions.py`（複数スキルから直接参照される共有モジュール）
- `skills/pr-review-triage/scripts/pr_ops.py`、`check_devin_review.py`、`pr_guardrails.py`、`triage_decision1.py`（Git 操作、GraphQL 更新、Devin API 連携）
- `.github/workflows/ci.yml`、`skills/plugin-authoring/scripts/check_plugin.py`、`check_hygiene.py`、`new_entry.py`、`run_all_tests.py`（CI とプラグイン検証）
- `skills/japanese-tech-writing/scripts/`（CI の `check_hygiene.py` が呼び出す `slop_lint.py` と関連スクリプト）
- `rules/AGENTS.md`（全セッションで常時読み込まれる共通ルール）

## 優先して指摘してほしい観点

- **diff 外への波及と後方互換性の破壊**：`skills/` 配下は `sys.path` や `importlib` で共有スクリプトを直接読み込むため、関数シグネチャ、戻り値形式、定数、終了コードの変更が別スキルの呼び出し元を壊していないか確認する。
- **PreToolUse ガードレールの回避と不整合**：引用符、ヒアドキュメント、サブシェル、ラッパーコマンド、パス走査、シンボリックリンクや Windows のリパースポイントによる検査回避がないか、異常系やタイムアウト超過時に誤って `allow` を返したりクラッシュしたりしないか確認する。
- **セキュリティと秘密情報の保護**：秘密情報のマスクを文字列切り詰めより先に実行しているか、エラー出力や dry-run 経路を含めて URL エンコード済みの秘密値を漏らしていないか、実在 `.env` や秘密鍵の読み込みとステージングを遮断しているか、API キーを CLI 引数で受け取ったり出力したりしていないか確認する。
- **外部コマンドと API 呼び出しの安全性**：`subprocess` で `shell=False` を保っているか、`--` によるオプション注入防止があるか、保護ブランチや対象 PR 外の GraphQL スレッドを誤操作しないか、`check_devin_review.py` の接続先制限が緩んでいないか確認する。
- **境界値、状態管理、エラー処理の漏れ**：未置換プレースホルダの残留、ファイル生成時のロールバック漏れ、並行実行時の競合、JSON や数値判定（Python の `bool` は `int` のサブクラス）の取りこぼしがないか確認する。
- **Windows と UTF-8 の互換性**：標準入出力とファイル入出力で明示的な UTF-8 指定があるか、日本語パス向けに `git -c core.quotePath=false` と区切り正規化を行っているか、BOM や `U+FFFD` を混入させないか確認する。
- **Decisions API 固有の仕様**：二値質問の型に `"noul"` を使っているか（`"bool"` は不可、`choice` や `score` は用途に応じて許可）、しきい値が `(0.01, 0.99)` の範囲内か、HTTP 400 と HTTP 200 の双方の安全ブロックを処理しているか確認する。

## 指摘を抑えてほしい観点と除外対象（Ignore）

### 抑えてほしい指摘

- フォーマット、空白、命名の好みなど主観的なスタイル指摘。
- CI の `check_plugin.py` と `check_hygiene.py`（`slop_lint --strict` を含む）が機械的に検知する書式、frontmatter、行数、README 同期、文体の指摘。
- PR の議論済みスレッドや意図的な設計と明示された箇所への重複指摘。
- GitHub の Suggested change 構文を前提とした提案。

### 除外対象（実パス）

- `skills/japanese-tech-writing/LICENSE-yomiyasu`（転用元の MIT ライセンス原文）
- `skills/japanese-tech-writing/references/lists/*.txt`（静的語彙リスト）
- `skills/japanese-tech-writing/references/slop-catalog.md`、`calques.md`（禁止表現のサンプル集）
- `skills/plugin-authoring/rule-template.md`、`skill-template.md`（新規作成用テンプレート）
- `skills/**/test_*.py` 内のダミー秘密値、コンフリクトマーカー、`U+FFFD` のテストデータ（テスト自体のロジック不備や OS 依存バグは指摘してよい）

### 意図的な設計例外

- `skills/` 配下に `__init__.py` を置かず、Python 標準ライブラリ中心で `sys.path` と `importlib` により単体実行する構成。
- `pretool_guard.py` がエラー時や `GEMINI_API_KEY` 未設定時に終了コード `0` で `{"decision": "ask"}` を返すフォールバック挙動と、高速判定のための `.git/config` 直接読み取り。
- `rules/AGENTS.md` に YAML frontmatter を置かない構成（常時適用ルールのため）。
- `check_devin_review.py` の通常照会時に認証情報未設定なら `fallback_github_only`（終了コード `0`）へ縮退する挙動。
- `pr_ops.py` の `invariant-check` で一時 `GIT_INDEX_FILE` と `GIT_OBJECT_DIRECTORY` を使う読み取り専用スナップショット処理。
- `skills/japanese-tech-writing/scripts/` で上流 `nanaism/yomiyasu` 由来の構造や Windows 向け `os.path.abspath` を保持している点。
<!-- 意図的な設計例外を追加する場合は、この行の上へ箇条書きで追記する -->

## 指摘の書き方（トリアージ向け）

各指摘は AGY App 側で誤検知か否かを即座に判定できるよう、次の 3 点を簡潔に含める。

1. **該当箇所**：対象ファイルパス、行番号、シンボル名。
2. **発火条件と影響範囲**：どの入力、環境、呼び出し経路で何が起きるか（diff 外への波及を含む）。
3. **性質の区分**：再現可能な不具合や脆弱性の指摘か、仕様確認の質問かを明示する。
