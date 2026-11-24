---
name: codebase-contract-extract
description: 既存コードベースの公開仕様、不変条件、副作用をスコープ探索とボトムアップ集約で単一レポートへ抽出する手順。未把握コードの構造や制約を実体から整理するときに使用する。既存文書との乖離監査は repo-drift-audit に委ねる。
---

# コードベースのボトムアップ仕様抽出

既存コードベースのディレクトリ構成から公開インターフェース、不変条件、および副作用を推測なしで抽出し、葉から親へ向けて単一の統合レポートへまとめる手順を定める。
ゴールは各ディレクトリへ `README.md` を量産して文書ドリフト負債を増やすことなく、コード実体へ引用紐付けされた仕様一覧を最小コストで得ることである。

## 責任範囲の境界

- **既存文書との乖離監査と大規模整理**：ドキュメントとの整合確認やリファクタ計画への展開は `repo-drift-audit` に委ねる。
- **Devin CLI への外部委任**：無料枠モデル `swe-2-max` での呼び出し手順と並列制限は `devin-cli-delegate` とルール `external-agent-devin` に委ねる。
- **サブエージェントの終了管理**：`invoke_subagent` 完了後の解放手順はルール `subagent-cleanup` に委ねる。
- **Windows シェルと UTF-8**：PowerShell 5.1 の構文制限と `PYTHONUTF8` 設定は `windows-cli-pitfalls` に委ねる。

## 出力先と量産禁止の制約

本スキルではディレクトリごとの `README.md` ファイルを一括生成する行為を禁止する。
生成後にコードへ追随できなくなった散在ドキュメントが継続的な乖離負債を生むためである。

- **既定の出力先**：`<Artifact Directory Path>/scratch/contract-<slug>.md` への書き出し、またはチャット本文への直接出力とする。
- **リポジトリ内への書込**：ユーザーが単一の出力パスを明示的に指定した場合に限り、その 1 ファイルへ書き込む。

## 手順

### 1. 決定論的スコープ探索

同梱の `scripts/discover_contract_scope.py` を実行し、後行順（`leaf` -> `intermediate` -> `root`）の対象ディレクトリ一覧、承認要否、推奨実行モード、および優先度付きチャンク計画を取得する。
このスクリプトは `os.scandir`（`follow_symlinks=False`）の BFS で走査し、除外ディレクトリ、テスト専用ディレクトリ、`.gitignore` 対象、`.env` 系秘密ファイル、ロックファイル、スタイルシート、非 UTF-8 バイナリを除外したうえでボトムアップ剪定を行う。

```powershell
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"
python "$HOME/.gemini/config/plugins/shared-skills/skills/codebase-contract-extract/scripts/discover_contract_scope.py" --root . --format json
```

ディレクトリ内のファイルはスキーマやビルド定義、エントリーポイント（`main.*`、`index.*`、`lib.*`、`mod.*`、`__init__.py`）、一般ソースコード昇順の順に並び替え、`--chunk-lines`（既定 `1500` 行）以内のチャンクへ梱包する。
単一ファイルが `--chunk-lines` を超える場合も途中で分割せず 1 チャンクに保持し、出力 JSON の `dir_count`、`requires_approval`、`recommended_mode`、`directories` を次工程の入力として使う。

### 2. 承認判定と解析モードの選択

Step 1 の JSON 出力に含まれる `requires_approval` と `recommended_mode` に従って実行方針を決める。

1. `requires_approval` が `true`（`dir_count > 15`）の場合は、解析を進める前にユーザーへ対象ディレクトリ数とチャンク数を提示して確認を求める。
2. `recommended_mode` が `"direct"`（`dir_count <= 5`）の場合は、親セッションがチャンク順に対象ファイルを直接読み込み、`references/extract-prompt.md` のスキーマに沿って 3 項目を抽出する。
3. `recommended_mode` が `"delegated"`（`dir_count >= 6`）の場合は、チャンク単位の解析を外部または読み取り専用サブエージェントへ委任する。
   - **Devin CLI を使う場合**：`devin-cli-delegate` に従い、`ACP_BACKEND` を除去したうえで `--model swe-2-max` かつ `--permission-mode auto` の読み取り専用で同時実行数を 2 以下に制限して実行する。
   - **サブエージェントを使う場合**：`invoke_subagent`（`TypeName: "research"`）で読み取り専用解析を依頼し、結果受領後は `subagent-cleanup` に従い `manage_subagents` で確実に終了させる。

委任プロンプトには `references/extract-prompt.md` の抽出スキーマと推測禁止規則を必ず含め、プロンプトファイル経由で渡して標準出力から JSON を回収する。

### 3. ボトムアップ統合と実在確認

葉ディレクトリ（`leaf`）の JSON 抽出結果から順に中間ディレクトリ（`intermediate`）とルート（`root`）へ集約し、最終レポートを組み立てる。

1. 各出力の `interface`、`invariants`、`side_effects` について、該当なしが `["None"]` であることを確認する。
2. すべての項目末尾に `[file:symbol_or_flag]` 形式の引用が付いているか点検し、引用を欠く記述やディレクトリ名から推測した記述は削除または実コードで再確認する。
3. 引用中のファイルパス、シンボル名、CLI フラグ名が実際のチャンク内ファイルに存在することを照合してから、`references/extract-prompt.md` の Markdown テンプレートで既定の出力先へ出力する。

## 原則

- 対象範囲の確定とチャンク分割は `discover_contract_scope.py` で決定論的に行い、テストや秘密ファイルを読まない。
- ディレクトリ名やファイル名から仕様を推測せず、確認できたコード実体と `[file:symbol_or_flag]` 引用だけを出力する。
- ディレクトリ別 `README.md` の一括生成は行わず、出力は `<Artifact Directory Path>/scratch/contract-<slug>.md` またはチャット本文の単一箇所へ集約する。
