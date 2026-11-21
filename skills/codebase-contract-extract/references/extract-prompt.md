# 抽出プロンプトとボトムアップ統合テンプレート

本ファイルは `codebase-contract-extract` でチャンク解析の委任時と最終のボトムアップ統合時に使用する抽出スキーマ、検証規則、および Markdown テンプレートを定める。

## チャンク抽出用プロンプト定型

`devin-cli-delegate`（`--model swe-2-max` かつ `--permission-mode auto` の読み取り専用）または `invoke_subagent`（`TypeName: "research"`）へ渡す指示文の末尾には、次の抽出規則と JSON スキーマをそのまま埋め込む。
調査対象ファイルの一覧は `discover_contract_scope.py` が出力したチャンクの `files` をそのまま渡し、対象外のテストや `.env` 系ファイルは読ませない。

```text
あなたはコードベースの読み取り専用解析担当である。
ファイルを一切編集せず、指定された対象ディレクトリおよびチャンク内ファイルだけを読んで次の JSON 1 オブジェクトだけを標準出力へ返せ。

出力スキーマ（JSON 以外の前置きや説明文は付けない）:
{
  "directory": "<対象の相対 POSIX パス>",
  "interface": ["<公開関数、RPC、CLI 引数、HTTP エンドポイント、設定キー等の要約> [file:symbol_or_flag]"],
  "invariants": ["<前提条件、境界値、型制約、ロック順、冪等性、エラー条件等> [file:symbol_or_flag]"],
  "side_effects": ["<外部 API 呼び出し、DB/ファイル書込、環境変数参照、サブプロセス起動等> [file:symbol_or_flag]"]
}

厳守事項:
1. ディレクトリ名やファイル名からの推測で RPC、不変条件、副作用を補完しない。
2. 実際に読んだファイル内で確認できた項目だけを記録し、すべての項目末尾に `[file:symbol_or_flag]` 形式の引用を付ける。
3. 該当項目が確認できない節には空配列ではなく `["None"]` を入れる。
4. コード内に存在しないシンボル名やフラグ名を捏造しない。
```

## 中間ディレクトリ集約時の指針

子ディレクトリが複数ある中間ディレクトリ（`kind: "intermediate"`）とルートディレクトリ（`kind: "root"`）を集約するときは、子ノードから受け取った 3 項目をそのまま並べず、親ディレクトリ直下のファイル（エントリーポイントや設定定義）と照合して公開面へ露出する項目とディレクトリ横断の不変条件および副作用だけを引き上げる。

- **子から親への引き上げ**：上位モジュールや外部利用者が依存するインターフェース、複数サブディレクトリをまたぐ不変条件、および集約された I/O 境界だけを残す。
- **推測の遮断**：子ディレクトリの解析結果に含まれない項目を親の名前や構成から補わない。
- **引用の維持**：引き上げた各項目にも `[file:symbol_or_flag]` 引用を必ず残す。

## 最終 Markdown 統合テンプレート

統合結果は既定では `<Artifact Directory Path>/scratch/contract-<slug>.md` またはチャット本文へ出力し、各ディレクトリへ `README.md` を量産しない。
ボトムアップの記載順（`leaf` -> `intermediate` -> `root`）を保ち、次のテンプレートに沿って整形する。

```markdown
# コードベース仕様抽出レポート: <対象ルート名>

- 走査対象ディレクトリ数: <dir_count>
- 抽出モード: <direct / delegated>
- 出力方針: 単一集約出力（ディレクトリ単位 README.md 生成なし）

## 全体サマリー（Root）

- **ディレクトリ**: `.`（`root`）
- **Interface**:
  - <親レベルへ引き上げた公開仕様> `[file:symbol_or_flag]`（該当なしの場合は `None`）
- **Invariants**:
  - <システム全体の不変条件> `[file:symbol_or_flag]`（該当なしの場合は `None`）
- **Side Effects**:
  - <外部通信、永続化、プロセス起動等の副作用> `[file:symbol_or_flag]`（該当なしの場合は `None`）

## 中間ディレクトリ（Intermediate）

### `<intermediate_path>`

- **Interface**:
  - <集約されたインターフェース> `[file:symbol_or_flag]`
- **Invariants**:
  - <集約された不変条件> `[file:symbol_or_flag]`
- **Side Effects**:
  - <集約された副作用> `[file:symbol_or_flag]`

## 末端ディレクトリ（Leaf）

### `<leaf_path>`

- **Interface**:
  - <確認済みの公開仕様> `[file:symbol_or_flag]`
- **Invariants**:
  - <確認済みの不変条件> `[file:symbol_or_flag]`
- **Side Effects**:
  - <確認済みの副作用> `[file:symbol_or_flag]`
```
