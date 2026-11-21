---
trigger: model_decision
description: Antigravity の各実行基盤から外部の Devin CLI を呼び出して調査やテキスト生成を委任するとき
---

# Devin CLI の呼び出しは無料モデルと読み取り専用に限定する

Antigravity から外部の Devin CLI を呼び出すときは、無料枠のモデルと読み取り専用の出力だけを使い、意図しないクォータ消費とファイル競合を防ぐ。
実行方法と並列制御の詳細手順はスキル `devin-cli-delegate` を参照する。

## 手順

1. ローカル実行では既定として `--model swe-2-max` を明示し、`*-lightning` などの有料モデルや期間限定無料の `swe-2-flash-*` を指定しない。
2. 非対話実行（`-p`）では `--permission-mode` を既定値 `auto` のまま維持し、調査や雛形テキストの出力だけに使ってファイル編集は Antigravity 側で行う。
3. `--cloud` と `-p` を組み合わせた自動非対話呼び出しは行わない。
   - 執筆時点（2026-11、`devin 3000.11.3`）の `devin acp --help` では `--cloud` 時に `--model` が無視されると記載されており、意図せず有料枠を消費する恐れがある。
4. 実行前に環境変数 `ACP_BACKEND` を除去し、Windows 上でのプロンプト渡しと並列制御はスキル `devin-cli-delegate` と `windows-cli-pitfalls` に従う。

## 対象外

- ユーザーが明示的に有料モデルやクラウド対話セッションの利用を指示した場合
- ユーザーが直接ターミナルで対話的に `devin` や `devin --cloud` を操作する場合
- 外部の Devin CLI を使わずに Antigravity 内のツールだけで完結する作業
