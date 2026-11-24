---
trigger: model_decision
description: 再利用可能なルールやスキル(SKILL.md)を新規作成する、保存する、ほかのセッションやワークスペースと共有したい、と判断したとき
---

# 再利用可能なルールとスキルは shared-skills プラグインに集約する

再利用可能なルールやスキルを作成したとき、またはその保存や共有を求められたときは、`shared-skills` プラグインに登録する。
特定リポジトリに閉じない共通のルールとスキルは、このプラグインを共有の管理場所とする。

## 手順

1. `~/.gemini/config/plugins/shared-skills/AGENTS.md` でディレクトリ分離構成を確認し、本番稼働先を直接編集せず PR 作業用クローンで作業する。
2. スキル `plugin-authoring` を呼び出し、置き場所の判断、作成、構造検査(`check_plugin.py --version-base origin/main`)、PR 作成を進める。
3. PR マージ後に本番稼働先(`~/.gemini/config/plugins/shared-skills`)で `git pull --ff-only origin main` を実行した次のターンから自動的に読み込まれることをユーザーへ伝える。

## 対象外

- 個人用の一度きりの使い捨てスキル
- リポジトリ固有の手順を書くルールやスキル(作業対象のリポジトリ内の `.agents/skills/`、`.agents/rules/`、または `AGENTS.md` に置くべきもの)
