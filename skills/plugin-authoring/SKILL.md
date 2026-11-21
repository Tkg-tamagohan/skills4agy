---
name: plugin-authoring
description: shared-skills プラグインにルールやスキルを追加または変更する手順。置き場所(rules/AGENTS.md、rules/、skills/)の判断、粒度と構成の指針、テンプレートからの作成、plugin.json のバージョン更新、構造検査を扱う。共有すべきルールやスキルを新規作成する、既存のものを統合または分離する、または shared-skills プラグインを編集するときに使用する。日本語の文体規範は japanese-tech-writing に委ねる。
---

# shared-skills へのルールとスキルの追加と変更

`~/.gemini/config/plugins/shared-skills` にルールやスキルを追加または変更するときは、以下の手順で進める。
ゴールは、追加した内容が他のファイルと重複せず、読み込まれるべき状況でだけ読み込まれる状態にすることである。

置き場所と粒度の判断基準は同じディレクトリの `guidelines.md` に、ファイルの型は `rule-template.md` と `skill-template.md` にある。
判断に迷ったら本文で推測せず、`guidelines.md` の判断表に戻る。

## 責任範囲の境界

- **文章の文体**：日本語の本文は `japanese-tech-writing` に従う。
  - 本スキルは文体を定めない。
- **リポジトリ固有の手順**：作業対象リポジトリにしか関係しない手順は本スキルの対象外とし、そのリポジトリの `.agents/skills/`、`.agents/rules/`、または `AGENTS.md` に置く。
- **生成と記帳の機械化**：命名規約の検査、テンプレートの複写、README 収録一覧への行追加、`plugin.json` の version バンプは `scripts/new_entry.py` が担う。
  - 置き場所と粒度の判断、description と本文の執筆だけがモデルの仕事である。

## 手順

1. `guidelines.md` の判断表で置き場所を決める（`rules/AGENTS.md` の節、`rules/<name>.md`、`skills/<name>/SKILL.md` のいずれかになる）。
2. `rg` でキーワードを検索して既存の内容と重複しないか確認し、同じ状況を扱うファイルがあれば新規作成ではなくそのファイルの修正か統合にする。
3. `scripts/new_entry.py` でファイルと記帳を生成する。
   - `$env:PYTHONUTF8="1"; python skills/plugin-authoring/scripts/new_entry.py rule <name> --summary "<README の収録一覧に載せる一文>"` を実行する。
   - skill の場合は `skill` を指定する。
   - 命名規約と重複の検査、テンプレート(`rule-template.md`、`skill-template.md`)の複写、README 収録一覧への行追加、`plugin.json` の version バンプ(追加なのでパッチ)までをスクリプトが行う。
   - 生成されたファイルの description と本文はモデルが埋める。
4. 作成した内容を `guidelines.md` のチェックリストで点検する。
   - 特に description は、モデルが読むかどうかを決める唯一の材料なので、読み込むべき状況が一文で特定できることを確認する。
   - 機械化できる項目は `python skills/plugin-authoring/scripts/check_plugin.py` の実行でも確認する。
   - description の状況特定など判断が要る項目は引き続き目視で確認する。
5. `plugin.json` の `version` を規約どおりに上げる。
   - 手順 3 の生成では追加の分のパッチが済んでいる。
   - 生成を伴わない修正(既存ファイルや `rules/AGENTS.md` の変更)と、移動、改名、削除を含む変更では、`new_entry.py bump`（削除や改名時は `--level minor`）でバージョンを上げる。
6. `README.md` の収録一覧は手順 3 で `--summary` の文による行が追加済みである。
   - 構成の説明に影響する変更(ディレクトリ追加、ファイルの改名など)は引き続き手で追随させる。
7. 変更完了後、登録または更新した内容は次のターンから自動的に読み込まれることをユーザーへ伝える。

## 既存のルールやスキルを見直すとき

統合や分離を判断するときも `guidelines.md` の基準に従う。
改名や移動を含む変更では、README、他ファイルからの参照、および `plugin.json` のバージョンをあわせて更新する。
