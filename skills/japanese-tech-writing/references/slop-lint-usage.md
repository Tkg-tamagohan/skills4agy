# スロップリンターの運用手順

`scripts/slop_lint.py` の実行方法と検出結果の読み方をまとめる。
単一ファイルの検査は SKILL.md の機械検査節に記したコマンドを使う。

## CLI の仕様

使い方は `python "$HOME/.gemini/config/plugins/shared-skills/skills/japanese-tech-writing/scripts/slop_lint.py" [ファイル] [--json] [--strict] [--fail-on {warn,error}]` で、ファイルを省略するか `-` を渡すと標準入力を読む。
詳しい説明は `--help` で表示する。

- `--json` は結果を JSON(形式2)で出力する。
- JSON の主なキーは `format`(`yomiyasu-lint`)、`format_version`(2)、`tool_version`、`candidate_count`、`counts`(error、warn、info の件数)、`no_rule_findings`、`rule_penalty_score`、`not_judged`、`context`、`metrics`、`findings`。
- `--strict` は warn か error の候補が1件でもあれば終了コード1で終わる。
- `--fail-on` は指定した重さの候補があれば終了コード1で終わる。
- `--fail-on` には `warn`(warn か error の候補)と `error` を、カンマ区切りまたは繰り返しで指定できる。
- `meaning-risk` は意味リスクの判定が別計画のため lint では使えない(判定には2つの文章の比較が必要で、現在はどのコマンドでも使えない)。
- 点数(`rule_penalty_score`)は `--strict` と `--fail-on` の条件に使えない。
- info の候補は `--strict` と `--fail-on` の条件に入らない。
- `rule_penalty_score` は上流 2.2.0 以降で足した規則の候補を数えず、残りの候補を地の文1,000字あたりの密度に直して計算する(行の候補は error 3、warn 2、info 1 の重さ、excess_bold と excess_list は1件で2、bold_label_list は1を足し、negative_parallelism_density は数えず、細かい決まりは `--help` の末尾にある)。

終了コードの意味は次のとおり。

- 0 は検査を最後まで実行して `--strict` と `--fail-on` の条件に当たらなかった場合で、候補の有無によらない。
- 1 は `--strict` か `--fail-on` の条件に当たった場合。
- 2 は使い方か入力の誤り(ファイルを開けない、作業フォルダの外や名前が点で始まる部分を含むパス、UTF-8 として読めない、使えない `--fail-on` の値、語の一覧の誤り)。
- 3 は予期しない内部エラーか、出力先が閉じられて結果を最後まで書けなかった場合。

通常出力(`--json` なし)は見出し3行を出し、候補があれば内訳(error、warn、info の件数)と行番号順の候補の並びを続ける。
条件に当たったときは末尾に終了コード1の内訳を足す。
語の一覧は作業ディレクトリから上へたどった git の最上位の `.yomiyasu-words/`(allow.txt、flag.txt、flag-patterns.txt)を自動で探し、使ったときは出力に1行足す。

`rule_penalty_score` は候補の多さを地の文の長さで割った目安で、品質や合否の点数ではない。
CI では `--strict` か `counts` を使う。

## 一括検査

リポジトリ直下に `.sloplintignore` がある構成では、除外対象を `.sloplintignore`（gitignore 形式のパス一覧で、1 行 1 件）で管理する。
`references/slop-catalog.md` は禁止語彙のカタログ自体であり言及が規範抵触として検出されるため、恒久除外の対象とする。
`.sloplintignore` を置かない構成では、各検査コマンド側で `references/slop-catalog.md` と対象外のディレクトリ（`.git` や依存パッケージ配下、作業用下書きなど）を除外する。

Git 管理下のリポジトリで `.sloplintignore`（存在する場合）を適用して全対象を `--strict` で検査する手順は次のとおり。
スキルを標準のプラグイン配置先以外に置いている場合は、`"$HOME/.gemini/config/plugins/shared-skills/skills/japanese-tech-writing/scripts/slop_lint.py"` を実際の配置パスへ読み替える。

```bash
status=0
excluded=$(mktemp); trap 'rm -f "$excluded"' EXIT
if [ -f .sloplintignore ]; then
  git ls-files -z -c -i -X .sloplintignore -- '*.md' > "$excluded"
else
  : > "$excluded"
fi
while IFS= read -r -d '' f; do
  grep -qzxF -- "$f" "$excluded" && continue
  case "$f" in references/slop-catalog.md|*/references/slop-catalog.md) continue ;; esac
  PYTHONUTF8=1 PYTHONIOENCODING=utf-8 python "$HOME/.gemini/config/plugins/shared-skills/skills/japanese-tech-writing/scripts/slop_lint.py" --strict "$f" || status=1
done < <(git ls-files -z -- '*.md')
exit $status
```

AGY の Windows 環境や `.gemini` 配下（パス制限により直接引数で読めない場合）では、Python から標準入力 `-` 経由で一括検査する。
PowerShell では `$env:PYTHONUTF8="1"` と `$env:PYTHONIOENCODING="utf-8"` の両方を設定し、終了コード `2` や `3` のエラー理由も欠落させないため `stdout` と `stderr` を合わせて出力する。

Git 管理下のリポジトリでは、`git ls-files` と `.sloplintignore`（存在時）を用いて追跡対象だけを検査する。

```powershell
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"; python -c "import pathlib, subprocess, sys; lint = sys.argv[1]; git = lambda *a: subprocess.run(['git', '-c', 'core.quotePath=false', *a], capture_output=True, text=True, encoding='utf-8', check=True).stdout.split('\0')[:-1]; excl = set(git('ls-files', '-z', '-c', '-i', '-X', '.sloplintignore', '--', '*.md')) if pathlib.Path('.sloplintignore').is_file() else set(); files = [pathlib.Path(f) for f in sorted(git('ls-files', '-z', '--', '*.md')) if f not in excl and not f.endswith('references/slop-catalog.md')]; failed = [(str(p), (r.stdout + r.stderr).decode('utf-8', 'replace').strip()) for p in files for r in [subprocess.run([sys.executable, lint, '--strict', '-'], input=p.read_bytes(), capture_output=True)] if r.returncode != 0]; print('\n'.join(f'=== {f} ===\n{o}' for f, o in failed) if failed else 'ALL_CLEAN'); sys.exit(bool(failed))" "$HOME/.gemini/config/plugins/shared-skills/skills/japanese-tech-writing/scripts/slop_lint.py"
```

Git 管理外のディレクトリや未追跡ファイルも検査する場合は `Path('.').rglob('*.md')` で走査できるが、`.sloplintignore` は解釈されないため、`.git` などの隠しディレクトリや不要ディレクトリと `slop-catalog.md` 以外の除外対象を条件へ明示的に追加する。

## 語の一覧(.yomiyasu-words/)

`.yomiyasu-words/` の3つのファイルの役割は次のとおり。
空行と `#` で始まる行はどのファイルでも除く。

- `allow.txt` は指摘を外す語を1行に1語で書き、当たった語が一覧にあれば候補を外すか、その語を除いて残す(規則ごとの決まりは `slop_lint.py` の `_ALLOW_RULES`)。
- `flag.txt` は見直す語を1行に1語で書き(「使わない語<TAB>使う語」の2列目の使う語は指摘の message に添える)、その語には `project_term` が info で出る。
- `flag-patterns.txt` は見直す語の名前と正規表現を「名前<TAB>正規表現」で1行に1組書き、flag.txt と同じく `project_term` が出る(取り込む組 `( )` は使えず、`(?: )` と書く)。

## 検出結果の読み方

- 検出結果は機械的な見直し候補であり、本規範で正当な記述（定義語の太字、定義列挙の箇条書き、「」による言及、必要な推量表現、文脈上正当な専門用語など）に対する指摘は本規範を優先して保持する。
- 太字頻度と箇条書き比率の指摘は情報（info）として出るため、文書全体の装飾傾向を把握する目安として使い、本規範が許容する記法で閾値を超えているだけなら修正しない。
- 修正の試行は最大二回までとし、警告を消すためだけの過剰な言い換えループを避ける。
- 語彙の判断には `references/slop-catalog.md` を参照する。
- 既存の長大な文書へ部分追記したときは、`--strict` が未編集の既存行でも終了コード 1 を返す前提を踏まえ、編集行で新たに増えた指摘と既存の既知警告を切り分けて評価する。
- リポジトリの整合チェッカーが単一行テーブル書式などを要求する文書では、`one_sentence_per_line` 等の警告を消すために表構造を壊さない。
