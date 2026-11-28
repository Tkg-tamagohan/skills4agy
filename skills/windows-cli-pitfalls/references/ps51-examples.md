# PowerShell 5.1 と gh CLI の回避策コード例

Windows PowerShell 5.1 環境で `gh` CLI、UTF-8 テキスト、外部コマンド引数を安全に扱うためのコード例をまとめる。

## gh CLI へのマルチバイト本文と一時ファイル書き出し

GraphQL ミューテーションへ日本語を渡す場合は、Python の `json.dumps` で本文を文字列化して `subprocess.run` から実行する。

```python
import json, subprocess

q = 'mutation { addPullRequestReviewThreadReply(input: {pullRequestReviewThreadId: "%s", body: %s}) { comment { id } } }' % (
    tid,
    json.dumps("日本語の返信本文", ensure_ascii=False),
)
r = subprocess.run(["gh", "api", "graphql", "-f", "query=" + q], capture_output=True, text=True, encoding="utf-8")
print(r.stdout)
```

一時ファイルへ日本語を書き出す際は、`Set-Content -Encoding UTF8` を使わず `[System.IO.File]::WriteAllText` でリポジトリ外へ BOM なし UTF-8 を出力する。

```powershell
# NG（Set-Content -Encoding UTF8 は BOM \ufeff を付与し、作業ツリーへ一時ファイルが残り得る）
"日本語コミットメッセージ" | Set-Content -Path commit_msg.txt -Encoding UTF8; git commit -F commit_msg.txt
# OK（リポジトリ外へ BOM なし UTF-8 で書き出し、実行後に削除する）
$msg = Join-Path $env:TEMP "commit_msg.txt"
[System.IO.File]::WriteAllText($msg, "日本語コミットメッセージ", [System.Text.UTF8Encoding]::new($false))
git commit -F $msg; Remove-Item $msg
```

Markdown のバッククォート（`` `n `` や `` `t `` や `` `0 ``）を含む PR 本文や JSON を PowerShell から一時ファイルへ書き出すときは、二重引用ヒアストリング `@"..."@` ではなく単一引用ヒアストリング `@'...'@` または Python を使う。

```powershell
# NG（@"..."@ は `n や `t を制御文字へ展開し、PR 本文や JSON を破壊する）
$body = @"
仕様の `n と `t を説明する。
"@

# OK（単一引用ヒアストリング @'...'@ と UTF8Encoding($false) でそのまま BOM なし UTF-8 へ書き出す）
$bodyPath = Join-Path $env:TEMP "pr-body.md"
$body = @'
仕様の `n と `t を説明する。
'@
[System.IO.File]::WriteAllText($bodyPath, $body, [System.Text.UTF8Encoding]::new($false))
gh pr edit --body-file $bodyPath
Remove-Item $bodyPath
```

```python
# OK（Python から BOM なし UTF-8 で Markdown や JSON を一時ファイルへ書き出す）
from pathlib import Path
import os

body_path = Path(os.environ["TEMP"]) / "pr-body.md"
body_path.write_text("仕様の `n と `t を説明する。\n", encoding="utf-8")
```

## 外部コマンド引数の引用符剥離と $ 展開

PowerShell 5.1 ではシングルクォート内でも外部コマンドへ渡る `"` が剥離するため、短いワンライナーは外側を二重引用符にし、複雑な整形は `scratch/*.py` へ切り出す。

```powershell
# NG（シングルクォート内でも " が剥離し、二重引用内では $ と \" が崩れる）
gh pr view 5 --json body --jq '.body | split("\n")'
python -c 'import pathlib; print(pathlib.Path("a.txt").read_text("utf-8"))'
gh api graphql -f query="query(\$num: Int!) { ... }"
# OK（短いワンライナーは外側を二重引用、内側を単一引用にし、複雑な処理は scratch/*.py へ保存する）
python -c "import pathlib; print(pathlib.Path('a.txt').read_text('utf-8'))"
$env:PYTHONUTF8="1"; $env:PYTHONIOENCODING="utf-8"; python "...\scratch\inspect_pr.py"
```

```python
# scratch/inspect_pr.py（--jq の複雑な整形を避け json.loads で処理する）
import json, subprocess

r = subprocess.run(["gh", "pr", "view", "5", "--json", "body"], capture_output=True, text=True, encoding="utf-8", check=True)
print(json.loads(r.stdout)["body"].splitlines())
```

## UTF-8 読み取り、Start-Process 引用、.NET 例外、PSModulePath

BOM なし UTF-8 の読み取り、空白を含むパスの `Start-Process` 渡し、`.NET` 例外の失敗終了、および PS 6/7 混在環境での `PSModulePath` 整理は次の書き方を基準にする。

```powershell
# UTF-8 読み取り / Start-Process の空白パス保護
$text = [System.IO.File]::ReadAllText($path, [System.Text.UTF8Encoding]::new($false))
Start-Process -FilePath $exe -ArgumentList @("--config", "`"C:\Program Files\App\cfg.json`"")
# .NET 例外で失敗終了させ、原因判定時は InnerException 連鎖を辿る
$ErrorActionPreference = 'Stop'; $c = New-Object Net.Sockets.TcpClient
try { $c.Connect('127.0.0.1', 8080) } finally { $c.Dispose() }
# 既定配置の PS 6/7 由来 PSModulePath を除去し Security モジュールを明示読込
$env:PSModulePath = (($env:PSModulePath -split ';') | Where-Object { $_ -and $_ -notmatch '\\PowerShell(\\|$)' }) -join ';'
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -Force
```
