---
name: devin-cli-delegate
description: Antigravity の親エージェント、Subagents、run_workflow、および /swarm から外部の Devin CLI を呼び出してコード調査やテスト案と雛形の生成を委任し、結果を統合する手順。無料モデルの UID 指定、同時 2 枠の並列制御、Windows でのプロンプト渡しと ACP_BACKEND 回避、Antigravity 各機能での制約を扱う。Devin CLI（devin -p）を使った外部委任やクォータ温存を行うときに使用する。PowerShell や Python の文字コードと引用の罠は windows-cli-pitfalls、利用制約はルール external-agent-devin に委ねる。
---

# Devin CLI への軽量タスク委任

Antigravity の各実行基盤から外部の Devin CLI（`devin -p`）を呼び出し、無料枠の SWE-2 モデルへ読み取り専用の調査や雛形生成を委任して結果を統合する手順を定める。
ゴールはファイル競合と意図しない課金やクォータ消費を避けつつ、軽量な調査やテキスト生成を外部へ安全に逃がすことである。

## 責任範囲の境界

- **利用上の制約**：無料モデルの限定、自動での `--cloud -p` 実行禁止、読み取り専用限定のルールは `external-agent-devin` に委ねる。
- **Windows シェルと文字コード**：PowerShell 5.1 の構文制限、引用崩れ、`PYTHONUTF8`、一時ファイルパスの扱いは `windows-cli-pitfalls` に委ねる。
- **監査や並列機能の基本手順**：2 段ファンアウト監査は `repo-drift-audit`、動的ワークフローの記法は builtin の `run-workflow`、swarm の進行は builtin の `swarm` に委ねる。

## 前提と構成の現在地

執筆時点（2026-11、`devin 3000.11.3`）における CLI と無料枠の前提は次のとおりである。

- `devin models list --format json` により、`swe-2-medium`、`swe-2-high`、および `swe-2-max` が無料（`cost_tier: "Free"`）であることを確認しており、本スキルでは既定モデルとして `swe-2-max` を使用する。
- 同じ `swe-2` ファミリー内の `*-lightning` バリアントは従量課金であり、`swe-2-flash-*` は無料期間が限られたプロモーション扱いのため、都度確認と期限切れ後の誤課金を避ける目的で指定対象から除外する。
- Pro プランでも能力セレクタに `Free (powered by SWE-2)` が提供されており、メンバー単位の同時実行上限は 2 枠として案内されている。
- ただし `devin acp --help` には `--cloud` 指定時に `--model` が無視されると記載されているため、非対話 `-p` による自動呼び出しはローカル CLI のみに限定し、クラウドを使う場合はユーザーが手動で `devin --cloud` を起動して `Free (powered by SWE-2)` を選択したセッションで扱う。

## 手順

### 1. 事前の環境確認

非対話モード（`-p`）はブラウザ認証やオンボーディング画面を出せないため、先に認証状態とモデル一覧を確認する。
未認証の場合は自動実行を中断し、ユーザーへ通常ターミナルで `devin` や `devin setup` によるログインを案内する。

```powershell
devin --version
devin auth status
devin models list
```

`devin list` は非対話シェル上で対話型のセッション選択画面を開いて入力待ちになるため、自動実行や `run_command` からは実行しない。

### 2. 環境変数のクリアとプロンプト準備

Devin Desktop がシェル環境に `ACP_BACKEND=windsurf` を設定する場合があるため、起動前に環境変数 `ACP_BACKEND` を除去する。
また、日本語や改行、バッククォートを含むプロンプトをコマンド引数へ直接渡すと PowerShell で引用崩れを起こすため、一時ファイル（`<Artifact Directory Path>\scratch\` 配下など）へ UTF-8 で書き出して `--prompt-file` で渡す。

### 3. ローカル非対話実行と出力回収

`--permission-mode` は既定値 `auto`（読み取り専用ツールのみ自動承認）のまま維持し、プロンプト末尾にもファイルを変更せず標準出力へ出すよう明記する。
信頼済みディレクトリ外で実行する場合のみ `--respect-workspace-trust false` を補う。

```powershell
Remove-Item Env:ACP_BACKEND -ErrorAction SilentlyContinue
devin --model swe-2-max -p --prompt-file "<Artifact Directory Path>\scratch\prompt.txt"
```

複数件をまとめて調査する場合は、親エージェントが Python スクリプトを実行して同時起動数を 2 以下に制限する。

```python
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

def run_devin(prompt_path: Path, cwd: Path) -> str:
    env = os.environ.copy()
    env.pop("ACP_BACKEND", None)
    res = subprocess.run(
        [
            "devin",
            "--model",
            "swe-2-max",
            "-p",
            "--prompt-file",
            str(prompt_path),
        ],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return res.stdout

with ThreadPoolExecutor(max_workers=2) as pool:
    results = list(pool.map(lambda p: run_devin(p, Path.cwd()), prompt_files))
```

### 4. Antigravity 側での統合と編集

Devin CLI が標準出力へ返した調査要約、境界値テスト案、またはコード雛形を受け取ったあと、実際のファイル編集と検証は Antigravity 側のエージェントやワーカーが行う。

## Antigravity 機能別の使い分け

### 調査手段の使い分け（親直接 / research / devin -p）

| 手段 | 適した場面 | 前提と制約 |
| :--- | :--- | :--- |
| 親エージェント直接調査 | 数ファイルの確認で済む小中規模の調査 | 親セッションのキャッシュを再利用でき、サブエージェント起動コストを避けられる（`rules/AGENTS.md` の基本方針）。 |
| 組み込み `research` サブエージェント | 外部送信が不可、またはネットワーク不要で親コンテキストを汚さず独立調査や網羅読解を行いたいとき | 読み取り専用かつネットワーク遮断のため `devin` は実行できない。 |
| 親（または Python 並列）＋ `devin -p`（`swe-2-max`） | 外部送信が許可される環境での多ファイル調査、テスト雛形生成、Antigravity クォータ温存 | Python 側で同時 2 枠上限を制御でき、編集と検証は Antigravity 側で行う。 |

### 呼び出し元別の実行設計

| 呼び出し元 | 適した場面 | 並列制御と制約 |
| :--- | :--- | :--- |
| 親エージェントと Python スクリプト | 複数ファイルや複数パッケージの調査を一括で外注するとき（最推奨） | Python の `max_workers=2` などで並列上限を確実に守れるうえ、Antigravity 側のワーカー起動クォータを消費しない。 |
| Subagents（`self` など） | メイン会話のコンテキストを汚さず単発の調査を裏で委任するとき | 同時起動数が 1 枠に収まる。組み込みの `research` サブエージェントは読み取り専用かつネットワーク遮断のため `devin` を実行できない。 |
| Dynamic Workflows（`run_workflow`） | 外部調査の取得後に Antigravity 側で並列編集や多段判定を編成するとき | バッチ分割や `agent(model="flash_lite")` などで同時実行数が上限を超えないよう制御する。 |
| `/swarm` | 担当パッケージごとのワーカーに外部調査と実装を割り当てるとき | ワーカー間で `devin` の同時起動数を調整する仕組みがないため、ロックファイルなどで同時 2 枠以下を調停し、ファイル編集は担当ワーカーが行う。 |

## 原則

- ローカル実行時は既定として `swe-2-max` を明示し、`*-lightning`、期間限定無料の `swe-2-flash-*`、および自動の `--cloud -p` は使わない。
- `devin -p` は `--permission-mode auto` かつ `--prompt-file` 経由の標準出力回収にとどめ、編集作業は Antigravity 側で行う。
- 複数タスクの一括調査は Python スクリプト側で並列数を 2 以下に制御し、Antigravity 側のクォータ消費とセッション上限超過を同時に防ぐ。
