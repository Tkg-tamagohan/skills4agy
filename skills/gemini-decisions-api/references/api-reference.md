# Gemini Decisions API 詳細リファレンス

本リファレンスは 2026年11月時点の Google AI Studio 公式 Decisions API ガイドおよび REST API リファレンスに基づく。
判断基準と質問設計の急所は [SKILL.md](../SKILL.md) を参照する。

## エンドポイントと認証

- **URL**：`POST https://generativelanguage.googleapis.com/v1beta/decisions`
- **認証ヘッダー**：`x-goog-api-key: $GEMINI_API_KEY`
- **Content-Type**：`application/json`
- **モデル**：`gemini-decision-1`
- **SDK 最小バージョン**：`google-genai >= 3.2.0`（Python）、`@google/genai >= 3.2.0`（JavaScript / TypeScript）

## 言語別の実装例

### Python（`google-genai >= 3.2.0`）

```python
import json
from google import genai

client = genai.Client(http_options={"api_version": "v1beta"})

order = {"order": {"id": "8821", "item": "headphones", "price_usd": 240}, "tier": "Gold"}
message = {"message": "Audio cuts out on the left earcup. Fix it today or I cancel."}

result = client.decisions.create(
    model="gemini-decision-1",
    input=[
        {"type": "text", "text": json.dumps(order) + "\n"},
        {"type": "text", "text": json.dumps(message)},
    ],
    questions={
        "is_defect": {
            "type": "noul",
            "instructions": "Does `message` describe a hardware defect?",
            "criteria": {
                "true_description": "The product itself is broken or faulty.",
                "false_description": "Preference, sizing, shipping, or pricing complaint.",
            },
        },
        "next_action": {
            "type": "choice",
            "instructions": "What is the right resolution given `tier` and `order`?",
            "criteria": {
                "instant_refund": "Refund without return for low value or clear fault.",
                "replacement_shipment": "Ship a replacement and return the original.",
                "troubleshooting_flow": "The issue may be fixable by the customer.",
                "other": "Anything outside these options.",
            },
        },
        "churn_risk": {
            "type": "score",
            "instructions": "How likely is the customer to churn without immediate help?",
            "criteria": [
                "No churn signal",
                "Mild frustration",
                "Mentions alternatives",
                "Threatens to cancel",
            ],
        },
    },
)

if getattr(result, "prompt_feedback", None) and result.prompt_feedback.block_reason:
    raise RuntimeError(f"Blocked: {result.prompt_feedback.block_reason}")

answers = result.answers or {}
defect = answers["is_defect"]
route = answers["next_action"]
risk = answers["churn_risk"]
top_level = max(risk.probabilities, key=risk.probabilities.get)
normalized = risk.score / (len(risk.legend) - 1)
print(defect.noul, route.choice, route.confidence, risk.score, top_level, normalized)
```

### JavaScript / TypeScript（`@google/genai >= 3.2.0`）

```javascript
import { GoogleGenAI } from "@google/genai";

const ai = new GoogleGenAI({ apiVersion: "v1beta" });

const result = await ai.decisions.create({
  model: "gemini-decision-1",
  input: "I was charged twice for my order.",
  questions: {
    is_billing: {
      type: "noul",
      instructions: "Is the customer reporting a billing or payment issue?",
    },
    department: {
      type: "choice",
      instructions: "Which department should handle this request?",
      criteria: {
        billing: "Payments, invoices, and refunds.",
        technical: "Problems using the product.",
        shipping: "Delivery and tracking.",
        other: "Anything outside these categories.",
      },
    },
  },
});

if (result.prompt_feedback?.block_reason) {
  throw new Error(`Blocked: ${result.prompt_feedback.block_reason}`);
}

const dept = result.answers?.department;
if (dept?.type === "choice") {
  console.log(dept.choice, dept.confidence, dept.probabilities);
}
```

### REST（curl / PowerShell `curl.exe`）

Windows PowerShell 5.1 では `curl` が `Invoke-WebRequest` のエイリアスとなるため、`curl.exe` を使用し JSON 本文はファイル経由（`--data-binary @payload.json`）で渡す。

```bash
curl -X POST "https://generativelanguage.googleapis.com/v1beta/decisions" \
  -H "x-goog-api-key: $GEMINI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gemini-decision-1",
    "input": "Export fails in Safari but works in Chrome.",
    "questions": {
      "severity": {
        "type": "score",
        "instructions": "How severe is this issue for the user?",
        "criteria": [
          "Cosmetic: appearance only, no lost functionality.",
          "Workaround available: a task fails, but another way works.",
          "Fully blocked: a task fails with no workaround."
        ]
      }
    }
  }'
```

## マルチモーダル入力ブロック仕様

`input` は文字列、単一のコンテンツブロック、またはコンテンツブロックの配列を受け取る。
メディアはインライン Base64（`data`）か、Files API の URI または公開や署名付きの HTTPS URL（`uri`）で渡す。

| ブロック `type` | 主なフィールド | 対応 MIME タイプ |
| --- | --- | --- |
| `text` | `text`（必須） | なし |
| `image` | `data` または `uri`、`mime_type`、`resolution`（任意） | `image/png`, `image/jpeg`, `image/webp`, `image/heic`, `image/heif`, `image/gif`, `image/bmp`, `image/tiff` |
| `audio` | `data` または `uri`、`mime_type`、`channels`、`sample_rate`、`processing`（任意） | `audio/wav`, `audio/mp3`, `audio/mpeg`, `audio/aiff`, `audio/aac`, `audio/ogg`, `audio/flac`, `audio/m4a`, `audio/opus`, `audio/webm`, `audio/l16`, `audio/alaw`, `audio/mulaw` |
| `video` | `data` または `uri`、`mime_type`、`resolution`、`processing`、`name`（任意） | `video/mp4`, `video/mpeg`, `video/mpg`, `video/mov`, `video/avi`, `video/webm`, `video/wmv`, `video/x-flv`, `video/3gpp` |
| `document` | `data` または `uri`、`mime_type`、`resolution`、`processing`（任意） | `application/pdf`, `text/csv`, `application/vnd.openxmlformats-officedocument.wordprocessingml.document`, `application/msword`, `application/vnd.openxmlformats-officedocument.wordprocessingml.template`, `application/vnd.oasis.opendocument.text`, `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`, `application/vnd.ms-excel`, `application/vnd.oasis.opendocument.spreadsheet`, `application/vnd.openxmlformats-officedocument.presentationml.presentation`, `application/vnd.ms-powerpoint`, `application/vnd.oasis.opendocument.presentation` |

### 解像度と処理オプション

- **`resolution`**：`low`、`medium`、`high`、`ultra_high` を指定できる。
  - ガイド上の記載では `ultra_high` は画像向けであり、音声ブロックには適用されない。
  - ドキュメントでは `content_layers` に `page_image` を選ぶ場合に適用される。
- **ドキュメントの `processing`**（`type: "static"`）では次のオプションを指定できる。
  - `page_options`（PDF や Office 文書向け）：1 始まりの `start_page` / `end_page`（両端含む）、`content_layers`（`page_image`、`page_text`）。
  - `spreadsheet_options`（`.xlsx`、`.xls`、`.ods` 向け）：A1 記法の `visible_cells`（例 `"A1:D10"`）、1 始まりの `sheet_index`、`content_layers`（`visual`、`data`、`formulas`）。
- **音声の `processing`**（`type: "static"`）：`start_offset` と `end_offset` を秒数表記（例 `"10.5s"`、`"30s"`）で指定できる。
- **動画の `processing`**（`type: "static"` または文字列 `"static"` / `"agentic"`）：`start_offset`、`end_offset`、`fps`、`content_layers`（`frames`、`audio`、`transcript`）を指定できる。

## レスポンスと安全フィルタ遮断

正常応答は `answers`、`usage`、および任意で `prompt_feedback` を含む。
`usage.input_tokens_by_modality` では、動画フレームと PDF ページ画像が `image` モダリティとして計上され、`total_output_tokens` は常に `0` となる。

安全フィルタによる遮断は次の二経路で返る。

1. **HTTP 400 Bad Request**：JSON の `error.code` に `safety`、`prohibited_content`、`blocklist`、`image_safety`、`content_blocked` のいずれかと `error.message` が入る。
2. **HTTP 200 OK + `prompt_feedback`**：`prompt_feedback.block_reason`（`safety`、`other`、`blocklist`、`prohibited_content`、`image_safety`）と任意の `block_reason_message` が設定され、`answers` は空になる。

## 制約、料金、レート制限

| 項目 | 上限と仕様 |
| --- | --- |
| 1 リクエストの質問数 | 1–1,000（コンテキスト上限 262,144 トークンの範囲内） |
| `choice` の選択肢数 | 2–255 個 |
| `score` の段階数 | 2–255 個の非空文字列（実用上は 2–10 段階を推奨） |
| 質問キー | 1–64 文字の ASCII、`[A-Za-z0-9_-]+` |
| 選択肢キー | 1–128 文字かつ 512 UTF-8 バイト以内。内部の ASCII 空白は許可、前後空白と制御文字と非 ASCII 空白は禁止 |
| インラインデータ上限 | リクエスト全体で 100 MB、PDF は 50 MB |
| 外部 URL 上限 | 1 URL あたり 15 MB |
| JSON ネスト深度 | 100 階層 |
| 非対応の入力と機能 | `application/octet-stream`、`gs://` URI、YouTube URL、質問 `instructions` 内へのメディア埋め込み、会話履歴や `thought` / `tool_call` ブロック、Context Caching、Batch API、Flex / Priority 推論 |

### 料金とレート制限（2026年11月時点）

- **料金**：Free Tier は無料（製品改善に利用される）。
  - Paid Tier は入力トークンあたり \$0.10 / 1M トークン（テキスト、画像、動画、音声、PDF 共通）で、出力トークンは 0 のため課金対象外となる。
- **レート制限**は利用ティアごとに設定される。
  - Free：200 RPM / 50,000 TPM / 10,000 RPD
  - Tier 1：1,500 RPM / 1,000,000 TPM / 50,000 RPD
  - Tier 2：5,000 RPM / 4,000,000 TPM / RPD 無制限
  - Tier 3：15,000 RPM / 10,000,000 TPM / RPD 無制限
