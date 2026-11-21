#!/usr/bin/env python3
"""Gemini Decision 1 (POST /v1beta/decisions) のローカル検証とバッチ判定 CLI。

Python 標準ライブラリのみで動作し、送信前バリデーション、--dry-run、
マルチモーダル入力組み立て、信頼度閾値によるエスカレーション判定、
および安全フィルタ遮断（HTTP 400 / HTTP 200 prompt_feedback）の検出を行う。
"""

from __future__ import annotations

import argparse
import base64
import json
import mimetypes
import os
from pathlib import Path
import re
import sys
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

DEFAULT_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/decisions"
DEFAULT_MODEL = "gemini-decision-1"

QUESTION_KEY_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
VALID_RESOLUTIONS = frozenset({"low", "medium", "high", "ultra_high"})
SAFETY_ERROR_CODES = frozenset(
    {"safety", "prohibited_content", "blocklist", "image_safety", "content_blocked"}
)
YOUTUBE_HOSTS = frozenset(
    {
        "youtube.com",
        "www.youtube.com",
        "m.youtube.com",
        "music.youtube.com",
        "youtu.be",
        "www.youtu.be",
    }
)

IMAGE_MIME_TYPES = frozenset(
    {
        "image/png",
        "image/jpeg",
        "image/webp",
        "image/heic",
        "image/heif",
        "image/gif",
        "image/bmp",
        "image/tiff",
    }
)
AUDIO_MIME_TYPES = frozenset(
    {
        "audio/wav",
        "audio/mp3",
        "audio/mpeg",
        "audio/aiff",
        "audio/aac",
        "audio/ogg",
        "audio/flac",
        "audio/m4a",
        "audio/opus",
        "audio/webm",
        "audio/l16",
        "audio/alaw",
        "audio/mulaw",
    }
)
VIDEO_MIME_TYPES = frozenset(
    {
        "video/mp4",
        "video/mpeg",
        "video/mpg",
        "video/mov",
        "video/avi",
        "video/webm",
        "video/wmv",
        "video/x-flv",
        "video/3gpp",
    }
)
DOCUMENT_MIME_TYPES = frozenset(
    {
        "application/pdf",
        "text/csv",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.ms-powerpoint",
        "application/vnd.oasis.opendocument.presentation",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
        "application/vnd.oasis.opendocument.text",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-excel",
        "application/vnd.oasis.opendocument.spreadsheet",
    }
)

EXT_TO_MIME: dict[str, str] = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".heic": "image/heic",
    ".heif": "image/heif",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
    ".wav": "audio/wav",
    ".mp3": "audio/mp3",
    ".aiff": "audio/aiff",
    ".aif": "audio/aiff",
    ".aac": "audio/aac",
    ".ogg": "audio/ogg",
    ".flac": "audio/flac",
    ".m4a": "audio/m4a",
    ".opus": "audio/opus",
    ".mp4": "video/mp4",
    ".mpeg": "video/mpeg",
    ".mpg": "video/mpg",
    ".mov": "video/mov",
    ".avi": "video/avi",
    ".webm": "video/webm",
    ".wmv": "video/wmv",
    ".flv": "video/x-flv",
    ".3gp": "video/3gpp",
    ".3gpp": "video/3gpp",
    ".pdf": "application/pdf",
    ".csv": "text/csv",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".ppt": "application/vnd.ms-powerpoint",
    ".odp": "application/vnd.oasis.opendocument.presentation",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".doc": "application/msword",
    ".dotx": "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
    ".odt": "application/vnd.oasis.opendocument.text",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".xls": "application/vnd.ms-excel",
    ".ods": "application/vnd.oasis.opendocument.spreadsheet",
}


class SafetyBlockError(RuntimeError):
    """安全フィルタによってリクエストが遮断されたときの例外。"""

    def __init__(self, source: str, code: str, message: str, raw: dict[str, Any] | None = None):
        super().__init__(f"[{source}] {code}: {message}")
        self.source = source
        self.code = code
        self.message = message
        self.raw = raw or {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "blocked": True,
            "source": self.source,
            "code": self.code,
            "message": self.message,
        }


class ApiRequestError(RuntimeError):
    """安全ブロック以外の API 通信エラー。"""

    def __init__(self, status: int | None, message: str, body: Any = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.body = body


def infer_mime_type(path: Path, explicit_mime: str | None = None) -> str:
    """ファイルパスから公式対応の MIME タイプを判定する。"""
    if explicit_mime:
        return explicit_mime.strip().lower()
    suffix = path.suffix.lower()
    if suffix in EXT_TO_MIME:
        return EXT_TO_MIME[suffix]
    guessed, _ = mimetypes.guess_type(str(path))
    if guessed:
        return guessed.lower()
    raise ValueError(
        f"MIME タイプを判定できませんでした: {path}。--mime-type で明示してください。"
    )


def block_type_for_mime(mime_type: str) -> str:
    """MIME タイプに対応する入力ブロック種別を返す。"""
    mime = mime_type.strip().lower()
    if mime == "application/octet-stream":
        raise ValueError("application/octet-stream は Decisions API で非対応です。")
    if mime in IMAGE_MIME_TYPES:
        return "image"
    if mime in AUDIO_MIME_TYPES:
        return "audio"
    if mime in VIDEO_MIME_TYPES:
        return "video"
    if mime in DOCUMENT_MIME_TYPES:
        return "document"
    raise ValueError(f"非対応の MIME タイプです: {mime_type}")


def build_media_block(
    path: Path,
    mime_type: str | None = None,
    resolution: str | None = None,
) -> dict[str, Any]:
    """ローカルファイルを読み込み Decisions API のメディアブロックを構築する。"""
    resolved_mime = infer_mime_type(path, mime_type)
    block_type = block_type_for_mime(resolved_mime)
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    block: dict[str, Any] = {
        "type": block_type,
        "data": encoded,
        "mime_type": resolved_mime,
    }
    if resolution is not None:
        block["resolution"] = resolution
    return block


def build_uri_block(
    uri: str,
    mime_type: str,
    resolution: str | None = None,
) -> dict[str, Any]:
    """URI 指定のメディアブロックを構築する。"""
    block_type = block_type_for_mime(mime_type)
    block: dict[str, Any] = {
        "type": block_type,
        "uri": uri,
        "mime_type": mime_type.strip().lower(),
    }
    if resolution is not None:
        block["resolution"] = resolution
    return block


def _split_key_spec(spec: str, flag_name: str) -> tuple[str, str]:
    if "=" not in spec:
        raise ValueError(f"{flag_name} は key=value 形式で指定してください: {spec}")
    key, value = spec.split("=", 1)
    key = key.strip()
    if not key:
        raise ValueError(f"{flag_name} の質問キーが空です: {spec}")
    return key, value


def parse_inline_questions(
    noul_specs: list[str],
    choice_specs: list[str],
    score_specs: list[str],
) -> dict[str, dict[str, Any]]:
    """インライン CLI 引数から質問マップを構築する。"""
    questions: dict[str, dict[str, Any]] = {}

    for spec in noul_specs:
        key, instructions = _split_key_spec(spec, "--noul")
        if key in questions:
            raise ValueError(f"質問キーが重複しています: {key}")
        questions[key] = {
            "type": "noul",
            "instructions": instructions,
        }

    for spec in choice_specs:
        key, body = _split_key_spec(spec, "--choice")
        if key in questions:
            raise ValueError(f"質問キーが重複しています: {key}")
        parts = body.split("|")
        instructions = parts[0]
        criteria: dict[str, str] = {}
        for item in parts[1:]:
            if ":" in item:
                opt_key, opt_desc = item.split(":", 1)
            else:
                opt_key, opt_desc = item, ""
            criteria[opt_key] = opt_desc
        questions[key] = {
            "type": "choice",
            "instructions": instructions,
            "criteria": criteria,
        }

    for spec in score_specs:
        key, body = _split_key_spec(spec, "--score")
        if key in questions:
            raise ValueError(f"質問キーが重複しています: {key}")
        parts = body.split("|")
        instructions = parts[0]
        criteria_list = parts[1:]
        questions[key] = {
            "type": "score",
            "instructions": instructions,
            "criteria": criteria_list,
        }

    return questions


def _is_youtube_url(uri: str) -> bool:
    parsed = urllib.parse.urlparse(uri)
    host = (parsed.hostname or "").lower()
    return host in YOUTUBE_HOSTS or host.endswith(".youtube.com")


def _validate_input_block(block: Any, idx: int) -> list[str]:
    errors: list[str] = []
    prefix = f"input[{idx}]"
    if not isinstance(block, dict):
        return [f"{prefix}: オブジェクトである必要があります。"]

    block_type = block.get("type")
    if block_type not in {"text", "image", "audio", "video", "document"}:
        return [
            f"{prefix}: 非対応のブロック type です（{block_type!r}）。"
            "text, image, audio, video, document のいずれかを指定してください。"
        ]

    if block_type == "text":
        text = block.get("text")
        if not isinstance(text, str) or text == "":
            errors.append(f"{prefix}: text ブロックは非空の文字列 text が必要です。")
        return errors

    mime = block.get("mime_type")
    if not isinstance(mime, str) or not mime.strip():
        errors.append(f"{prefix}: mime_type は必須です。")
    elif mime.strip().lower() == "application/octet-stream":
        errors.append(
            f"{prefix}: application/octet-stream は非対応です。実際の形式の MIME タイプを指定してください。"
        )

    data = block.get("data")
    uri = block.get("uri")
    if not data and not uri:
        errors.append(f"{prefix}: data または uri のいずれかが必要です。")
    if data and uri:
        errors.append(f"{prefix}: data と uri は同時に指定できません。")

    if isinstance(uri, str) and uri:
        if uri.lower().startswith("gs://"):
            errors.append(
                f"{prefix}: Cloud Storage の gs:// URI は非対応です。"
                "Files API URI、HTTPS URL、または Base64 data を使用してください。"
            )
        elif _is_youtube_url(uri):
            errors.append(
                f"{prefix}: YouTube URL は非対応です。"
                "Files API URI、HTTPS URL、または Base64 data を使用してください。"
            )

    resolution = block.get("resolution")
    if resolution is not None:
        if resolution not in VALID_RESOLUTIONS:
            errors.append(
                f"{prefix}: resolution は low, medium, high, ultra_high のいずれかです（指定値: {resolution!r}）。"
            )
        elif block_type == "audio":
            errors.append(f"{prefix}: audio ブロックに resolution は指定できません。")

    return errors


def _validate_choice_option_key(q_key: str, opt_key: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(opt_key, str) or not opt_key:
        return [f"questions.{q_key}.criteria: 選択肢キーは 1 文字以上の文字列が必要です。"]
    if len(opt_key) > 128:
        errors.append(
            f"questions.{q_key}.criteria[{opt_key!r}]: 選択肢キーは 128 文字以内にしてください（現在 {len(opt_key)} 文字）。"
        )
    byte_len = len(opt_key.encode("utf-8"))
    if byte_len > 512:
        errors.append(
            f"questions.{q_key}.criteria[{opt_key!r}]: 選択肢キーは 512 UTF-8 バイト以内にしてください（現在 {byte_len} バイト）。"
        )
    if opt_key[0].isspace() or opt_key[-1].isspace():
        errors.append(
            f"questions.{q_key}.criteria[{opt_key!r}]: 選択肢キーの先頭または末尾に空白は使えません。"
        )
    for ch in opt_key:
        if ord(ch) < 32 or ord(ch) == 127 or unicodedata.category(ch) == "Cc":
            errors.append(
                f"questions.{q_key}.criteria[{opt_key!r}]: 選択肢キーに制御文字は使えません。"
            )
            break
        if ch.isspace() and ch != " ":
            errors.append(
                f"questions.{q_key}.criteria[{opt_key!r}]: 選択肢キーに非 ASCII 空白は使えません。"
            )
            break
    return errors


def _validate_instructions(q_key: str, instructions: Any) -> list[str]:
    if isinstance(instructions, str):
        if not instructions.strip():
            return [f"questions.{q_key}.instructions: 空文字列は指定できません。"]
        return []
    if isinstance(instructions, dict):
        if instructions.get("type") != "text" or not str(instructions.get("text", "")).strip():
            return [f"questions.{q_key}.instructions: TextContent は type='text' と非空の text が必要です。"]
        return []
    if isinstance(instructions, list) and instructions:
        errs: list[str] = []
        for idx, item in enumerate(instructions):
            if not isinstance(item, dict) or item.get("type") != "text" or not str(item.get("text", "")).strip():
                errs.append(
                    f"questions.{q_key}.instructions[{idx}]: 質問指示はテキストブロックのみ対応します。"
                )
        return errs
    return [f"questions.{q_key}.instructions: 非空の文字列または TextContent を指定してください。"]


def validate_payload(payload: dict[str, Any]) -> list[str]:
    """Decisions API リクエスト JSON を送信前に検証し、エラー一覧を返す。"""
    errors: list[str] = []
    if not isinstance(payload, dict):
        return ["リクエスト本体は JSON オブジェクトである必要があります。"]

    model = payload.get("model")
    if not isinstance(model, str) or not model.strip():
        errors.append("model は非空の文字列が必要です（例: gemini-decision-1）。")

    input_val = payload.get("input")
    if input_val is None:
        errors.append("input は必須です。")
    elif isinstance(input_val, str):
        if not input_val.strip():
            errors.append("input は空にできません。")
    elif isinstance(input_val, dict):
        errors.extend(_validate_input_block(input_val, 0))
    elif isinstance(input_val, list):
        if not input_val:
            errors.append("input 配列は空にできません。")
        else:
            for idx, block in enumerate(input_val):
                errors.extend(_validate_input_block(block, idx))
    else:
        errors.append("input は文字列、ブロック、またはブロック配列である必要があります。")

    questions = payload.get("questions")
    if not isinstance(questions, dict):
        errors.append("questions は質問キーをマップしたオブジェクトである必要があります。")
        return errors

    q_count = len(questions)
    if q_count < 1 or q_count > 1000:
        errors.append(
            f"questions の件数は 1 から 1,000 の範囲にしてください（現在 {q_count} 件）。"
        )

    for q_key, q_body in questions.items():
        if not isinstance(q_key, str) or not QUESTION_KEY_RE.match(q_key):
            errors.append(
                f"質問キー {q_key!r} は [A-Za-z0-9_-] のみ 1–64 文字で指定してください。"
            )
        if not isinstance(q_body, dict):
            errors.append(f"questions.{q_key}: オブジェクトである必要があります。")
            continue

        q_type = q_body.get("type")
        if q_type == "bool":
            errors.append(
                f"questions.{q_key}.type: 'bool' は無効です。Yes/No 質問には 'noul' を指定してください。"
            )
            continue
        if q_type not in {"noul", "choice", "score"}:
            errors.append(
                f"questions.{q_key}.type: 'noul', 'choice', 'score' のいずれかを指定してください（指定値: {q_type!r}）。"
            )
            continue

        errors.extend(_validate_instructions(q_key, q_body.get("instructions")))

        criteria = q_body.get("criteria")
        if q_type == "noul":
            if criteria is not None and not isinstance(criteria, dict):
                errors.append(
                    f"questions.{q_key}.criteria: noul の criteria はオブジェクトで指定してください。"
                )
        elif q_type == "choice":
            if not isinstance(criteria, dict):
                errors.append(
                    f"questions.{q_key}.criteria: choice は選択肢マップ（2–255 個）が必須です。"
                )
            else:
                if len(criteria) < 2 or len(criteria) > 255:
                    errors.append(
                        f"questions.{q_key}.criteria: choice の選択肢数は 2–255 個にしてください（現在 {len(criteria)} 個）。"
                    )
                for opt_key, opt_desc in criteria.items():
                    errors.extend(_validate_choice_option_key(q_key, opt_key))
                    if not isinstance(opt_desc, str):
                        errors.append(
                            f"questions.{q_key}.criteria[{opt_key!r}]: 説明は文字列で指定してください。"
                        )
        elif q_type == "score":
            if not isinstance(criteria, list):
                errors.append(
                    f"questions.{q_key}.criteria: score はレベル説明の配列（2–255 個）が必須です。"
                )
            else:
                if len(criteria) < 2 or len(criteria) > 255:
                    errors.append(
                        f"questions.{q_key}.criteria: score の段階数は 2–255 個にしてください（現在 {len(criteria)} 個）。"
                    )
                for idx, level in enumerate(criteria):
                    if not isinstance(level, str) or not level.strip():
                        errors.append(
                            f"questions.{q_key}.criteria[{idx}]: score のレベル説明は非空文字列にしてください。"
                        )

    return errors


def enrich_response(raw: dict[str, Any], min_confidence: float | None = None) -> dict[str, Any]:
    """API 応答を検査し、score の補助値や信頼度エスカレーション判定を付与する。"""
    prompt_feedback = raw.get("prompt_feedback")
    if isinstance(prompt_feedback, dict) and prompt_feedback.get("block_reason"):
        reason = str(prompt_feedback["block_reason"])
        message = str(
            prompt_feedback.get("block_reason_message")
            or "入力ポリシーによりプロンプトが遮断され、回答は生成されませんでした。"
        )
        raise SafetyBlockError("prompt_feedback", reason, message, raw=raw)

    answers = raw.get("answers")
    if not isinstance(answers, dict):
        answers = {}

    enriched_answers: dict[str, Any] = {}
    for q_key, ans in answers.items():
        if not isinstance(ans, dict):
            enriched_answers[q_key] = ans
            continue
        item = dict(ans)
        if item.get("type") == "score":
            probs = item.get("probabilities")
            legend = item.get("legend")
            score_val = item.get("score")
            if isinstance(probs, dict) and probs:
                top_level = max(probs, key=lambda k: float(probs[k]))
                item["top_level"] = top_level
                if isinstance(legend, dict) and top_level in legend:
                    item["top_level_label"] = legend[top_level]
            if isinstance(score_val, (int, float)):
                max_index = 0
                if isinstance(legend, dict) and len(legend) >= 2:
                    max_index = len(legend) - 1
                elif isinstance(probs, dict) and len(probs) >= 2:
                    max_index = len(probs) - 1
                if max_index > 0:
                    item["normalized_score"] = round(float(score_val) / max_index, 4)

        if min_confidence is not None:
            conf = item.get("confidence")
            if isinstance(conf, (int, float)):
                item["needs_escalation"] = float(conf) < min_confidence

        enriched_answers[q_key] = item

    result = dict(raw)
    result["answers"] = enriched_answers
    return result


def call_decisions_api(
    payload: dict[str, Any],
    api_key: str,
    endpoint: str = DEFAULT_ENDPOINT,
    timeout: float = 30.0,
    opener: Callable[..., Any] | None = None,
) -> dict[str, Any]:
    """Decisions API へ POST リクエストを送信し、JSON 応答を返す。"""
    body_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=body_bytes,
        headers={
            "x-goog-api-key": api_key,
            "Content-Type": "application/json; charset=utf-8",
        },
        method="POST",
    )
    open_fn = opener or urllib.request.urlopen
    try:
        with open_fn(req, timeout=timeout) as resp:
            raw_text = resp.read().decode("utf-8")
            return json.loads(raw_text)
    except urllib.error.HTTPError as exc:
        err_text = exc.read().decode("utf-8", errors="replace")
        err_json: dict[str, Any] | None = None
        try:
            parsed = json.loads(err_text)
            if isinstance(parsed, dict):
                err_json = parsed
        except json.JSONDecodeError:
            err_json = None

        if err_json and isinstance(err_json.get("error"), dict):
            err_obj = err_json["error"]
            code = str(err_obj.get("code", "")).lower()
            message = str(err_obj.get("message", err_text))
            if exc.code == 400 and code in SAFETY_ERROR_CODES:
                raise SafetyBlockError("http_400", code, message, raw=err_json) from exc
            raise ApiRequestError(exc.code, f"HTTP {exc.code} ({code}): {message}", body=err_json) from exc

        raise ApiRequestError(exc.code, f"HTTP {exc.code}: {err_text}", body=err_text) from exc
    except urllib.error.URLError as exc:
        raise ApiRequestError(None, f"通信エラー: {exc.reason}") from exc


def format_table(enriched: dict[str, Any]) -> str:
    """判定結果を Markdown 表形式の UTF-8 文字列に整形する。"""
    answers = enriched.get("answers") or {}
    lines = [
        "| question | type | value | confidence | extra |",
        "| --- | --- | --- | --- | --- |",
    ]
    for q_key, ans in answers.items():
        q_type = str(ans.get("type", ""))
        conf = ans.get("confidence")
        conf_str = f"{float(conf):.2f}" if isinstance(conf, (int, float)) else "-"
        extras: list[str] = []

        if q_type == "noul":
            val = ans.get("noul")
            val_str = f"P(yes)={float(val):.2f}" if isinstance(val, (int, float)) else "-"
        elif q_type == "choice":
            val_str = str(ans.get("choice", "-"))
        elif q_type == "score":
            val = ans.get("score")
            val_str = f"{float(val):.2f}" if isinstance(val, (int, float)) else "-"
            if "top_level" in ans:
                label = ans.get("top_level_label")
                if label:
                    extras.append(f"top={ans['top_level']} ({label})")
                else:
                    extras.append(f"top={ans['top_level']}")
            if "normalized_score" in ans:
                extras.append(f"norm={float(ans['normalized_score']):.2f}")
        else:
            val_str = "-"

        if ans.get("needs_escalation") is True:
            extras.append("ESCALATE")

        extra_str = "; ".join(extras) if extras else "-"
        lines.append(f"| {q_key} | {q_type} | {val_str} | {conf_str} | {extra_str} |")

    usage = enriched.get("usage")
    if isinstance(usage, dict):
        in_tok = usage.get("total_input_tokens")
        out_tok = usage.get("total_output_tokens")
        if in_tok is not None or out_tok is not None:
            lines.append("")
            lines.append(f"usage: input_tokens={in_tok}, output_tokens={out_tok}")
    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Gemini Decision 1 (POST /v1beta/decisions) のローカル検証と実行 CLI"
    )
    parser.add_argument("--model", default=DEFAULT_MODEL, help="モデル ID（既定: gemini-decision-1）")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT, help="API エンドポイント URL")
    parser.add_argument("--timeout", type=float, default=30.0, help="HTTP タイムアウト秒数")

    parser.add_argument("--text", action="append", default=[], help="入力テキスト（複数指定可）")
    parser.add_argument(
        "--text-file", action="append", default=[], help="UTF-8 テキストファイル（複数指定可）"
    )
    parser.add_argument("--stdin", action="store_true", help="標準入力から UTF-8 テキストを読み込む")
    parser.add_argument("--media", action="append", default=[], help="ローカルメディアファイル（複数指定可）")
    parser.add_argument(
        "--mime-type",
        action="append",
        default=[],
        help="--media に対応する MIME タイプ（省略時は拡張子から推定）",
    )
    parser.add_argument("--uri", action="append", default=[], help="外部 HTTPS または Files API URI")
    parser.add_argument("--uri-mime", action="append", default=[], help="--uri に対応する MIME タイプ")
    parser.add_argument(
        "--resolution",
        choices=["low", "medium", "high", "ultra_high"],
        default=None,
        help="画像・動画・ドキュメントに付与する解像度",
    )

    parser.add_argument("--questions", default=None, help="質問マップを定義した JSON ファイルパス")
    parser.add_argument("--noul", action="append", default=[], help='Yes/No 質問: key="質問文"')
    parser.add_argument(
        "--choice",
        action="append",
        default=[],
        help='単一選択質問: key="質問文|opt1:説明1|opt2:説明2"',
    )
    parser.add_argument(
        "--score",
        action="append",
        default=[],
        help='ルーブリック質問: key="質問文|Lv0|Lv1|Lv2"',
    )

    parser.add_argument(
        "--min-confidence",
        type=float,
        default=None,
        help="0.0–1.0 の信頼度閾値。未満の回答に needs_escalation: true を付与する",
    )
    parser.add_argument(
        "--format",
        choices=["json", "table"],
        default="json",
        help="出力形式（既定: json）",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="API 送信せず事前検証済みリクエスト JSON を出力して終了する（GEMINI_API_KEY 不要）",
    )
    return parser


def _build_input_blocks(
    args: argparse.Namespace, stdin_text: str | None = None
) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    for text in args.text:
        blocks.append({"type": "text", "text": text})
    for file_str in args.text_file:
        text_content = Path(file_str).read_text(encoding="utf-8")
        blocks.append({"type": "text", "text": text_content})
    if args.stdin:
        content = stdin_text if stdin_text is not None else sys.stdin.read()
        blocks.append({"type": "text", "text": content})

    if args.mime_type and len(args.mime_type) != len(args.media):
        raise ValueError("--mime-type の個数は --media と一致させてください。")
    for idx, media_str in enumerate(args.media):
        explicit_mime = args.mime_type[idx] if args.mime_type else None
        blocks.append(build_media_block(Path(media_str), mime_type=explicit_mime, resolution=args.resolution))

    if len(args.uri) != len(args.uri_mime):
        raise ValueError("--uri と --uri-mime は同じ個数でペア指定してください。")
    for uri, uri_mime in zip(args.uri, args.uri_mime):
        blocks.append(build_uri_block(uri, uri_mime, resolution=args.resolution))

    return blocks


def main(
    argv: list[str] | None = None,
    *,
    opener: Callable[..., Any] | None = None,
    env: dict[str, str] | None = None,
    stdin_text: str | None = None,
) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.min_confidence is not None and not (0.0 <= args.min_confidence <= 1.0):
        print("エラー: --min-confidence は 0.0 から 1.0 の範囲で指定してください。", file=sys.stderr)
        return 2

    try:
        input_blocks = _build_input_blocks(args, stdin_text=stdin_text)
        questions: dict[str, Any] = {}
        if args.questions:
            loaded = json.loads(Path(args.questions).read_text(encoding="utf-8"))
            if not isinstance(loaded, dict):
                raise ValueError("--questions の JSON は質問キーをマップしたオブジェクトが必要です。")
            questions.update(loaded)
        inline_questions = parse_inline_questions(args.noul, args.choice, args.score)
        for key, q_obj in inline_questions.items():
            if key in questions:
                raise ValueError(f"質問キーが重複しています: {key}")
            questions[key] = q_obj
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"入力エラー: {exc}", file=sys.stderr)
        return 2

    payload: dict[str, Any] = {
        "model": args.model,
        "input": input_blocks,
        "questions": questions,
    }
    errors = validate_payload(payload)
    if errors:
        print("事前バリデーションエラー:", file=sys.stderr)
        for err in errors:
            print(f"- {err}", file=sys.stderr)
        return 2

    if args.dry_run:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    environ = os.environ if env is None else env
    api_key = environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        print(
            "エラー: 環境変数 GEMINI_API_KEY が設定されていません。"
            "API キーを設定するか --dry-run を使用してください。",
            file=sys.stderr,
        )
        return 2

    try:
        raw_response = call_decisions_api(
            payload,
            api_key=api_key,
            endpoint=args.endpoint,
            timeout=args.timeout,
            opener=opener,
        )
        enriched = enrich_response(raw_response, min_confidence=args.min_confidence)
    except SafetyBlockError as exc:
        print(json.dumps(exc.to_dict(), ensure_ascii=False, indent=2), file=sys.stderr)
        return 3
    except ApiRequestError as exc:
        print(f"API エラー: {exc.message}", file=sys.stderr)
        return 1

    if args.format == "table":
        print(format_table(enriched))
    else:
        print(json.dumps(enriched, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
