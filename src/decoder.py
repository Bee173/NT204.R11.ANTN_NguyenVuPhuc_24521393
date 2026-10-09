from html import unescape
from urllib.parse import unquote, parse_qsl


def decode_event(event):
    event["decode_status"] = "skipped"
    event["decode_errors"] = []

    if event.get("application_protocol") == "SMTP":
        return decode_smtp_event(event)

    if event.get("application_protocol") != "HTTP":
        return event

    application = event.get("application") or {}
    event["decode_errors"].extend(
        f"character: {error}"
        for error in application.get("character_decode_errors", [])
    )
    decoded_any = False

    # Giải mã URI, giữ nguyên path gốc.
    raw_path = application.get("path")

    if raw_path is not None:
        try:
            application["decoded_path"] = unquote(
                raw_path,
                encoding="utf-8",
                errors="strict",
            )
            decoded_any = True
        except (UnicodeDecodeError, TypeError) as error:
            application["decoded_path"] = None
            event["decode_errors"].append(f"path: {error}")

    # Tra cứu header không phân biệt hoa/thường.
    headers = {
        name.lower(): value
        for name, value in (application.get("headers") or {}).items()
    }

    content_type = headers.get("content-type", "")
    media_type = content_type.split(";", 1)[0].strip().lower()

    # Chỉ giải mã form khi Content-Type phù hợp.
    if media_type == "application/x-www-form-urlencoded":
        raw_body = application.get("body")

        if raw_body is not None:
            try:
                application["decoded_form"] = parse_qsl(
                    raw_body,
                    keep_blank_values=True,
                    encoding="utf-8",
                    errors="strict",
                    max_num_fields=1000,
                )
                decoded_any = True
            except (UnicodeDecodeError, ValueError, TypeError) as error:
                application["decoded_form"] = None
                event["decode_errors"].append(f"form: {error}")


    # Giải mã HTML entity trong HTTP text body.
    if media_type in {"text/html", "text/plain"}:
        raw_body = application.get("body")

        if raw_body is not None:
            try:
                application["decoded_body"] = unescape(raw_body)
                decoded_any = True
            except (TypeError, AttributeError) as error:
                application["decoded_body"] = None
                event["decode_errors"].append(f"html_entity: {error}")

    if event["decode_errors"]:
        event["decode_status"] = "partial" if decoded_any else "error"
    elif decoded_any:
        event["decode_status"] = "success"

    event["application"] = application
    return event

def decode_smtp_event(event):
    import base64
    import binascii
    import quopri
    from email import policy
    from email.parser import BytesParser

    application = event.get("application") or {}
    raw_b64 = application.get("raw_payload_b64")

    if not raw_b64:
        return event

    try:
        payload = base64.b64decode(raw_b64, validate=True)

        # Hỗ trợ input có DATA và MIME message trong cùng packet.
        if payload[:6].upper() == b"DATA\r\n":
            payload = payload[6:]

        if payload.endswith(b"\r\n.\r\n"):
            payload = payload[:-5]

        message = BytesParser(policy=policy.default).parsebytes(payload)
        encoding = str(
            message.get("Content-Transfer-Encoding", "")
        ).strip().lower()

        if encoding not in {"base64", "quoted-printable"}:
            return event

        if message.is_multipart():
            raise ValueError("Multipart MIME chưa được hỗ trợ")

        body = message.get_payload(decode=False)
        application["mime_encoding"] = encoding
        application["mime_body_raw"] = body

        encoded_body = body.encode("ascii")

        if encoding == "base64":
            # Bỏ whitespace MIME trước khi kiểm tra Base64.
            compact_body = b"".join(encoded_body.split())
            decoded_bytes = base64.b64decode(
                compact_body, validate=True
            )
        else:
            decoded_bytes = quopri.decodestring(encoded_body)

        charset = message.get_content_charset() or "ascii"
        application["mime_charset"] = charset
        application["decoded_body"] = decoded_bytes.decode(
            charset, errors="strict"
        )
        event["decode_status"] = "success"

    except (
        ValueError, TypeError, UnicodeError,
        LookupError, binascii.Error
    ) as error:
        application["decoded_body"] = None
        event["decode_status"] = "error"
        event["decode_errors"].append(f"smtp_mime: {error}")

    event["application"] = application
    return event
