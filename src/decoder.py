from html import unescape
from urllib.parse import unquote, parse_qsl


def decode_event(event):
    event["decode_status"] = "skipped"
    event["decode_errors"] = []

    if event.get("application_protocol") != "HTTP":
        return event

    application = event.get("application") or {}
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