from urllib.parse import unquote


def decode_event(event):
    event["decode_status"] = "skipped"
    event["decode_errors"] = []

    if event.get("application_protocol") != "HTTP":
        return event

    application = event.get("application") or {}
    raw_path = application.get("path")

    if raw_path is None:
        return event

    try:
        application["decoded_path"] = unquote(
            raw_path,
            encoding="utf-8",
            errors="strict",
        )
        event["decode_status"] = "success"
    except (UnicodeDecodeError, TypeError) as error:
        application["decoded_path"] = None
        event["decode_status"] = "error"
        event["decode_errors"].append(str(error))

    event["application"] = application
    return event