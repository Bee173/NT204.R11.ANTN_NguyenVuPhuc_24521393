import sys
from pathlib import Path
from tempfile import TemporaryDirectory


folder = Path(__file__).resolve().parent
sys.path.insert(0, str(folder.parents[2]))


try:
    from src.core_engine.rule_loader import load_rule_files
except ModuleNotFoundError as error:
    print(f"FAIL: Rule Loader chưa được triển khai: {error}")
    raise SystemExit(1) from error


with TemporaryDirectory() as temporary_directory:
    temporary_path = Path(temporary_directory)
    enabled_file = temporary_path / "enabled.rules"
    disabled_file = temporary_path / "disabled.rules"
    missing_file = temporary_path / "missing.rules"

    enabled_file.write_text(
        "# comment đầu file\n"
        "\n"
        "alert tcp any any -> any 80 (sid:100001; rev:1;)\n"
        "   # comment có khoảng trắng\n"
        "alert udp any any <> any 53 (sid:100002; rev:1;)\n",
        encoding="utf-8",
    )
    disabled_file.write_text(
        "alert tcp any any -> any 22 (sid:100003; rev:1;)\n",
        encoding="utf-8",
    )

    result = load_rule_files(
        [enabled_file, missing_file, disabled_file],
        disabled_files=[disabled_file],
    )

    assert [candidate.raw for candidate in result.candidates] == [
        "alert tcp any any -> any 80 (sid:100001; rev:1;)",
        "alert udp any any <> any 53 (sid:100002; rev:1;)",
    ], "Loader phải chỉ trả về các dòng rule có nội dung"
    assert [candidate.line_number for candidate in result.candidates] == [3, 5]
    assert all(
        candidate.source == str(enabled_file)
        for candidate in result.candidates
    )

    assert len(result.issues) == 1, (
        "File bị disable phải được bỏ qua; file thiếu phải tạo đúng một issue"
    )
    assert result.issues[0].source == str(missing_file)
    assert result.issues[0].reason

print("PASS: Snort Rule Loader đọc và lọc file rule an toàn")
