import logging
from pathlib import Path

from roborock_local_server.bundled_backend.shared.io_utils import append_jsonl, setup_file_logger


def test_setup_file_logger_mirrors_messages_to_file_and_stream(
    tmp_path: Path,
    capsys,
) -> None:
    log_path = tmp_path / "api_server.log"
    logger = setup_file_logger("api_test", log_path)

    logger.info("device initialization failed")

    captured = capsys.readouterr()
    assert "device initialization failed" in captured.err
    assert "[real_stack.api_test]" in captured.err
    assert "device initialization failed" in log_path.read_text(encoding="utf-8")


def test_append_jsonl_writes_file_and_hides_structured_entry_by_default(
    tmp_path: Path,
    capsys,
) -> None:
    logger = logging.getLogger("real_stack.jsonl")
    logger.handlers.clear()
    logger.setLevel(logging.NOTSET)

    jsonl_path = tmp_path / "decompiled_http.jsonl"
    append_jsonl(jsonl_path, {"route": "get_home_data", "success": True})

    captured = capsys.readouterr()
    written = jsonl_path.read_text(encoding="utf-8")

    assert '"route":"get_home_data"' in written
    assert captured.err == ""


def test_append_jsonl_streams_structured_entry_when_jsonl_logger_is_debug(
    tmp_path: Path,
    capsys,
) -> None:
    logger = logging.getLogger("real_stack.jsonl")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG)

    jsonl_path = tmp_path / "decompiled_http.jsonl"
    append_jsonl(jsonl_path, {"route": "get_home_data", "success": True})

    captured = capsys.readouterr()

    assert "[decompiled_http.jsonl]" in captured.err
    assert '"success":true' in captured.err
