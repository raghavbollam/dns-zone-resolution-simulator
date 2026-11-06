import json
from pathlib import Path

import pytest
from slimconfig import build_output, plain_output

from contract import (
    DNSQuery,
    DNSZoneInput,
    DNSZoneOutput,
    QueryType,
    ReadZoneInput,
    WriteResolutionsInput,
)
from plugin.tools import read_zone, write_resolutions

FIXTURES = Path(__file__).parent / "fixtures"


def load_basic_input() -> DNSZoneInput:
    data = json.loads((FIXTURES / "basic-case-input.json").read_text(encoding="utf-8"))
    return build_output(data, DNSZoneInput)


def load_basic_output() -> DNSZoneOutput:
    data = json.loads((FIXTURES / "basic-case-expected.json").read_text(encoding="utf-8"))
    return build_output(data, DNSZoneOutput)


def test_read_zone_returns_task_input(tmp_path: Path) -> None:
    task = load_basic_input()

    result = read_zone(ReadZoneInput(task=task), tmp_path)

    assert result.origin == task.origin
    assert result.records == task.records
    assert result.queries == task.queries


def test_write_resolutions_saves_json_report(tmp_path: Path) -> None:
    task = load_basic_input()
    expected = load_basic_output()

    result = write_resolutions(
        WriteResolutionsInput(task=task, resolutions=expected.resolutions),
        tmp_path,
    )

    assert result.report_path == "resolutions.json"
    assert result.report == expected
    saved_report = json.loads((tmp_path / "resolutions.json").read_text(encoding="utf-8"))
    assert saved_report == plain_output(expected)


def test_read_zone_rejects_invalid_task(tmp_path: Path) -> None:
    task = DNSZoneInput(
        origin="example.test.",
        records=[],
        queries=[DNSQuery(name="outside.test.", query_type=QueryType.A)],
    )

    with pytest.raises(ValueError, match="must be inside origin"):
        read_zone(ReadZoneInput(task=task), tmp_path)
