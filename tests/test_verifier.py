import json
from pathlib import Path

from slimconfig import build_output

from contract import (
    DNSZoneInput,
    DNSZoneOutput,
    Task,
    Tool,
    WriteResolutionsInput,
    WriteResolutionsOutput,
)
from plugin.tools import write_resolutions
from verifier import verify_input, verify_output
from verifier import verify_task as verify_registered_task
from verifier.task import verify_task

FIXTURES = Path(__file__).parent / "fixtures"


def load_basic_input() -> DNSZoneInput:
    data = json.loads((FIXTURES / "basic-case-input.json").read_text(encoding="utf-8"))
    return build_output(data, DNSZoneInput)


def load_basic_output() -> DNSZoneOutput:
    data = json.loads((FIXTURES / "basic-case-expected.json").read_text(encoding="utf-8"))
    return build_output(data, DNSZoneOutput)


def test_verifier_accepts_correct_resolutions(tmp_path: Path) -> None:
    result = verify_task(
        load_basic_input(),
        load_basic_output(),
        reference=None,
        workspace=tmp_path,
    )

    assert result.ok is True
    assert result.score == 1.0
    assert result.errors == []


def test_verifier_rejects_incorrect_resolution(tmp_path: Path) -> None:
    task = load_basic_input()
    output = load_basic_output()
    output.resolutions[0].canonical_name = "wrong.example.test."

    result = verify_task(task, output, reference=None, workspace=tmp_path)

    assert result.ok is False
    assert result.score == 0.0
    assert len(result.errors) == 1
    assert "Resolution 1 does not match" in result.errors[0]


def test_verifier_rejects_missing_resolution(tmp_path: Path) -> None:
    task = load_basic_input()
    output = load_basic_output()

    result = verify_task(
        task,
        DNSZoneOutput(resolutions=output.resolutions[:-1]),
        reference=None,
        workspace=tmp_path,
    )

    assert result.ok is False
    assert any("Expected 5 resolutions, but received 4" in error for error in result.errors)
    assert any("Missing resolution 5" in error for error in result.errors)


def test_verifier_rejects_extra_and_reordered_resolutions(tmp_path: Path) -> None:
    task = load_basic_input()
    output = load_basic_output()

    result = verify_task(
        task,
        DNSZoneOutput(
            resolutions=[
                output.resolutions[1],
                output.resolutions[0],
                *output.resolutions[2:],
                output.resolutions[0],
            ]
        ),
        reference=None,
        workspace=tmp_path,
    )

    assert result.ok is False
    assert any("Expected 5 resolutions, but received 6" in error for error in result.errors)
    assert any("Resolution 1 does not match" in error for error in result.errors)
    assert any("Unexpected extra resolution 6" in error for error in result.errors)


def test_registered_verifier_dispatches_to_task_verifier(tmp_path: Path) -> None:
    result = verify_registered_task(
        Task.SIMULATE_DNS_RESOLUTION.value,
        load_basic_input(),
        load_basic_output(),
        reference=None,
        workspace=tmp_path,
    )

    assert result["valid"] is True
    assert result["score"] == 1.0


def test_read_zone_input_verifier_rejects_invalid_task() -> None:
    task = load_basic_input()
    task.queries = []

    result = verify_input(
        Tool.READ_ZONE.value,
        type("ReadZoneValue", (), {"task": task})(),
    )

    assert result["valid"] is False
    assert result["details"]["errors"] == ["queries must contain at least one query."]


def test_write_output_verifier_requires_persisted_report(tmp_path: Path) -> None:
    task = load_basic_input()
    expected = load_basic_output()
    input_value = WriteResolutionsInput(
        task=task,
        resolutions=expected.resolutions,
    )
    output_value = WriteResolutionsOutput(
        report_path="resolutions.json",
        report=expected,
    )

    result = verify_output(
        Tool.WRITE_RESOLUTIONS.value,
        input_value,
        output_value,
        tmp_path,
    )

    assert result["valid"] is False
    assert result["details"]["errors"] == ["resolutions.json is missing."]


def test_write_output_verifier_accepts_persisted_report(tmp_path: Path) -> None:
    task = load_basic_input()
    expected = load_basic_output()
    input_value = WriteResolutionsInput(
        task=task,
        resolutions=expected.resolutions,
    )
    output_value = write_resolutions(input_value, tmp_path)

    result = verify_output(
        Tool.WRITE_RESOLUTIONS.value,
        input_value,
        output_value,
        str(tmp_path),
    )

    assert result["valid"] is True
