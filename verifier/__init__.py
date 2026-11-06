"""Deterministic verifier entry points for the DNS zone resolution simulator."""

import json
from pathlib import Path

from slimconfig import plain_output

from contract import (
    DNSZoneOutput,
    ReadZoneOutput,
    Task,
    Tool,
)

from .rules import validate_dns_zone_input
from .task import verify_task as verify_dns_resolution


def result(valid, message, *, score=None, **details):
    """Return a NanoAgent v0001 verifier result."""

    return {
        "valid": valid,
        "score": float(valid) if score is None else score,
        "message": message,
        "details": details,
    }


def verify_input(tool, value):
    """Validate tool inputs against the deterministic task evaluation."""

    if Tool(tool) is Tool.READ_ZONE:
        try:
            validate_dns_zone_input(value.task)
        except ValueError as error:
            return result(False, "The DNS zone task input is invalid.", errors=[str(error)])
        return result(True, "The DNS zone task input is valid.")

    verdict = verify_dns_resolution(
        value.task,
        DNSZoneOutput(resolutions=value.resolutions),
        None,
        None,
    )
    return result(
        verdict.ok,
        verdict.message,
        score=verdict.score,
        errors=verdict.errors,
    )


def verify_output(tool, input_value, output_value, workspace):
    """Validate that each tool returns the value specified by its contract."""

    if Tool(tool) is Tool.READ_ZONE:
        expected = ReadZoneOutput(
            origin=input_value.task.origin,
            records=input_value.task.records,
            queries=input_value.task.queries,
        )
        return result(
            output_value == expected,
            "The DNS zone was read correctly."
            if output_value == expected
            else "The DNS zone output did not match the task input.",
        )

    expected = DNSZoneOutput(resolutions=input_value.resolutions)
    expected_report = plain_output(expected)
    report_file = Path(workspace) / "resolutions.json"

    try:
        written_report = json.loads(report_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return result(
            False,
            "The resolution report was not written.",
            errors=["resolutions.json is missing."],
        )
    except json.JSONDecodeError as error:
        return result(
            False,
            "The resolution report is not valid JSON.",
            errors=[f"resolutions.json could not be decoded: {error.msg}."],
        )

    valid = (
        output_value.report_path == "resolutions.json"
        and output_value.report == expected
        and written_report == expected_report
    )
    return result(
        valid,
        "The resolutions were written correctly."
        if valid
        else "The resolution report did not match the submitted resolutions.",
        errors=[] if valid else ["resolutions.json or the returned report differs from the submitted resolutions."],
    )


def verify_task(task, arguments, output, reference, workspace):
    """Verify final task output against the independently simulated answer."""

    del reference, workspace
    verdict = verify_dns_resolution(arguments, output, None, None)
    return result(
        verdict.ok,
        verdict.message,
        score=verdict.score,
        errors=verdict.errors,
        task=Task(task).value,
    )
