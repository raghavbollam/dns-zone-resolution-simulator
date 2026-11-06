"""Verify an agent's submitted DNS resolutions deterministically."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from contract import DNSZoneInput, DNSZoneOutput, ResolutionResult

from .rules import simulate_dns_resolution


@dataclass(frozen=True)
class VerificationResult:
    """The deterministic verdict for one submitted task answer."""

    ok: bool
    score: float
    message: str
    errors: list[str]


def describe_resolution(resolution: ResolutionResult) -> str:
    """Format one resolution so mismatches are easy to understand."""

    return (
        f"query={resolution.query_name!r} {resolution.query_type.value}, "
        f"status={resolution.status.value}, canonical_name={resolution.canonical_name!r}, "
        f"answers={resolution.answers!r}, steps={resolution.steps!r}"
    )


def verify_task(
    arguments: DNSZoneInput,
    output: DNSZoneOutput,
    reference: object | None,
    workspace: Path | None,
) -> VerificationResult:
    """Compare every submitted resolution with the independently simulated answer."""

    del reference, workspace

    try:
        expected = simulate_dns_resolution(arguments)
    except ValueError as error:
        return VerificationResult(
            ok=False,
            score=0.0,
            message="The DNS zone task input is invalid.",
            errors=[str(error)],
        )

    errors: list[str] = []
    if len(output.resolutions) != len(expected):
        errors.append(f"Expected {len(expected)} resolutions, but received {len(output.resolutions)}.")

    for index, expected_resolution in enumerate(expected):
        if index >= len(output.resolutions):
            errors.append(
                f"Missing resolution {index + 1} for "
                f"{expected_resolution.query_name!r} {expected_resolution.query_type.value}."
            )
            continue

        actual_resolution = output.resolutions[index]
        if actual_resolution != expected_resolution:
            errors.append(
                f"Resolution {index + 1} does not match. "
                f"Expected ({describe_resolution(expected_resolution)}); "
                f"received ({describe_resolution(actual_resolution)})."
            )

    for index in range(len(expected), len(output.resolutions)):
        errors.append(f"Unexpected extra resolution {index + 1}: ({describe_resolution(output.resolutions[index])}).")

    if errors:
        return VerificationResult(
            ok=False,
            score=0.0,
            message="The submitted resolutions did not match the deterministic simulation.",
            errors=errors,
        )

    return VerificationResult(
        ok=True,
        score=1.0,
        message="Every submitted resolution matches the deterministic simulation.",
        errors=[],
    )
