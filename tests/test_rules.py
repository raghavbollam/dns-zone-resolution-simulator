import json
from pathlib import Path

import pytest
from slimconfig import build_output, plain_output

from contract import (
    DNSQuery,
    DNSRecord,
    DNSZoneInput,
    DNSZoneOutput,
    QueryType,
    RecordType,
    ResolutionStatus,
)
from verifier.rules import simulate_dns_resolution, validate_dns_zone_input

FIXTURES = Path(__file__).parent / "fixtures"


def load_basic_input() -> DNSZoneInput:
    data = json.loads((FIXTURES / "basic-case-input.json").read_text(encoding="utf-8"))
    return build_output(data, DNSZoneInput)


def test_basic_fixture_matches_expected_resolutions() -> None:
    expected = json.loads((FIXTURES / "basic-case-expected.json").read_text(encoding="utf-8"))
    actual = DNSZoneOutput(resolutions=simulate_dns_resolution(load_basic_input()))

    assert plain_output(actual) == expected


def test_simulation_reports_every_documented_status() -> None:
    results = simulate_dns_resolution(load_basic_input())

    assert [result.status for result in results] == [
        ResolutionStatus.ANSWER,
        ResolutionStatus.ANSWER,
        ResolutionStatus.NXDOMAIN,
        ResolutionStatus.NODATA,
        ResolutionStatus.CNAME_LOOP,
    ]
    assert results[1].canonical_name == "www.example.test."
    assert [step.record_type for step in results[1].steps] == [
        RecordType.CNAME,
        RecordType.AAAA,
    ]
    assert results[4].canonical_name == "loop-a.example.test."


def test_address_answers_use_numeric_order() -> None:
    result = simulate_dns_resolution(load_basic_input())[0]

    assert [answer.value for answer in result.answers] == [
        "192.0.2.3",
        "192.0.2.20",
    ]
    assert result.steps[0].values == ["192.0.2.3", "192.0.2.20"]


def valid_task(
    *,
    records: list[DNSRecord] | None = None,
    queries: list[DNSQuery] | None = None,
) -> DNSZoneInput:
    return DNSZoneInput(
        origin="example.test.",
        records=records
        if records is not None
        else [
            DNSRecord(
                name="www.example.test.",
                record_type=RecordType.A,
                value="192.0.2.1",
                ttl=300,
            )
        ],
        queries=queries if queries is not None else [DNSQuery(name="www.example.test.", query_type=QueryType.A)],
    )


@pytest.mark.parametrize(
    ("task", "message"),
    [
        (valid_task(queries=[]), "queries must contain at least one query"),
        (
            DNSZoneInput(
                origin="Example.test.",
                records=[],
                queries=[DNSQuery("www.example.test.", QueryType.A)],
            ),
            "origin must be lowercase",
        ),
        (
            valid_task(
                records=[
                    DNSRecord(
                        "outside.test.",
                        RecordType.A,
                        "192.0.2.1",
                        300,
                    )
                ]
            ),
            "must be inside origin",
        ),
        (
            valid_task(
                records=[
                    DNSRecord(
                        "www.example.test.",
                        RecordType.AAAA,
                        "192.0.2.1",
                        300,
                    )
                ]
            ),
            "valid AAAA address",
        ),
        (
            valid_task(
                records=[
                    DNSRecord(
                        "www.example.test.",
                        RecordType.AAAA,
                        "2001:0db8::1",
                        300,
                    )
                ]
            ),
            "canonical AAAA address",
        ),
        (
            valid_task(
                records=[
                    DNSRecord(
                        "www.example.test.",
                        RecordType.A,
                        "192.0.2.1",
                        -1,
                    )
                ]
            ),
            "ttl must be a non-negative integer",
        ),
        (
            valid_task(
                records=[
                    DNSRecord("www.example.test.", RecordType.A, "192.0.2.1", 300),
                    DNSRecord("www.example.test.", RecordType.A, "192.0.2.1", 300),
                ]
            ),
            "duplicates an existing record",
        ),
        (
            valid_task(
                records=[
                    DNSRecord("www.example.test.", RecordType.A, "192.0.2.1", 300),
                    DNSRecord("www.example.test.", RecordType.A, "192.0.2.2", 60),
                ]
            ),
            "must use one shared TTL",
        ),
        (
            valid_task(
                records=[
                    DNSRecord(
                        "www.example.test.",
                        RecordType.CNAME,
                        "one.example.test.",
                        300,
                    ),
                    DNSRecord(
                        "www.example.test.",
                        RecordType.CNAME,
                        "two.example.test.",
                        300,
                    ),
                ]
            ),
            "exactly one CNAME",
        ),
        (
            valid_task(
                records=[
                    DNSRecord(
                        "www.example.test.",
                        RecordType.CNAME,
                        "target.example.test.",
                        300,
                    ),
                    DNSRecord("www.example.test.", RecordType.A, "192.0.2.1", 300),
                ]
            ),
            "cannot have other record types",
        ),
    ],
)
def test_validation_rejects_malformed_zone(
    task: DNSZoneInput,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        validate_dns_zone_input(task)
