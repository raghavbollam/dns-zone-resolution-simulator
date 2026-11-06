"""Tools that provide a DNS zone case and save an agent's submitted resolutions."""

from __future__ import annotations

import json
from collections import defaultdict
from ipaddress import ip_address
from pathlib import Path

from slimconfig import plain_output

from contract import (
    DNSRecord,
    DNSZoneOutput,
    ReadZoneInput,
    ReadZoneOutput,
    RecordType,
    WriteResolutionsInput,
    WriteResolutionsOutput,
)


def _validate_absolute_name(name: object, field: str) -> str:
    if not isinstance(name, str) or not name:
        raise ValueError(f"{field} must be a non-empty string.")
    if name != name.lower():
        raise ValueError(f"{field} must be lowercase.")
    if not name.endswith("."):
        raise ValueError(f"{field} must be an absolute name ending in a dot.")
    if len(name) > 253:
        raise ValueError(f"{field} must not exceed 253 characters.")

    labels = name[:-1].split(".")
    if any(
        not label
        or len(label) > 63
        or label[0] == "-"
        or label[-1] == "-"
        or not all(character.isascii() and (character.isalnum() or character == "-") for character in label)
        for label in labels
    ):
        raise ValueError(f"{field} contains an invalid DNS label.")
    return name


def _is_in_zone(name: str, origin: str) -> bool:
    return name == origin or name.endswith(f".{origin}")


def _validate_dns_zone_input(task) -> None:
    origin = _validate_absolute_name(task.origin, "origin")
    if not task.queries:
        raise ValueError("queries must contain at least one query.")

    rrsets: dict[tuple[str, RecordType], list[DNSRecord]] = defaultdict(list)
    owner_types: dict[str, set[RecordType]] = defaultdict(set)
    seen_records: set[tuple[str, RecordType, str]] = set()

    for index, record in enumerate(task.records):
        field = f"records[{index}]"
        name = _validate_absolute_name(record.name, f"{field}.name")
        if not _is_in_zone(name, origin):
            raise ValueError(f"{field}.name must be inside origin {origin!r}.")
        if not isinstance(record.ttl, int) or isinstance(record.ttl, bool) or record.ttl < 0:
            raise ValueError(f"{field}.ttl must be a non-negative integer.")

        if record.record_type in (RecordType.A, RecordType.AAAA):
            try:
                address = ip_address(record.value)
            except ValueError as error:
                raise ValueError(f"{field}.value must be a valid {record.record_type.value} address.") from error
            expected_version = 4 if record.record_type is RecordType.A else 6
            if address.version != expected_version:
                raise ValueError(f"{field}.value must be a valid {record.record_type.value} address.")
            if record.value != address.compressed:
                raise ValueError(f"{field}.value must be a canonical {record.record_type.value} address.")
        else:
            target = _validate_absolute_name(record.value, f"{field}.value")
            if not _is_in_zone(target, origin):
                raise ValueError(f"{field}.value must be inside origin {origin!r}.")

        record_key = (name, record.record_type, record.value)
        if record_key in seen_records:
            raise ValueError(f"{field} duplicates an existing record.")
        seen_records.add(record_key)
        rrsets[(name, record.record_type)].append(record)
        owner_types[name].add(record.record_type)

    for (name, record_type), records in rrsets.items():
        if len({record.ttl for record in records}) != 1:
            raise ValueError(f"RRset {name!r} {record_type.value} must use one shared TTL.")
        if record_type is RecordType.CNAME and len(records) != 1:
            raise ValueError(f"owner {name!r} must have exactly one CNAME record.")

    for name, record_types in owner_types.items():
        if RecordType.CNAME in record_types and len(record_types) != 1:
            raise ValueError(f"CNAME owner {name!r} cannot have other record types.")

    for index, query in enumerate(task.queries):
        name = _validate_absolute_name(query.name, f"queries[{index}].name")
        if not _is_in_zone(name, origin):
            raise ValueError(f"queries[{index}].name must be inside origin {origin!r}.")


def read_zone(given: ReadZoneInput, workspace: Path) -> ReadZoneOutput:
    """Return the validated DNS zone task input unchanged."""

    del workspace
    _validate_dns_zone_input(given.task)
    return ReadZoneOutput(
        origin=given.task.origin,
        records=given.task.records,
        queries=given.task.queries,
    )


def write_resolutions(
    given: WriteResolutionsInput,
    workspace: Path,
) -> WriteResolutionsOutput:
    """Write the agent's final structured answer into its permitted workspace."""

    _validate_dns_zone_input(given.task)
    report = DNSZoneOutput(resolutions=given.resolutions)
    report_path = workspace / "resolutions.json"
    report_path.write_text(
        json.dumps(plain_output(report), indent=2) + "\n",
        encoding="utf-8",
    )
    return WriteResolutionsOutput(
        report_path="resolutions.json",
        report=report,
    )
