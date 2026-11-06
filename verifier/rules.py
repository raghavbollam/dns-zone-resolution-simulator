"""Independently simulate deterministic DNS resolution for one supplied zone."""

from __future__ import annotations

from collections import defaultdict
from ipaddress import ip_address

from contract import (
    DNSQuery,
    DNSRecord,
    DNSZoneInput,
    RecordType,
    ResolutionResult,
    ResolutionStatus,
    ResolutionStep,
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


def _record_sort_key(record: DNSRecord) -> tuple[int, bytes]:
    address = ip_address(record.value)
    return address.version, address.packed


def validate_dns_zone_input(task: DNSZoneInput) -> None:
    """Raise ValueError unless a task defines one deterministic authoritative zone."""

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


def _step(records: list[DNSRecord]) -> ResolutionStep:
    ordered = (
        sorted(records, key=_record_sort_key) if records[0].record_type in (RecordType.A, RecordType.AAAA) else records
    )
    return ResolutionStep(
        name=ordered[0].name,
        record_type=ordered[0].record_type,
        values=[record.value for record in ordered],
        ttl=ordered[0].ttl,
    )


def resolve_query(task: DNSZoneInput, query: DNSQuery) -> ResolutionResult:
    """Resolve one validated query with CNAME following and loop detection."""

    rrsets: dict[tuple[str, RecordType], list[DNSRecord]] = defaultdict(list)
    owner_names: set[str] = set()
    for record in task.records:
        rrsets[(record.name, record.record_type)].append(record)
        owner_names.add(record.name)

    current_name = query.name
    visited: set[str] = set()
    steps: list[ResolutionStep] = []
    terminal_type = RecordType(query.query_type.value)

    while True:
        if current_name in visited:
            return ResolutionResult(
                query_name=query.name,
                query_type=query.query_type,
                status=ResolutionStatus.CNAME_LOOP,
                canonical_name=current_name,
                answers=[],
                steps=steps,
            )
        visited.add(current_name)

        terminal_records = rrsets.get((current_name, terminal_type), [])
        if terminal_records:
            ordered_answers = sorted(terminal_records, key=_record_sort_key)
            steps.append(_step(ordered_answers))
            return ResolutionResult(
                query_name=query.name,
                query_type=query.query_type,
                status=ResolutionStatus.ANSWER,
                canonical_name=current_name,
                answers=ordered_answers,
                steps=steps,
            )

        cname_records = rrsets.get((current_name, RecordType.CNAME), [])
        if cname_records:
            steps.append(_step(cname_records))
            current_name = cname_records[0].value
            continue

        status = ResolutionStatus.NODATA if current_name in owner_names else ResolutionStatus.NXDOMAIN
        return ResolutionResult(
            query_name=query.name,
            query_type=query.query_type,
            status=status,
            canonical_name=current_name,
            answers=[],
            steps=steps,
        )


def simulate_dns_resolution(task: DNSZoneInput) -> list[ResolutionResult]:
    """Return one canonical resolution result for every query in input order."""

    validate_dns_zone_input(task)
    return [resolve_query(task, query) for query in task.queries]
