"""Independently simulate deterministic DNS resolution for one supplied zone."""

from __future__ import annotations

from collections import defaultdict

from contract import (
    DNSQuery,
    DNSRecord,
    DNSZoneInput,
    RecordType,
    ResolutionResult,
    ResolutionStatus,
    ResolutionStep,
)


def _parse_ipv4(value: object) -> tuple[bytes, str] | None:
    if not isinstance(value, str):
        return None
    parts = value.split(".")
    if len(parts) != 4:
        return None

    numbers: list[int] = []
    for part in parts:
        if not part or not part.isascii() or not part.isdigit() or (len(part) > 1 and part.startswith("0")):
            return None
        number = int(part)
        if number > 255:
            return None
        numbers.append(number)

    return bytes(numbers), ".".join(str(number) for number in numbers)


def _parse_ipv6(value: object) -> tuple[bytes, str] | None:
    if not isinstance(value, str) or not value or value.count("::") > 1:
        return None

    if "::" in value:
        left, right = value.split("::")
        left_parts = left.split(":") if left else []
        right_parts = right.split(":") if right else []
        missing_count = 8 - len(left_parts) - len(right_parts)
        if missing_count < 1:
            return None
        parts = [*left_parts, *(["0"] * missing_count), *right_parts]
    else:
        parts = value.split(":")
        if len(parts) != 8:
            return None

    numbers: list[int] = []
    for part in parts:
        if (
            not 1 <= len(part) <= 4
            or not part.isascii()
            or any(character.lower() not in "0123456789abcdef" for character in part)
        ):
            return None
        numbers.append(int(part, 16))

    best_start = -1
    best_length = 0
    start = 0
    while start < 8:
        if numbers[start] != 0:
            start += 1
            continue
        end = start
        while end < 8 and numbers[end] == 0:
            end += 1
        if end - start > best_length and end - start >= 2:
            best_start = start
            best_length = end - start
        start = end

    if best_start >= 0:
        left = ":".join(f"{number:x}" for number in numbers[:best_start])
        right = ":".join(f"{number:x}" for number in numbers[best_start + best_length :])
        if left and right:
            canonical = f"{left}::{right}"
        elif left:
            canonical = f"{left}::"
        elif right:
            canonical = f"::{right}"
        else:
            canonical = "::"
    else:
        canonical = ":".join(f"{number:x}" for number in numbers)

    packed = b"".join(number.to_bytes(2, "big") for number in numbers)
    return packed, canonical


def _parse_address(
    value: object,
    record_type: RecordType,
) -> tuple[int, bytes, str] | None:
    if record_type is RecordType.A:
        parsed = _parse_ipv4(value)
        version = 4
    else:
        parsed = _parse_ipv6(value)
        version = 6
    if parsed is None:
        return None
    packed, canonical = parsed
    return version, packed, canonical


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
    parsed = _parse_address(record.value, record.record_type)
    if parsed is None:
        raise ValueError(f"{record.value!r} is not a valid address.")
    version, packed, _ = parsed
    return version, packed


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
            parsed = _parse_address(record.value, record.record_type)
            if parsed is None:
                raise ValueError(f"{field}.value must be a valid {record.record_type.value} address.")
            _, _, canonical = parsed
            if record.value != canonical:
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
