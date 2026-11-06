"""Each tool's and task's typed input and output: declarations only."""

from dataclasses import dataclass
from enum import Enum
from typing import Annotated

from slimconfig import Output


class Tool(Enum):
    READ_ZONE = "read_zone"
    WRITE_RESOLUTIONS = "write_resolutions"


class Task(Enum):
    SIMULATE_DNS_RESOLUTION = "simulate-dns-resolution"


class RecordType(Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"


class QueryType(Enum):
    A = "A"
    AAAA = "AAAA"


class ResolutionStatus(Enum):
    ANSWER = "ANSWER"
    NXDOMAIN = "NXDOMAIN"
    NODATA = "NODATA"
    CNAME_LOOP = "CNAME_LOOP"


@dataclass
class DNSRecord(Output):
    name: Annotated[str, "Lowercase absolute owner name ending in a dot."]
    record_type: Annotated[RecordType, "DNS record type."]
    value: Annotated[str, "IP address or lowercase absolute CNAME target."]
    ttl: Annotated[int, "Non-negative time-to-live in seconds."]


@dataclass
class DNSQuery(Output):
    name: Annotated[str, "Lowercase absolute name ending in a dot."]
    query_type: Annotated[QueryType, "Address record type to resolve."]


@dataclass
class DNSZoneInput(Output):
    origin: Annotated[str, "Lowercase absolute zone origin ending in a dot."]
    records: Annotated[list[DNSRecord], "Authoritative records contained in the zone."]
    queries: Annotated[list[DNSQuery], "One or more address queries in requested output order."]


@dataclass
class ResolutionStep(Output):
    name: Annotated[str, "Owner name examined during resolution."]
    record_type: Annotated[RecordType, "Record type followed or returned."]
    values: Annotated[list[str], "Canonical ordered values in the selected RRset."]
    ttl: Annotated[int, "Shared TTL for the selected RRset."]


@dataclass
class ResolutionResult(Output):
    query_name: Annotated[str, "Query name copied exactly from the task."]
    query_type: Annotated[QueryType, "Query type copied exactly from the task."]
    status: Annotated[ResolutionStatus, "Deterministic resolution outcome."]
    canonical_name: Annotated[
        str,
        "Final name examined, including a repeated name when a CNAME loop is detected.",
    ]
    answers: Annotated[
        list[DNSRecord],
        "Canonical ordered terminal A or AAAA records; empty unless status is ANSWER.",
    ]
    steps: Annotated[
        list[ResolutionStep],
        "CNAME RRsets followed and the terminal address RRset when present.",
    ]


@dataclass
class DNSZoneOutput(Output):
    resolutions: Annotated[
        list[ResolutionResult],
        "Exactly one deterministic result for every query in input order.",
    ]


@dataclass
class ReadZoneInput(Output):
    task: Annotated[DNSZoneInput, "The DNS zone task input to inspect."]


@dataclass
class ReadZoneOutput(Output):
    origin: str
    records: list[DNSRecord]
    queries: list[DNSQuery]


@dataclass
class WriteResolutionsInput(Output):
    task: Annotated[DNSZoneInput, "The task input copied exactly as given."]
    resolutions: Annotated[
        list[ResolutionResult],
        "The final resolution results for every query, copied exactly as given.",
    ]


@dataclass
class WriteResolutionsOutput(Output):
    report_path: Annotated[str, "The report path written relative to the workspace."]
    report: DNSZoneOutput


TOOLS = {
    Tool.READ_ZONE: (ReadZoneInput, ReadZoneOutput),
    Tool.WRITE_RESOLUTIONS: (WriteResolutionsInput, WriteResolutionsOutput),
}

TASKS = {
    Task.SIMULATE_DNS_RESOLUTION: (DNSZoneInput, DNSZoneOutput),
}
