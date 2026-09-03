"""Build frozen scenario contexts and reference keys from their specifications."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from functools import lru_cache
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import pcap  # noqa: E402
from normalize import event_time, normalize, short_host  # noqa: E402

from harness.blinding import blind_context  # noqa: E402

SCENARIOS_DIR = BASE / "scenarios"
DATASETS_DIR = BASE / "datasets"

_SHIPPER_NOISE = {
    "@version",
    "@timestamp",
    "tags",
    "port",
    "SourceModuleName",
    "SourceModuleType",
    "EventReceivedTime",
    "ThreadID",
    "OpcodeValue",
    "Opcode",
    "Keywords",
    "RecordNumber",
    "ProviderGuid",
    "Version",
    "ExecutionProcessID",
    "host",
    "type",
    "beat",
    "input_type",
    "count",
    "offset",
    "fields",
    "@metadata",
    "AccountType",
    "EventTime",
    "Severity",
    "SeverityValue",
    "Task",
    "SourceName",
    "UserID",
    "ActivityID",
    "RelatedActivityID",
}


def load_capture(zip_name: str) -> list[dict]:
    """Read newline-delimited JSON records from a capture archive."""
    path = DATASETS_DIR / zip_name
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Run tools/fetch_datasets.sh, or see datasets/README.md."
        )
    events = []
    with zipfile.ZipFile(path) as archive:
        members = [name for name in archive.namelist() if name.lower().endswith(".json")]
        if not members:
            raise ValueError(f"{zip_name} contains no JSON capture (members: {archive.namelist()})")
        for member in members:
            with archive.open(member) as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    events.sort(key=event_time)
    return events


# String ops; gte/lte are lexical (fine for ISO-8601, wrong for numbers).
_OPERATORS = {
    "eq": lambda actual, expected: actual == str(expected),
    "ieq": lambda actual, expected: actual.lower() == str(expected).lower(),
    "contains": lambda actual, expected: str(expected).lower() in actual.lower(),
    "not_contains": lambda actual, expected: str(expected).lower() not in actual.lower(),
    "startswith": lambda actual, expected: actual.lower().startswith(str(expected).lower()),
    "endswith": lambda actual, expected: actual.lower().endswith(str(expected).lower()),
    "in": lambda actual, expected: actual.lower() in {str(item).lower() for item in expected},
    "gte": lambda actual, expected: actual >= str(expected),
    "lte": lambda actual, expected: actual <= str(expected),
}


def matches(record: dict, where: dict) -> bool:
    """`where` keys are `field` (exact) or `field__op`, all ANDed together.

    Applies to raw capture records and normalized projections alike; the caller chooses which by
    passing the corresponding field names.
    """
    for key, expected in where.items():
        field, _, operator = key.partition("__")
        value = record.get(field)
        if value is None:
            return False
        try:
            compare = _OPERATORS[operator or "eq"]
        except KeyError:
            raise ValueError(f"unknown selector operator: {operator}") from None
        if not compare(str(value), expected):
            return False
    return True


def _selector_hits(record: dict, selector: dict) -> bool:
    event_id = selector.get("event_id")
    if event_id and record.get("event_id") != event_id:
        return False
    where = selector.get("where")
    return not where or matches(record, where)


def select(
    records: list[dict], selectors: list[dict], hosts: list[str] | None = None
) -> list[dict]:
    """Apply an ordered selector list; de-duplicate while preserving chronological order.

    `hosts` is the short hostname of each record, positionally aligned, and is required only when a
    selector carries a `host` key.
    """
    picked: list[dict] = []
    seen: set[str] = set()
    for selector in selectors:
        wanted_host = selector.get("host")
        limit = selector.get("limit")
        hits = 0
        for position, record in enumerate(records):
            if wanted_host and (hosts is None or hosts[position] != wanted_host):
                continue
            if not _selector_hits(record, selector):
                continue
            key = json.dumps(record, sort_keys=True)
            if key not in seen:
                seen.add(key)
                picked.append(record)
            hits += 1
            if limit and hits >= limit:
                break
        if hits == 0:
            print(f"    ! selector matched nothing: {selector}")
    picked.sort(key=lambda record: record["utc_time"])
    return picked


class Capture:
    """A capture's raw records alongside their normalized projections.

    Selectors scan the whole capture repeatedly, so each projection is built once and reused rather
    than recomputed per selector.
    """

    def __init__(self, events: list[dict]):
        # IDs are assigned before any tier selects or projects records. The same source event
        # therefore keeps one citation in minimal, curated, and verbose contexts.
        self.events = [
            {**event, "record_id": f"R{index:06d}"} for index, event in enumerate(events, start=1)
        ]
        self.hosts = [short_host(raw) for raw in self.events]
        self.times = [event_time(raw) for raw in self.events]
        self._projections: dict[bool, list[dict]] = {}

    def normalized(self, include_host: bool = False) -> list[dict]:
        projection = self._projections.get(include_host)
        if projection is None:
            projection = [normalize(raw, include_host=include_host) for raw in self.events]
            self._projections[include_host] = projection
        return projection


def _even_sample(items: list, count: int) -> list:
    """Return a deterministic even sample."""
    if count >= len(items):
        return items
    step = len(items) / count
    return [items[int(index * step)] for index in range(count)]


def build_verbose(capture: Capture, config: dict) -> tuple[list[dict], dict]:
    """Build deterministic, windowed verbose telemetry."""
    hosts = set(config.get("hosts", []))
    start, end = config.get("start"), config.get("end")
    drop_ids = {str(value) for value in config.get("drop_event_ids", [])}
    keep_all = {str(value) for value in config.get("keep_all_event_ids", [])}
    cap = config.get("max_per_event_id")
    max_events = config.get("max_events")

    window: list[int] = []
    dropped = 0
    for position, raw in enumerate(capture.events):
        if hosts and capture.hosts[position] not in hosts:
            continue
        moment = capture.times[position]
        if (start and moment < start) or (end and moment > end):
            continue
        if str(raw.get("EventID")) in drop_ids:
            dropped += 1
            continue
        window.append(position)

    # Pinned records survive per-event sampling. Only the windowed slice needs projecting, and
    # most scenarios pin nothing at all.
    pin_selectors = config.get("pin", [])
    pinned: set[int] = set()
    if pin_selectors:
        for position in window:
            record = normalize(capture.events[position])
            if any(_selector_hits(record, selector) for selector in pin_selectors):
                pinned.add(position)

    sampled: dict[str, tuple[int, int]] = {}
    if cap:
        buckets: dict[str, list[int]] = {}
        for position in window:
            raw = capture.events[position]
            buckets.setdefault(f"{raw.get('Channel')}/{raw.get('EventID')}", []).append(position)
        keep: set[int] = set(pinned)
        for label, bucket in buckets.items():
            if label.rsplit("/", 1)[-1] in keep_all or len(bucket) <= cap:
                keep.update(bucket)
            else:
                chosen = _even_sample(
                    [position for position in bucket if position not in pinned], cap
                )
                keep.update(chosen)
                sampled[label] = (
                    len(bucket),
                    len(chosen) + sum(1 for position in bucket if position in pinned),
                )
        window = [position for position in window if position in keep]

    kept = [
        {key: value for key, value in capture.events[position].items() if key not in _SHIPPER_NOISE}
        for position in window
    ]

    if max_events and len(kept) > max_events:
        raise ValueError(
            f"verbose tier has {len(kept)} events, over this scenario's cap of {max_events}. "
            f"Tighten the window or lower max_per_event_id. Do not silently truncate; that would "
            f"remove evidence the gold key expects to be present."
        )
    return kept, {"dropped": dropped, "sampled": sampled}


@lru_cache(maxsize=1)
def env_map() -> tuple[tuple[str, str], ...]:
    """Lab-identifier substitutions, longest-first so that FQDNs are rewritten before bare names."""
    raw = json.loads((Path(__file__).resolve().parent / "environment_map.json").read_text())
    return tuple(sorted(raw["map"].items(), key=lambda pair: -len(pair[0])))


def anonymize(obj):
    """Rewrite lab identifiers to neutral corporate ones.

    Must be applied to contexts and gold keys together, or a reference keyword stops matching the
    telemetry it grades against.
    """
    return _substitute(obj, env_map())


def case_id(scenario_id: str) -> str:
    """Opaque case identifier. Hashed, not sequential: it must encode nothing about the answer."""
    return "CASE-" + hashlib.sha256(scenario_id.encode()).hexdigest()[:8].upper()


def apply_transform(events: list[dict], transform: dict) -> tuple[list[dict], dict]:
    """Apply remove, replace, and inject operations to capture records."""
    stats = {"removed": 0, "replaced": 0, "injected": 0}

    kept = []
    for raw in events:
        if any(matches(raw, selector) for selector in transform.get("remove", [])):
            stats["removed"] += 1
            continue
        kept.append(raw)

    for rule in transform.get("replace", []):
        selector = rule.get("where")
        pairs = rule.get("pairs", [])
        fields = rule.get("set", {})
        for position, raw in enumerate(kept):
            if selector and not matches(raw, selector):
                continue
            replaced = _substitute(raw, pairs)
            replaced.update(fields)
            if replaced != raw:
                kept[position] = replaced
                stats["replaced"] += 1

    for record in transform.get("inject", []):
        kept.append(record)
        stats["injected"] += 1

    kept.sort(key=event_time)
    return kept, stats


def _substitute(value, pairs):
    """Apply ordered substitutions to strings at any depth."""
    if isinstance(value, str):
        for source, target in pairs:
            value = value.replace(source, target)
        return value
    if isinstance(value, dict):
        return {key: _substitute(nested, pairs) for key, nested in value.items()}
    if isinstance(value, list):
        return [_substitute(nested, pairs) for nested in value]
    return value


def _timestamp(moment) -> str:
    return moment.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def load_pcap_tiers(spec: dict) -> tuple[list[dict], list[dict]]:
    """Return flow and packet records from each configured sensor."""
    zip_path = DATASETS_DIR / spec["source"]["zip"]
    if not zip_path.exists():
        raise FileNotFoundError(f"{zip_path} not found. See datasets/README.md.")

    flows, packets = [], []
    with zipfile.ZipFile(zip_path) as archive:
        for sensor, member in spec["source"]["captures"].items():
            parsed = pcap.read_packet_bytes(archive.read(member), member)
            for flow in pcap.flows(parsed):
                flows.append(
                    {
                        "event_id": "NetworkFlow",
                        "event_type": "TcpFlow",
                        "utc_time": _timestamp(flow["first_seen"]),
                        "sensor": sensor,
                        "source_ip": flow["source_ip"],
                        "source_port": flow["source_port"],
                        "destination_ip": flow["destination_ip"],
                        "destination_port": flow["destination_port"],
                        "protocol": "tcp",
                        "duration_s": round(
                            (flow["last_seen"] - flow["first_seen"]).total_seconds(), 3
                        ),
                        "packets": flow["packets"],
                        "bytes_to_server": flow["bytes_to_server"],
                        "bytes_to_client": flow["bytes_to_client"],
                        "handshake_observed": flow["saw_syn"],
                    }
                )
            for packet in parsed:
                packets.append(
                    {
                        "event_id": "NetworkPacket",
                        "event_type": "TcpSegment",
                        "utc_time": _timestamp(packet["ts"]),
                        "sensor": sensor,
                        "source_ip": packet["src"],
                        "source_port": packet["sport"],
                        "destination_ip": packet["dst"],
                        "destination_port": packet["dport"],
                        "tcp_flags": packet["flags"] or "(none)",
                        "payload_bytes": packet["payload_len"],
                    }
                )
    flows.sort(key=lambda record: (record["utc_time"], record["sensor"]))
    packets.sort(key=lambda record: (record["utc_time"], record["sensor"]))
    for prefix, records in (("F", flows), ("P", packets)):
        for index, record in enumerate(records, start=1):
            record["record_id"] = f"{prefix}{index:06d}"
    return flows, packets


def build(spec: dict, capture: Capture | None) -> dict[str, dict]:
    scenario_id = spec["scenario_id"]
    multi_host = bool(spec.get("multi_host"))
    header = {
        "case_id": case_id(scenario_id),
        "environment": spec["environment"],
        "alert": spec["alert"],
    }

    if spec["source"]["kind"] == "pcap":
        flows, packets = load_pcap_tiers(spec)
        minimal = select(flows, spec["select"]["minimal"])
        curated = select(flows, spec["select"]["curated"])
        verbose = packets
        coverage = {
            "format": "tcp_packet_headers",
            "sensors": sorted(spec["source"]["captures"]),
            "payload_content": False,
        }
    else:
        if capture is None:
            raise ValueError(f"{scenario_id}: host and derived scenarios require a capture")
        records = capture.normalized(multi_host)
        minimal = select(records, spec["select"]["minimal"], capture.hosts)
        curated = select(records, spec["select"]["curated"], capture.hosts)
        verbose, stats = build_verbose(capture, spec["select"]["verbose"])
        coverage = {
            "format": "raw_windows_events",
            "dropped_events": stats["dropped"],
            "sampling": {
                label: {"source": source, "retained": retained}
                for label, (source, retained) in sorted(stats["sampled"].items())
            },
            "complete_event_ids": sorted(
                str(value) for value in spec["select"]["verbose"].get("keep_all_event_ids", [])
            ),
        }

    contexts = {}
    for tier, telemetry in (("minimal", minimal), ("curated", curated), ("verbose", verbose)):
        context = dict(header)
        context["context_tier"] = tier
        context["telemetry"] = telemetry
        if tier == "curated":
            context["enrichment"] = spec["enrichment"]
        if tier == "verbose":
            context["telemetry_coverage"] = coverage
        contexts[tier] = context
    return contexts


def _write_or_compare(path: Path, text: str, check: bool) -> int:
    """Write the artifact, or report whether it drifted from what is committed."""
    if not check:
        path.write_text(text)
        return 0
    current = path.read_text() if path.exists() else ""
    if current == text:
        return 0
    print(f"    DRIFT: {path.relative_to(BASE)}")
    return 1


def run(only: str | None, check: bool) -> int:
    specs = sorted(SCENARIOS_DIR.glob("*/spec.json"))
    if only:
        specs = [path for path in specs if only in path.parent.name]
    if not specs:
        print(f"No specs matched {only!r}.")
        return 1

    capture_cache: dict[str, list[dict]] = {}
    drift = 0
    for spec_path in specs:
        spec = json.loads(spec_path.read_text())
        out_dir = spec_path.parent
        source = spec["source"]
        print(f"==> {spec['scenario_id']}  ({source['kind']})")

        capture = None
        if source["kind"] in ("host", "derived"):
            zip_name = source["zip"]
            if zip_name not in capture_cache:
                capture_cache[zip_name] = load_capture(zip_name)
            events = capture_cache[zip_name]
            if source["kind"] == "derived":
                events, stats = apply_transform(events, spec["transform"])
                print(
                    f"    transform: {stats['removed']} removed, "
                    f"{stats['replaced']} rewritten, {stats['injected']} injected"
                )
            capture = Capture(events)

        contexts = {
            tier: anonymize(blind_context(context))
            for tier, context in build(spec, capture).items()
        }
        for tier, context in contexts.items():
            text = json.dumps(context, indent=2) + "\n"
            drift += _write_or_compare(out_dir / f"context_{tier}.json", text, check)
            print(
                f"    {tier:<8} {len(context['telemetry']):>4} events  {len(text) / 1024:>7.1f} KB"
            )

        gold = anonymize(dict(spec["gold"]))
        gold["scenario_id"] = spec["scenario_id"]
        gold["scenario_family"] = spec["scenario_family"]
        drift += _write_or_compare(out_dir / "gold.json", json.dumps(gold, indent=2) + "\n", check)

    if check:
        print(f"\n{f'DRIFT DETECTED in {drift} file(s)' if drift else 'No drift.'}")
        return 1 if drift else 0
    print("\nBuilt.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", nargs="?", help="substring of a scenario directory name")
    parser.add_argument(
        "--check",
        action="store_true",
        help="rebuild in memory and fail if committed artifacts differ",
    )
    args = parser.parse_args()
    raise SystemExit(run(args.scenario, args.check))
