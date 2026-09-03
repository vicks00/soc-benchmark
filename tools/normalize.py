"""Normalize Windows event records for minimal and curated contexts."""

from __future__ import annotations

EVENT_SPECS: dict[tuple[str, int], tuple[str, dict[str, str]]] = {
    ("sysmon", 1): (
        "ProcessCreate",
        {
            "ProcessId": "process_id",
            "Image": "image",
            "CommandLine": "command_line",
            "CurrentDirectory": "current_directory",
            "User": "user",
            "IntegrityLevel": "integrity_level",
            "Hashes": "hashes",
            "ParentProcessId": "parent_process_id",
            "ParentImage": "parent_image",
            "ParentCommandLine": "parent_command_line",
            "OriginalFileName": "original_file_name",
        },
    ),
    ("sysmon", 3): (
        "NetworkConnect",
        {
            "ProcessId": "process_id",
            "Image": "image",
            "User": "user",
            "Protocol": "protocol",
            "SourceIp": "source_ip",
            "SourcePort": "source_port",
            "DestinationIp": "destination_ip",
            "DestinationPort": "destination_port",
            "DestinationHostname": "destination_hostname",
            "Initiated": "initiated",
        },
    ),
    ("sysmon", 7): (
        "ImageLoad",
        {
            "ProcessId": "process_id",
            "Image": "image",
            "ImageLoaded": "image_loaded",
            "Signed": "signed",
            "Signature": "signature",
            "SignatureStatus": "signature_status",
            "Company": "company",
            "Description": "description",
            "Hashes": "hashes",
        },
    ),
    ("sysmon", 8): (
        "CreateRemoteThread",
        {
            "SourceProcessId": "source_process_id",
            "SourceImage": "source_image",
            "TargetProcessId": "target_process_id",
            "TargetImage": "target_image",
            "StartAddress": "start_address",
            "StartModule": "start_module",
            "StartFunction": "start_function",
        },
    ),
    ("sysmon", 10): (
        "ProcessAccess",
        {
            "SourceProcessId": "source_process_id",
            "SourceImage": "source_image",
            "TargetProcessId": "target_process_id",
            "TargetImage": "target_image",
            "GrantedAccess": "granted_access",
            "CallTrace": "call_trace",
            "SourceUser": "source_user",
        },
    ),
    ("sysmon", 11): (
        "FileCreate",
        {
            "ProcessId": "process_id",
            "Image": "image",
            "TargetFilename": "target_filename",
            "CreationUtcTime": "creation_utc_time",
            "User": "user",
        },
    ),
    ("sysmon", 12): (
        "RegistryAddOrDelete",
        {
            "ProcessId": "process_id",
            "Image": "image",
            "TargetObject": "target_object",
            "EventType": "operation",
        },
    ),
    ("sysmon", 13): (
        "RegistrySetValue",
        {
            "ProcessId": "process_id",
            "Image": "image",
            "TargetObject": "target_object",
            "Details": "details",
            "EventType": "operation",
        },
    ),
    ("sysmon", 15): (
        "FileCreateStreamHash",
        {
            "ProcessId": "process_id",
            "Image": "image",
            "TargetFilename": "target_filename",
            "Hashes": "hashes",
        },
    ),
    ("sysmon", 17): (
        "PipeCreated",
        {
            "ProcessId": "process_id",
            "Image": "image",
            "PipeName": "pipe_name",
        },
    ),
    ("sysmon", 18): (
        "PipeConnected",
        {
            "ProcessId": "process_id",
            "Image": "image",
            "PipeName": "pipe_name",
        },
    ),
    ("sysmon", 22): (
        "DnsQuery",
        {
            "ProcessId": "process_id",
            "Image": "image",
            "QueryName": "query_name",
            "QueryResults": "query_results",
        },
    ),
    ("sysmon", 23): (
        "FileDelete",
        {
            "ProcessId": "process_id",
            "Image": "image",
            "TargetFilename": "target_filename",
            "User": "user",
        },
    ),
    ("security", 4624): (
        "LogonSuccess",
        {
            "TargetUserName": "target_user_name",
            "TargetDomainName": "target_domain_name",
            "LogonType": "logon_type",
            "IpAddress": "source_ip",
            "WorkstationName": "workstation",
            "LogonProcessName": "logon_process",
            "AuthenticationPackageName": "auth_package",
            "TargetLogonId": "logon_id",
        },
    ),
    ("security", 4662): (
        "DirectoryServiceAccess",
        {
            "SubjectUserName": "subject_user_name",
            "SubjectDomainName": "subject_domain_name",
            "SubjectLogonId": "logon_id",
            "ObjectName": "object_name",
            "ObjectType": "object_type",
            "Properties": "properties",
            "AccessMask": "access_mask",
        },
    ),
    ("security", 4672): (
        "SpecialPrivilegesAssigned",
        {
            "SubjectUserName": "subject_user_name",
            "SubjectDomainName": "subject_domain_name",
            "SubjectLogonId": "logon_id",
            "PrivilegeList": "privileges",
        },
    ),
    ("security", 4769): (
        "KerberosServiceTicketRequest",
        {
            "TargetUserName": "target_user_name",
            "ServiceName": "service_name",
            "IpAddress": "source_ip",
            "TicketOptions": "ticket_options",
            "TicketEncryptionType": "ticket_encryption_type",
            "Status": "status",
        },
    ),
    ("security", 4688): (
        "ProcessCreate",
        {
            "NewProcessId": "process_id",
            "NewProcessName": "image",
            "CommandLine": "command_line",
            "ParentProcessName": "parent_image",
            "SubjectUserName": "subject_user_name",
            "SubjectDomainName": "subject_domain_name",
            "TokenElevationType": "token_elevation_type",
            "MandatoryLabel": "mandatory_label",
        },
    ),
    ("security", 4697): (
        "ServiceInstalled",
        {
            "SubjectUserName": "subject_user_name",
            "ServiceName": "service_name",
            "ServiceFileName": "service_file_name",
            "ServiceType": "service_type",
            "ServiceStartType": "service_start_type",
            "ServiceAccount": "service_account",
        },
    ),
    ("security", 4703): (
        "TokenPrivilegeAdjust",
        {
            "SubjectUserName": "subject_user_name",
            "TargetUserName": "target_user_name",
            "ProcessName": "image",
            "EnabledPrivilegeList": "enabled_privileges",
        },
    ),
    ("security", 4720): (
        "UserAccountCreated",
        {
            "SubjectUserName": "subject_user_name",
            "TargetUserName": "target_user_name",
            "TargetDomainName": "target_domain_name",
        },
    ),
    ("security", 5140): (
        "NetworkShareAccess",
        {
            "SubjectUserName": "subject_user_name",
            "ShareName": "share_name",
            "ShareLocalPath": "share_local_path",
            "IpAddress": "source_ip",
            "AccessMask": "access_mask",
        },
    ),
    ("security", 5145): (
        "NetworkShareFileAccess",
        {
            "SubjectUserName": "subject_user_name",
            "SubjectDomainName": "subject_domain_name",
            "ShareName": "share_name",
            "RelativeTargetName": "relative_target_name",
            "AccessMask": "access_mask",
            "AccessList": "access_list",
            "IpAddress": "source_ip",
        },
    ),
    ("security", 5156): (
        "FirewallConnectionAllowed",
        {
            "Application": "image",
            "Direction": "direction",
            "SourceAddress": "source_ip",
            "SourcePort": "source_port",
            "DestAddress": "destination_ip",
            "DestPort": "destination_port",
            "Protocol": "protocol",
        },
    ),
    ("powershell", 4103): (
        "PowerShellPipelineExecution",
        {
            "Payload": "payload",
            "ContextInfo": "context_info",
        },
    ),
    ("powershell", 4104): (
        "PowerShellScriptBlock",
        {
            "ScriptBlockText": "script_block_text",
            "Path": "script_path",
        },
    ),
    # Application and System channel records carry their content in the Message body rather than
    # in structured fields, so `message` is projected verbatim for these.
    ("application", 1000): ("ApplicationError", {"Message": "message"}),
    ("application", 1001): ("WindowsErrorReporting", {"Message": "message"}),
    ("system", 7034): ("ServiceCrashed", {"Message": "message"}),
    ("system", 7036): ("ServiceStateChange", {"Message": "message"}),
    ("system", 7045): ("ServiceInstalled", {"Message": "message"}),
}

_PREFIX = {
    "sysmon": "Sysmon",
    "security": "Security",
    "powershell": "PowerShell",
    "application": "Application",
    "system": "System",
}


def channel_kind(channel: str) -> str:
    lowered = (channel or "").lower()
    if "sysmon" in lowered:
        return "sysmon"
    if "powershell" in lowered:
        return "powershell"
    if lowered in ("application", "system"):
        return lowered
    return "security"


def event_key(raw: dict) -> tuple[str, int]:
    """The (channel_kind, event_id) lookup key into EVENT_SPECS."""
    try:
        eid = int(raw.get("EventID"))
    except (TypeError, ValueError):
        eid = -1
    return channel_kind(raw.get("Channel", "")), eid


def event_time(raw: dict) -> str:
    """Canonical UTC event time as ``YYYY-MM-DD HH:MM:SS.mmm``.

    Sysmon carries ``UtcTime``, but Security and PowerShell carry ``EventTime``/``TimeCreated`` in
    the collector's local zone, which in several captures runs 16 hours off the Sysmon clock. The
    shipper's ``@timestamp`` is UTC on every record, so it is preferred over the local-time fields.
    """
    recorded = (
        raw.get("UtcTime")
        or raw.get("@timestamp")
        or raw.get("TimeCreated")
        or raw.get("EventTime")
        or ""
    )
    moment = str(recorded).strip().replace("T", " ").rstrip("Z")
    if "." not in moment and len(moment) == 19:
        moment += ".000"
    return moment[:23]


def short_host(raw: dict) -> str:
    return str(raw.get("Hostname", "")).split(".")[0]


def normalize(raw: dict, include_host: bool = False) -> dict:
    """Project one raw record onto the flat tier schema.

    An event type absent from EVENT_SPECS still yields id, type, time, and host rather than being
    dropped.
    """
    kind, eid = event_key(raw)
    label, mapping = EVENT_SPECS.get((kind, eid), (f"{kind.capitalize()}Event{eid}", {}))
    prefix = _PREFIX[kind]

    out: dict[str, object] = {
        "event_id": f"{prefix}/{eid}",
        "event_type": label,
        "utc_time": event_time(raw),
    }
    if raw.get("record_id"):
        out["record_id"] = raw["record_id"]
    if include_host:
        out["host"] = short_host(raw)
    for src, dst in mapping.items():
        val = raw.get(src)
        if val in (None, "", "-"):
            continue
        out[dst] = val
    return out
