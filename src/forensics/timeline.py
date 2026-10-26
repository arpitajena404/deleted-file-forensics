"""
Forensic Timeline and Event Analysis Module.
Extracts, structures, and correlates $STANDARD_INFORMATION and $FILE_NAME timestamps.
Enforces strict separation between empirical file system artifacts and investigative inferences.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional

from .models import FileRecord, TimelineEvent

EXPLANATIONS = {
    "SI_CREATED": (
        "$STANDARD_INFORMATION Creation timestamp. Reflects file creation time as maintained by the Windows shell "
        "and application layer. Can be modified by userland APIs (vulnerable to timestomping)."
    ),
    "SI_MODIFIED": (
        "$STANDARD_INFORMATION Content Altered / Modification timestamp. Updated when data stream content "
        "is written or flushed to disk."
    ),
    "SI_MFT_MODIFIED": (
        "$STANDARD_INFORMATION MFT Record Modified timestamp. Updated by the NTFS kernel driver whenever any MFT "
        "attribute is modified. Highly resistant to userland tampering."
    ),
    "SI_ACCESSED": (
        "$STANDARD_INFORMATION Last Access timestamp. Indicates when file was opened or read. "
        "Note: Windows often disables or defers last access updates for performance (NtfsDisableLastAccessUpdate)."
    ),
    "FN_CREATED": (
        "$FILE_NAME Creation timestamp. Recorded when the directory entry was first established. "
        "Copied from $STANDARD_INFORMATION at creation time and typically NOT altered by timestomping utilities."
    ),
    "FN_MODIFIED": (
        "$FILE_NAME Modification timestamp. Updated when the file is renamed or moved within directories; "
        "often preserves initial modification time."
    ),
    "FN_MFT_MODIFIED": (
        "$FILE_NAME MFT Modified timestamp. Updated on directory metadata operations."
    ),
    "FN_ACCESSED": (
        "$FILE_NAME Last Access timestamp. Associated with directory index updates."
    ),
}


def build_forensic_timeline(records: List[FileRecord], include_allocated: bool = True) -> List[TimelineEvent]:
    """
    Extracts all empirical timestamps from file records and builds a chronological timeline.
    Omits synthetic or invented dates; handles missing values cleanly.
    """
    events: List[TimelineEvent] = []

    for rec in records:
        if not include_allocated and rec.in_use:
            continue

        alloc_label = "Allocated" if rec.in_use else "Deleted / Unallocated"

        # Check all 8 potential timestamps
        timestamp_specs = [
            ("SI_CREATED", "File Created ($STANDARD_INFORMATION)", rec.si_created, "$STANDARD_INFORMATION"),
            ("SI_MODIFIED", "Content Modified ($STANDARD_INFORMATION)", rec.si_modified, "$STANDARD_INFORMATION"),
            ("SI_MFT_MODIFIED", "MFT Record Modified ($STANDARD_INFORMATION)", rec.si_mft_modified, "$STANDARD_INFORMATION"),
            ("SI_ACCESSED", "Last Accessed ($STANDARD_INFORMATION)", rec.si_accessed, "$STANDARD_INFORMATION"),
            ("FN_CREATED", "File Created ($FILE_NAME)", rec.fn_created, "$FILE_NAME"),
            ("FN_MODIFIED", "Content Modified ($FILE_NAME)", rec.fn_modified, "$FILE_NAME"),
            ("FN_MFT_MODIFIED", "MFT Record Modified ($FILE_NAME)", rec.fn_mft_modified, "$FILE_NAME"),
            ("FN_ACCESSED", "Last Accessed ($FILE_NAME)", rec.fn_accessed, "$FILE_NAME"),
        ]

        for code, label, dt, attr_name in timestamp_specs:
            if dt is not None:
                source_art = f"$MFT Record {rec.record_number} ({attr_name})"
                explanation = EXPLANATIONS.get(code, "File system timestamp recorded in NTFS metadata.")
                
                # Default cautious observation
                note = ""
                if not rec.in_use:
                    if code == "SI_MFT_MODIFIED":
                        note = "MFT modification timestamp may correlate closely with the deallocation/deletion event."
                    elif code == "SI_MODIFIED":
                        note = "Last active content modification prior to file deallocation."

                events.append(TimelineEvent(
                    timestamp=dt,
                    timestamp_type=code,
                    timestamp_name=label,
                    record_number=rec.record_number,
                    filename=rec.filename,
                    path=rec.path,
                    allocation_status=alloc_label,
                    source_artifact=source_art,
                    forensic_explanation=explanation,
                    investigator_note=note,
                ))

    # Sort chronologically
    events.sort(key=lambda e: e.timestamp)
    return events


def format_timeline_table(events: List[TimelineEvent]) -> List[Dict[str, Any]]:
    """Formats timeline events for rendering in tabular format or reporting."""
    table_rows = []
    for ev in events:
        table_rows.append({
            "Timestamp (UTC)": ev.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") if ev.timestamp else "unknown",
            "Event": ev.timestamp_name,
            "Target File": ev.filename,
            "Path": ev.path,
            "Status": ev.allocation_status,
            "Source Artifact": ev.source_artifact,
            "Investigative Interpretation": ev.investigator_note or "Consistent with normal file operations.",
        })
    return table_rows
