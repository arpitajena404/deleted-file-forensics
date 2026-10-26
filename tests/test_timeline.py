"""
Unit tests for Forensic Timeline generation.
"""

from datetime import datetime, timezone
from src.forensics.timeline import build_forensic_timeline, format_timeline_table
from src.forensics.models import FileRecord


def test_build_timeline_ordering():
    t1 = datetime(2026, 10, 24, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 24, 11, 0, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc)

    rec1 = FileRecord(
        record_number=36,
        sequence_number=1,
        in_use=True,
        is_directory=False,
        filename="FILE_A.txt",
        path="\\FILE_A.txt",
        parent_record=5,
        file_size=100,
        allocated_size=100,
        si_created=t3,
        si_modified=t1,
    )

    rec2 = FileRecord(
        record_number=37,
        sequence_number=1,
        in_use=False,
        is_directory=False,
        filename="FILE_B.txt",
        path="\\FILE_B.txt",
        parent_record=5,
        file_size=200,
        allocated_size=200,
        si_created=t2,
    )

    events = build_forensic_timeline([rec1, rec2])
    assert len(events) == 3

    # Must be sorted chronologically
    assert events[0].timestamp == t1
    assert events[0].filename == "FILE_A.txt"
    assert events[1].timestamp == t2
    assert events[1].filename == "FILE_B.txt"
    assert events[2].timestamp == t3
    assert events[2].filename == "FILE_A.txt"

    # Verify formatting
    tbl = format_timeline_table(events)
    assert len(tbl) == 3
    assert tbl[0]["Target File"] == "FILE_A.txt"
    assert tbl[0]["Status"] == "Allocated"
    assert tbl[1]["Status"] == "Deleted / Unallocated"
