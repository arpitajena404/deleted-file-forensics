"""
Unit tests for NTFS File System Parser.
"""

import datetime
import os
import struct
import pytest
from src.forensics.ntfs_parser import (
    filetime_to_datetime,
    datetime_to_filetime,
    detect_partition_offset,
    NTFSParser,
)
from scripts.create_test_image import generate_synthetic_case


def test_filetime_conversion():
    # Jan 1, 1970 00:00:00 UTC = 11644473600 seconds = 116444736000000000 filetime
    ft_epoch = 116444736000000000
    dt_epoch = filetime_to_datetime(ft_epoch)
    assert dt_epoch is not None
    assert dt_epoch.year == 1970
    assert dt_epoch.month == 1
    assert dt_epoch.day == 1
    assert dt_epoch.hour == 0

    # Negative / zero filetime
    assert filetime_to_datetime(0) is None
    assert filetime_to_datetime(-100) is None

    # Roundtrip conversion
    now_dt = datetime.datetime(2026, 10, 24, 15, 30, 45, tzinfo=datetime.timezone.utc)
    ft_now = datetime_to_filetime(now_dt)
    dt_back = filetime_to_datetime(ft_now)
    assert dt_back == now_dt


def test_ntfs_parser_on_real_image(tmp_path):
    # Generate test image in temp dir
    meta = generate_synthetic_case(output_dir=str(tmp_path), include_mbr_partition=False)
    image_path = meta["working_copy"]

    offset, desc = detect_partition_offset(image_path)
    assert offset == 0

    with NTFSParser(image_path, partition_offset=offset) as parser:
        records = parser.scan_all_records()
        assert len(records) >= 8

        # Record 0 ($MFT)
        assert 0 in records
        rec0 = records[0]
        assert rec0.filename == "$MFT"
        assert rec0.in_use is True

        # Control file: Record 36 (README.txt)
        assert 36 in records
        rec36 = records[36]
        assert rec36.filename == "README.txt"
        assert rec36.in_use is True
        assert rec36.path == "\\README.txt"
        assert rec36.file_size > 50

        # Deleted file: Record 38 (BUDGET_DRAFT.txt)
        assert 38 in records
        rec38 = records[38]
        assert rec38.filename == "BUDGET_DRAFT.txt"
        assert rec38.in_use is False  # UNALLOCATED / DELETED!
        assert rec38.path == "\\BUDGET_DRAFT.txt"
        assert rec38.resident_data is not None
        assert b"CONFIDENTIAL" in rec38.resident_data
        assert rec38.si_modified is not None
        assert rec38.fn_created is not None


def test_partition_offset_detection_mbr(tmp_path):
    meta = generate_synthetic_case(output_dir=str(tmp_path), include_mbr_partition=True)
    image_path = meta["working_copy"]

    offset, desc = detect_partition_offset(image_path)
    assert offset == 1048576  # Sector 2048 * 512
    assert "MBR Partition 1" in desc

    with NTFSParser(image_path, partition_offset=offset) as parser:
        records = parser.scan_all_records()
        assert 38 in records
        assert records[38].filename == "BUDGET_DRAFT.txt"
        assert not records[38].in_use


def test_parser_handles_corrupt_data(tmp_path):
    # Create corrupted dummy image
    corrupt_img = tmp_path / "corrupt.raw"
    corrupt_img.write_bytes(b"\x00" * 4096)

    with pytest.raises(ValueError, match="Invalid NTFS signature"):
        NTFSParser(str(corrupt_img))
