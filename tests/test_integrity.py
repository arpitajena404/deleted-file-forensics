"""
Unit tests for Image Integrity and Hashing module.
"""

import hashlib
import os
import tempfile
import pytest
from pathlib import Path

from src.forensics.image_integrity import (
    calculate_image_hashes,
    verify_image_immutability,
    create_case_record,
    load_case_record,
)


def test_streaming_hashing(tmp_path):
    test_file = tmp_path / "test_image.raw"
    # Write 2.5 MB of deterministic data
    data = b"FORENSIC_TEST_CHUNK_DATA_12345" * 80000
    test_file.write_bytes(data)

    expected_sha256 = hashlib.sha256(data).hexdigest().lower()
    expected_md5 = hashlib.md5(data).hexdigest().lower()

    sha256_out, md5_out, size_out = calculate_image_hashes(str(test_file), chunk_size=65536)

    assert sha256_out.lower() == expected_sha256
    assert md5_out.lower() == expected_md5
    assert size_out == len(data)


def test_verify_image_immutability(tmp_path):
    test_file = tmp_path / "evidence.raw"
    test_file.write_bytes(b"IMMUTABLE_EVIDENCE_BYTES")
    correct_hash = hashlib.sha256(b"IMMUTABLE_EVIDENCE_BYTES").hexdigest()

    assert verify_image_immutability(str(test_file), correct_hash) is True
    assert verify_image_immutability(str(test_file), "00000000000000000000000000000000") is False


def test_case_record_roundtrip(tmp_path):
    test_img = tmp_path / "working_copy.raw"
    test_img.write_bytes(b"TEST_CASE_RAW_DATA")
    case_dir = tmp_path / "cases"

    record = create_case_record(
        case_id="TEST-CASE-01",
        case_name="Unit Test Case",
        examiner_name="Test Examiner",
        image_path=str(test_img),
        is_working_copy=True,
        master_sha256="dummy_master_hash",
        partition_offset_bytes=1048576,
        examiner_notes="Test notes for evidence intake",
        output_dir=str(case_dir),
    )

    assert record.case_id == "TEST-CASE-01"
    assert record.partition_offset_bytes == 1048576

    loaded = load_case_record(str(case_dir / "TEST-CASE-01.json"))
    assert loaded.case_id == "TEST-CASE-01"
    assert loaded.examiner_name == "Test Examiner"
    assert loaded.image_sha256 == record.image_sha256
    assert loaded.is_working_copy is True
    assert loaded.master_sha256 == "dummy_master_hash"


def test_missing_image_raises_error():
    with pytest.raises(FileNotFoundError):
        calculate_image_hashes("non_existent_image_file.raw")
