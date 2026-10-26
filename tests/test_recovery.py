"""
Unit tests for Deleted File Recovery and Hash Verification module.
"""

import hashlib
import os
import pytest
from src.forensics.ntfs_parser import NTFSParser
from src.forensics.recovery import attempt_recovery, load_ground_truth
from src.forensics.models import FileRecord
from scripts.create_test_image import generate_synthetic_case


def test_recovery_match(tmp_path):
    meta = generate_synthetic_case(output_dir=str(tmp_path))
    image_path = meta["working_copy"]
    gt_file = meta["ground_truth"]

    gt_data = load_ground_truth(gt_file).get("target_file")
    assert gt_data is not None

    with NTFSParser(image_path) as parser:
        records = parser.scan_all_records()
        target_rec = records[38]
        assert not target_rec.in_use

        res = attempt_recovery(
            parser=parser,
            record=target_rec,
            case_id="TEST-CASE",
            output_base_dir=str(tmp_path / "recovered"),
            ground_truth_record=gt_data,
        )

        assert res.status == "MATCH"
        assert res.recovered_path is not None
        assert os.path.exists(res.recovered_path)
        assert res.recovered_sha256.lower() == gt_data["sha256"].lower()
        assert "MATCH verified" in res.investigative_notes


def test_recovery_mismatch(tmp_path):
    meta = generate_synthetic_case(output_dir=str(tmp_path))
    with NTFSParser(meta["working_copy"]) as parser:
        records = parser.scan_all_records()
        target_rec = records[38]

        fake_gt = {
            "filename": "BUDGET_DRAFT.txt",
            "sha256": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        }

        res = attempt_recovery(
            parser=parser,
            record=target_rec,
            case_id="TEST-MISMATCH",
            output_base_dir=str(tmp_path / "recovered"),
            ground_truth_record=fake_gt,
        )

        assert res.status == "MISMATCH"
        assert res.recovered_sha256 != fake_gt["sha256"]
        assert "MISMATCH" in res.investigative_notes


def test_recovery_no_data_available(tmp_path):
    # Construct an empty FileRecord with no resident data and no cluster runs
    empty_rec = FileRecord(
        record_number=99,
        sequence_number=1,
        in_use=False,
        is_directory=False,
        filename="EMPTY_DELETED.txt",
        path="\\EMPTY_DELETED.txt",
        parent_record=5,
        file_size=0,
        allocated_size=0,
        is_resident=True,
        resident_data=None,
        data_runs=[],
    )

    with NTFSParser(meta_image_placeholder(tmp_path)) as parser:
        res = attempt_recovery(
            parser=parser,
            record=empty_rec,
            case_id="TEST-EMPTY",
            output_base_dir=str(tmp_path / "recovered"),
        )

        assert res.status == "NOT_AVAILABLE"
        assert res.recovered_path is None
        assert "not recoverable in this test" in res.investigative_notes


def meta_image_placeholder(tmp_path):
    meta = generate_synthetic_case(output_dir=str(tmp_path / "env"))
    return meta["working_copy"]
