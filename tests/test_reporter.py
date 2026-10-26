"""
Unit tests for Forensic Case Report generation.
"""

from datetime import datetime, timezone
from pathlib import Path
from src.forensics.models import CaseRecord, FileRecord, RecoveryResult, TimelineEvent
from src.forensics.reporter import generate_case_report


def test_generate_case_report(tmp_path):
    case = CaseRecord(
        case_id="REPORT-TEST-01",
        case_name="Report Generation Test Case",
        examiner_name="Student Examiner",
        created_at=datetime.now(timezone.utc).isoformat(),
        image_path="evidence/working_copy.raw",
        image_size_bytes=2097152,
        image_sha256="2f76ab5c2c3521c784fa013290070a7ff88d99bd27eb2ff567b798e06a7897ac",
        image_md5="abcdef1234567890abcdef1234567890",
        is_working_copy=True,
        master_sha256="2f76ab5c2c3521c784fa013290070a7ff88d99bd27eb2ff567b798e06a7897ac",
        partition_offset_bytes=0,
        examiner_notes="Unit test notes.",
    )

    t_now = datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc)
    target_rec = FileRecord(
        record_number=38,
        sequence_number=2,
        in_use=False,
        is_directory=False,
        filename="BUDGET_DRAFT.txt",
        path="\\BUDGET_DRAFT.txt",
        parent_record=5,
        file_size=327,
        allocated_size=327,
        is_resident=True,
        resident_data=b"CONFIDENTIAL FINANCIAL DATA TEST BYTES",
        si_created=t_now,
        si_modified=t_now,
        si_mft_modified=t_now,
        si_accessed=t_now,
        source_artifact="$MFT Record 38",
    )

    rec_res = RecoveryResult(
        target_filename="BUDGET_DRAFT.txt",
        record_number=38,
        status="MATCH",
        recovered_path=str(tmp_path / "recovered_budget.txt"),
        recovered_size=327,
        recovered_sha256="812c8c38e44b0cf4a6501bf015b6e079c2b376b453f3b37874710a49598ce6b4",
        recovered_md5="88849b28ec60429788f4cffad9f71ee5",
        ground_truth_sha256="812c8c38e44b0cf4a6501bf015b6e079c2b376b453f3b37874710a49598ce6b4",
        investigative_notes="Cryptographic match confirmed.",
    )

    ev = TimelineEvent(
        timestamp=t_now,
        timestamp_type="SI_MODIFIED",
        timestamp_name="Content Modified",
        record_number=38,
        filename="BUDGET_DRAFT.txt",
        path="\\BUDGET_DRAFT.txt",
        allocation_status="Deleted",
        source_artifact="$MFT Record 38 ($STANDARD_INFORMATION)",
        forensic_explanation="Content was modified.",
        investigator_note="Correlates with file write.",
    )

    out_file = generate_case_report(
        case_record=case,
        target_record=target_rec,
        all_records=[target_rec],
        recovery_result=rec_res,
        timeline_events=[ev],
        output_dir=str(tmp_path),
    )

    assert Path(out_file).is_file()
    content = Path(out_file).read_text(encoding="utf-8")

    # Verify all 8 core report sections are present
    assert "1. Case Identification and Purpose" in content
    assert "2. Evidence Image Details and Integrity Verification" in content
    assert "3. Forensic Tools, Environment, and Specifications" in content
    assert "4. Target File Identification and Metadata Breakdown" in content
    assert "5. Chronological Timeline of Observed File System Events" in content
    assert "6. Recovery Attempt and Hash Verification" in content
    assert "7. Supported Conclusions (Evidence-Backed)" in content
    assert "8. Limitations, Caveats, and Known Unknowns" in content

    # Verify key evidence values appear
    assert "BUDGET_DRAFT.txt" in content
    assert "812c8c38e44b0cf4a6501bf015b6e079c2b376b453f3b37874710a49598ce6b4" in content
    assert "MATCH" in content
    assert "Attribution Unknown" in content
