"""
Recovery and Comparison Module.
Safely exports deleted file content to an isolated output directory,
computes cryptographic hashes, and compares against ground-truth baselines.
"""

import hashlib
import json
import os
from pathlib import Path
from typing import Optional, Dict, Any

from .models import FileRecord, RecoveryResult
from .ntfs_parser import NTFSParser


def load_ground_truth(ground_truth_path: str) -> Dict[str, Any]:
    """Loads a ground-truth JSON record containing baseline file hashes and metadata."""
    path = Path(ground_truth_path)
    if not path.is_file():
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def attempt_recovery(
    parser: NTFSParser,
    record: FileRecord,
    case_id: str,
    output_base_dir: str = "outputs/recovered",
    ground_truth_record: Optional[Dict[str, Any]] = None,
) -> RecoveryResult:
    """
    Attempts to extract content for a deleted file record.
    Writes recovered bytes strictly outside the evidence image into an isolated directory.
    Validates output using SHA-256 comparison against ground truth.
    """
    out_dir = Path(output_base_dir) / case_id
    out_dir.mkdir(parents=True, exist_ok=True)

    sanitized_filename = os.path.basename(record.filename).replace(" ", "_")
    if not sanitized_filename:
        sanitized_filename = f"recovered_record_{record.record_number}.bin"
    output_filepath = out_dir / sanitized_filename

    recovered_bytes = b""
    recovery_method = ""

    # Attempt 1: Resident data inside MFT record
    if record.resident_data is not None and len(record.resident_data) > 0:
        recovered_bytes = record.resident_data
        recovery_method = f"Resident $DATA attribute directly extracted from $MFT Record {record.record_number} ({len(recovered_bytes)} bytes)"
    
    # Attempt 2: Non-resident data runs
    elif record.data_runs:
        try:
            recovered_bytes = parser.extract_non_resident_data(record)
            recovery_method = f"Non-resident cluster extraction via runlist {record.data_runs} ({len(recovered_bytes)} bytes)"
        except Exception as e:
            return RecoveryResult(
                target_filename=record.filename,
                record_number=record.record_number,
                status="ERROR",
                recovered_path=None,
                recovered_size=0,
                recovered_sha256=None,
                recovered_md5=None,
                ground_truth_sha256=None,
                investigative_notes=f"Error reading non-resident clusters: {str(e)}",
            )
    else:
        # No data streams survived or record has zero length
        notes = (
            f"No resident or non-resident $DATA stream present in MFT Record {record.record_number}. "
            "Data content is not recoverable in this test; only metadata attributes survived."
        )
        return RecoveryResult(
            target_filename=record.filename,
            record_number=record.record_number,
            status="NOT_AVAILABLE",
            recovered_path=None,
            recovered_size=0,
            recovered_sha256=None,
            recovered_md5=None,
            ground_truth_sha256=ground_truth_record.get("sha256") if ground_truth_record else None,
            investigative_notes=notes,
        )

    # Write recovered file to isolated destination
    with open(output_filepath, "wb") as f:
        f.write(recovered_bytes)

    # Calculate cryptographic hashes
    rec_sha256 = hashlib.sha256(recovered_bytes).hexdigest().lower()
    rec_md5 = hashlib.md5(recovered_bytes).hexdigest().lower()

    # Compare with ground truth
    expected_sha256 = None
    status = "NOT_AVAILABLE"

    if ground_truth_record:
        expected_sha256 = ground_truth_record.get("sha256", "").lower()
        if expected_sha256:
            if rec_sha256 == expected_sha256:
                status = "MATCH"
                notes = (
                    f"Cryptographic MATCH verified. Recovered SHA-256 matches staged baseline exactly. "
                    f"Recovery source: {recovery_method}."
                )
            else:
                status = "MISMATCH"
                notes = (
                    f"Cryptographic MISMATCH. Recovered SHA-256 ({rec_sha256}) differs from ground truth ({expected_sha256}). "
                    "Cluster slack or partial overwrite may have corrupted content."
                )
        else:
            notes = f"Content extracted successfully ({len(recovered_bytes)} bytes). No ground-truth hash supplied for comparison."
    else:
        notes = f"Content extracted successfully ({len(recovered_bytes)} bytes). No ground-truth record provided."

    return RecoveryResult(
        target_filename=record.filename,
        record_number=record.record_number,
        status=status,
        recovered_path=str(output_filepath),
        recovered_size=len(recovered_bytes),
        recovered_sha256=rec_sha256,
        recovered_md5=rec_md5,
        ground_truth_sha256=expected_sha256,
        investigative_notes=notes,
    )
