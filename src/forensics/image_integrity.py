"""
Forensic Image Integrity Module.
Handles streaming cryptographic hashing, case integrity tracking,
and strict read-only evidence verification.
"""

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

from .models import CaseRecord

CHUNK_SIZE = 1024 * 1024  # 1 MB streaming chunks


def calculate_image_hashes(image_path: str, chunk_size: int = CHUNK_SIZE) -> Tuple[str, str, int]:
    """
    Computes SHA-256 and MD5 hashes of a disk image by streaming in chunks.
    Guarantees minimal memory usage for large evidence files.
    Returns (sha256_hex, md5_hex, file_size_bytes).
    """
    path = Path(image_path)
    if not path.is_file():
        raise FileNotFoundError(f"Evidence image not found: {image_path}")

    sha256_hasher = hashlib.sha256()
    md5_hasher = hashlib.md5()
    total_bytes = 0

    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256_hasher.update(chunk)
            md5_hasher.update(chunk)
            total_bytes += len(chunk)

    return sha256_hasher.hexdigest(), md5_hasher.hexdigest(), total_bytes


def verify_image_immutability(image_path: str, expected_sha256: str) -> bool:
    """Verifies that the disk image has not been altered since acquisition."""
    current_sha256, _, _ = calculate_image_hashes(image_path)
    return current_sha256.lower() == expected_sha256.lower()


def create_case_record(
    case_id: str,
    case_name: str,
    examiner_name: str,
    image_path: str,
    is_working_copy: bool = True,
    master_sha256: Optional[str] = None,
    partition_offset_bytes: int = 0,
    examiner_notes: str = "",
    output_dir: str = "outputs/cases",
) -> CaseRecord:
    """
    Creates and persists a forensic case record with image integrity hashes.
    Ensures clear distinction between untouched master evidence and working copy.
    """
    abs_path = os.path.abspath(image_path)
    sha256_hash, md5_hash, size_bytes = calculate_image_hashes(abs_path)

    now_iso = datetime.now(timezone.utc).isoformat()
    record = CaseRecord(
        case_id=case_id,
        case_name=case_name,
        examiner_name=examiner_name,
        created_at=now_iso,
        image_path=abs_path,
        image_size_bytes=size_bytes,
        image_sha256=sha256_hash,
        image_md5=md5_hash,
        is_working_copy=is_working_copy,
        master_sha256=master_sha256 or (sha256_hash if not is_working_copy else None),
        partition_offset_bytes=partition_offset_bytes,
        examiner_notes=examiner_notes,
    )

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    case_file = out_path / f"{case_id}.json"

    with open(case_file, "w", encoding="utf-8") as f:
        json.dump(record.to_dict(), f, indent=2)

    return record


def load_case_record(case_id_or_path: str) -> CaseRecord:
    """Loads an existing forensic case record from disk."""
    path = Path(case_id_or_path)
    if not path.exists():
        path = Path("outputs/cases") / f"{case_id_or_path}.json"
    
    if not path.is_file():
        raise FileNotFoundError(f"Case record not found: {case_id_or_path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return CaseRecord(
        case_id=data["case_id"],
        case_name=data["case_name"],
        examiner_name=data["examiner_name"],
        created_at=data["created_at"],
        image_path=data["image_path"],
        image_size_bytes=data["image_size_bytes"],
        image_sha256=data["image_sha256"],
        image_md5=data["image_md5"],
        is_working_copy=data["is_working_copy"],
        master_sha256=data.get("master_sha256"),
        partition_offset_bytes=data.get("partition_offset_bytes", 0),
        examiner_notes=data.get("examiner_notes", ""),
    )
