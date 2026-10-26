"""
Data models for NTFS forensic analysis, evidence tracking, timeline, and recovery.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Tuple, Dict, Any


@dataclass
class FileRecord:
    """Represents a parsed MFT entry or file record."""
    record_number: int
    sequence_number: int
    in_use: bool  # True = Active / Allocated; False = Deleted / Unallocated
    is_directory: bool
    filename: str
    path: str
    parent_record: int
    file_size: int
    allocated_size: int
    is_resident: bool = True
    resident_data: Optional[bytes] = None
    data_runs: List[Tuple[int, int]] = field(default_factory=list)  # (cluster_offset, cluster_count)
    
    # $STANDARD_INFORMATION Timestamps (UTC)
    si_created: Optional[datetime] = None
    si_modified: Optional[datetime] = None
    si_mft_modified: Optional[datetime] = None
    si_accessed: Optional[datetime] = None
    
    # $FILE_NAME Timestamps (UTC)
    fn_created: Optional[datetime] = None
    fn_modified: Optional[datetime] = None
    fn_mft_modified: Optional[datetime] = None
    fn_accessed: Optional[datetime] = None
    
    dos_flags: int = 0
    source_artifact: str = ""
    raw_attributes: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def status_label(self) -> str:
        return "Allocated" if self.in_use else "Deleted / Unallocated"

    @property
    def hex_preview(self) -> str:
        if not self.resident_data:
            return "No resident data in MFT record"
        preview_bytes = self.resident_data[:256]
        hex_lines = []
        for i in range(0, len(preview_bytes), 16):
            chunk = preview_bytes[i:i+16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            hex_lines.append(f"{i:04X}  {hex_part:<48}  |{ascii_part}|")
        return "\n".join(hex_lines)


@dataclass
class CaseRecord:
    """Record of an active forensic investigation case and image integrity."""
    case_id: str
    case_name: str
    examiner_name: str
    created_at: str
    image_path: str
    image_size_bytes: int
    image_sha256: str
    image_md5: str
    is_working_copy: bool
    master_sha256: Optional[str] = None
    partition_offset_bytes: int = 0
    examiner_notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "case_name": self.case_name,
            "examiner_name": self.examiner_name,
            "created_at": self.created_at,
            "image_path": self.image_path,
            "image_size_bytes": self.image_size_bytes,
            "image_sha256": self.image_sha256,
            "image_md5": self.image_md5,
            "is_working_copy": self.is_working_copy,
            "master_sha256": self.master_sha256,
            "partition_offset_bytes": self.partition_offset_bytes,
            "examiner_notes": self.examiner_notes,
        }


@dataclass
class RecoveryResult:
    """Outcome of attempting to recover a deleted file's content."""
    target_filename: str
    record_number: int
    status: str  # "MATCH", "MISMATCH", "NOT_AVAILABLE", "ERROR"
    recovered_path: Optional[str]
    recovered_size: int
    recovered_sha256: Optional[str]
    recovered_md5: Optional[str]
    ground_truth_sha256: Optional[str]
    investigative_notes: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_filename": self.target_filename,
            "record_number": self.record_number,
            "status": self.status,
            "recovered_path": self.recovered_path,
            "recovered_size": self.recovered_size,
            "recovered_sha256": self.recovered_sha256,
            "recovered_md5": self.recovered_md5,
            "ground_truth_sha256": self.ground_truth_sha256,
            "investigative_notes": self.investigative_notes,
        }


@dataclass
class TimelineEvent:
    """An atomic forensic event with timestamp, source artifact, and interpretation."""
    timestamp: datetime
    timestamp_type: str  # e.g., "SI_CREATED", "SI_MODIFIED", "FN_MODIFIED"
    timestamp_name: str  # Human-readable title
    record_number: int
    filename: str
    path: str
    allocation_status: str  # "Allocated" or "Deleted"
    source_artifact: str
    forensic_explanation: str
    investigator_note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp_iso": self.timestamp.isoformat() if self.timestamp else "unknown",
            "timestamp_type": self.timestamp_type,
            "timestamp_name": self.timestamp_name,
            "record_number": self.record_number,
            "filename": self.filename,
            "path": self.path,
            "allocation_status": self.allocation_status,
            "source_artifact": self.source_artifact,
            "forensic_explanation": self.forensic_explanation,
            "investigator_note": self.investigator_note,
        }
