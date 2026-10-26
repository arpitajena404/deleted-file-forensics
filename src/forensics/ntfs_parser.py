"""
Real NTFS File System Analysis Module.
Directly parses NTFS Volume Boot Record (VBR), Master Boot Record (MBR),
GPT partition tables, and Master File Table ($MFT) records.
Extracts active files, unallocated/deleted records, timestamps, and data streams.
"""

import datetime
import os
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from .models import FileRecord

FILETIME_EPOCH_DIFF = 11644473600  # Seconds between 1601-01-01 and 1970-01-01


def filetime_to_datetime(filetime: int) -> Optional[datetime.datetime]:
    """
    Converts a 64-bit Windows FILETIME (100-nanosecond intervals since Jan 1, 1601 UTC)
    to a Python datetime object in UTC.
    Returns None if timestamp is zero or invalid.
    """
    if filetime <= 0:
        return None
    try:
        seconds = (filetime / 10000000) - FILETIME_EPOCH_DIFF
        if seconds < -62135596800 or seconds > 253402300799:
            return None
        return datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def datetime_to_filetime(dt: datetime.datetime) -> int:
    """Converts a UTC datetime to a 64-bit Windows FILETIME."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    seconds = dt.timestamp()
    return int((seconds + FILETIME_EPOCH_DIFF) * 10000000)


def detect_partition_offset(image_path: str) -> Tuple[int, str]:
    """
    Detects the starting byte offset of the NTFS file system in a raw disk image.
    Supports:
    1. Direct raw volume (VBR at offset 0)
    2. MBR partitioned image (scans partition table entries at sector 0)
    3. GPT partitioned image (scans GPT header at sector 1)
    Returns (offset_bytes, description).
    """
    with open(image_path, "rb") as f:
        # Check offset 0 for direct NTFS VBR
        f.seek(0)
        sector0 = f.read(512)
        if len(sector0) == 512 and sector0[3:11] == b"NTFS    ":
            return 0, "Direct Raw NTFS Volume (Offset 0x0)"

        # Check MBR Partition Table
        if len(sector0) == 512 and sector0[510:512] == b"\x55\xAA":
            for i in range(4):
                entry_offset = 446 + (i * 16)
                p_type = sector0[entry_offset + 4]
                start_lba = struct.unpack("<I", sector0[entry_offset + 8 : entry_offset + 12])[0]
                if p_type in (0x07, 0x17) and start_lba > 0:
                    cand_offset = start_lba * 512
                    f.seek(cand_offset)
                    cand_sector = f.read(512)
                    if len(cand_sector) == 512 and cand_sector[3:11] == b"NTFS    ":
                        return cand_offset, f"MBR Partition {i+1} (Type 0x{p_type:02X}, LBA {start_lba}, Offset {cand_offset} bytes)"

        # Check GPT Partition Table (Sector 1)
        f.seek(512)
        sector1 = f.read(512)
        if len(sector1) == 512 and sector1[:8] == b"EFI PART":
            part_entry_lba = struct.unpack("<Q", sector1[72:80])[0]
            num_parts = struct.unpack("<I", sector1[80:84])[0]
            part_size = struct.unpack("<I", sector1[84:88])[0]
            f.seek(part_entry_lba * 512)
            part_data = f.read(min(num_parts * part_size, 16384))
            for i in range(min(num_parts, 16)):
                p_off = i * part_size
                if p_off + 40 > len(part_data):
                    break
                first_lba = struct.unpack("<Q", part_data[p_off + 32 : p_off + 40])[0]
                if first_lba > 0:
                    cand_offset = first_lba * 512
                    f.seek(cand_offset)
                    cand_sector = f.read(512)
                    if len(cand_sector) == 512 and cand_sector[3:11] == b"NTFS    ":
                        return cand_offset, f"GPT Partition {i+1} (LBA {first_lba}, Offset {cand_offset} bytes)"

    # Fallback to 0 if not found
    return 0, "Default (Offset 0 bytes)"


class NTFSParser:
    """
    Forensic NTFS Parser.
    Reads Volume Boot Record, resolves cluster geometry, parses $MFT records,
    reconstructs directory hierarchies, and enumerates allocated and deleted files.
    """

    def __init__(self, image_path: str, partition_offset: int = 0):
        self.image_path = os.path.abspath(image_path)
        self.partition_offset = partition_offset
        self.file_handle = open(self.image_path, "rb")

        # Filesystem geometry
        self.bytes_per_sector = 512
        self.sectors_per_cluster = 8
        self.cluster_size = 4096
        self.total_sectors = 0
        self.mft_start_cluster = 0
        self.mft_record_size = 1024
        self.mft_start_byte = 0
        self.volume_serial = ""

        # Parsed state
        self.records: Dict[int, FileRecord] = {}
        self.is_parsed = False

        self._read_vbr()

    def close(self):
        if self.file_handle and not self.file_handle.closed:
            self.file_handle.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _read_vbr(self):
        """Parses the NTFS Volume Boot Record (VBR)."""
        self.file_handle.seek(self.partition_offset)
        vbr_bytes = self.file_handle.read(512)
        if len(vbr_bytes) < 512:
            raise ValueError(f"Unable to read 512-byte VBR at offset {self.partition_offset}")

        oem_id = vbr_bytes[3:11]
        if oem_id != b"NTFS    ":
            raise ValueError(f"Invalid NTFS signature at offset {self.partition_offset}: {oem_id!r} (expected b'NTFS    ')")

        self.bytes_per_sector = struct.unpack("<H", vbr_bytes[11:13])[0]
        self.sectors_per_cluster = vbr_bytes[13]
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster
        self.total_sectors = struct.unpack("<Q", vbr_bytes[40:48])[0]
        self.mft_start_cluster = struct.unpack("<Q", vbr_bytes[48:56])[0]
        self.mft_start_byte = self.partition_offset + (self.mft_start_cluster * self.cluster_size)

        # Clusters per MFT record: signed 8-bit integer
        raw_mft_size = struct.unpack("<b", vbr_bytes[64:65])[0]
        if raw_mft_size < 0:
            self.mft_record_size = 1 << (-raw_mft_size)  # e.g. -10 -> 2^10 = 1024
        else:
            self.mft_record_size = raw_mft_size * self.cluster_size

        vol_sn = struct.unpack("<Q", vbr_bytes[72:80])[0]
        self.volume_serial = f"{vol_sn:016X}"

    def apply_fixup_array(self, record_bytes: bytearray) -> bool:
        """
        Applies the multi-sector transfer safety fixup array to an MFT record.
        Restores the original 2 bytes at the end of each 512-byte sector.
        """
        if len(record_bytes) < 48:
            return False

        fixup_offset = struct.unpack("<H", record_bytes[4:6])[0]
        fixup_count = struct.unpack("<H", record_bytes[6:8])[0]

        if fixup_offset + (fixup_count * 2) > len(record_bytes):
            return False

        expected_marker = record_bytes[fixup_offset : fixup_offset + 2]
        num_sectors = fixup_count - 1

        for i in range(num_sectors):
            sector_end = (i + 1) * self.bytes_per_sector - 2
            if sector_end + 2 > len(record_bytes):
                break
            # Overwrite sector end with original bytes stored in fixup array
            orig_bytes = record_bytes[fixup_offset + (i + 1) * 2 : fixup_offset + (i + 2) * 2]
            record_bytes[sector_end : sector_end + 2] = orig_bytes

        return True

    def parse_data_runs(self, runlist_bytes: bytes) -> List[Tuple[int, int]]:
        """
        Parses NTFS non-resident data runlist.
        Returns list of (cluster_offset, cluster_count).
        """
        runs = []
        idx = 0
        prev_cluster = 0

        while idx < len(runlist_bytes):
            header = runlist_bytes[idx]
            if header == 0:
                break
            idx += 1

            len_size = header & 0x0F
            offset_size = (header >> 4) & 0x0F

            if idx + len_size + offset_size > len(runlist_bytes):
                break

            # Read cluster length (unsigned)
            length_bytes = runlist_bytes[idx : idx + len_size]
            cluster_count = int.from_bytes(length_bytes, byteorder="little", signed=False)
            idx += len_size

            # Read cluster offset delta (signed)
            if offset_size > 0:
                offset_bytes = runlist_bytes[idx : idx + offset_size]
                cluster_delta = int.from_bytes(offset_bytes, byteorder="little", signed=True)
                idx += offset_size
                current_cluster = prev_cluster + cluster_delta
                prev_cluster = current_cluster
            else:
                # Sparse cluster
                current_cluster = 0

            runs.append((current_cluster, cluster_count))

        return runs

    def parse_mft_record(self, raw_record: bytes, record_idx: int) -> Optional[FileRecord]:
        """Parses a single 1024-byte MFT record into a FileRecord object."""
        if len(raw_record) < self.mft_record_size:
            return None

        magic = raw_record[:4]
        if magic not in (b"FILE", b"BAAD"):
            return None

        rec = bytearray(raw_record)
        self.apply_fixup_array(rec)

        seq_num = struct.unpack("<H", rec[16:18])[0]
        flags = struct.unpack("<H", rec[22:24])[0]
        in_use = bool(flags & 0x0001)
        is_directory = bool(flags & 0x0002)
        base_record = struct.unpack("<Q", rec[32:40])[0] & 0x0000FFFFFFFFFFFF
        first_attr_offset = struct.unpack("<H", rec[20:22])[0]

        curr = first_attr_offset
        filename = ""
        parent_record = 0
        file_size = 0
        allocated_size = 0
        is_resident = True
        resident_data = None
        data_runs: List[Tuple[int, int]] = []
        dos_flags = 0

        si_created = None
        si_modified = None
        si_mft_modified = None
        si_accessed = None

        fn_created = None
        fn_modified = None
        fn_mft_modified = None
        fn_accessed = None

        raw_attrs: List[Dict[str, Any]] = []

        while curr + 8 <= len(rec):
            attr_type = struct.unpack("<I", rec[curr : curr + 4])[0]
            if attr_type == 0xFFFFFFFF or attr_type == 0:
                break

            attr_len = struct.unpack("<I", rec[curr + 4 : curr + 8])[0]
            if attr_len < 16 or curr + attr_len > len(rec):
                break

            non_resident = rec[curr + 8] != 0
            name_len = rec[curr + 9]
            name_offset = struct.unpack("<H", rec[curr + 10 : curr + 12])[0]
            attr_flags = struct.unpack("<H", rec[curr + 12 : curr + 14])[0]
            attr_id = struct.unpack("<H", rec[curr + 14 : curr + 16])[0]

            attr_name = ""
            if name_len > 0 and curr + name_offset + (name_len * 2) <= curr + attr_len:
                attr_name = rec[curr + name_offset : curr + name_offset + (name_len * 2)].decode("utf-16le", errors="replace")

            raw_attrs.append({
                "type": f"0x{attr_type:02X}",
                "name": attr_name,
                "non_resident": non_resident,
                "length": attr_len,
            })

            # $STANDARD_INFORMATION (0x10)
            if attr_type == 0x10 and not non_resident:
                val_len = struct.unpack("<I", rec[curr + 16 : curr + 20])[0]
                val_off = struct.unpack("<H", rec[curr + 20 : curr + 22])[0]
                data_start = curr + val_off
                if data_start + 48 <= curr + attr_len:
                    c_time = struct.unpack("<Q", rec[data_start : data_start + 8])[0]
                    m_time = struct.unpack("<Q", rec[data_start + 8 : data_start + 16])[0]
                    mft_time = struct.unpack("<Q", rec[data_start + 16 : data_start + 24])[0]
                    a_time = struct.unpack("<Q", rec[data_start + 24 : data_start + 32])[0]
                    dos_flags = struct.unpack("<I", rec[data_start + 32 : data_start + 36])[0]

                    si_created = filetime_to_datetime(c_time)
                    si_modified = filetime_to_datetime(m_time)
                    si_mft_modified = filetime_to_datetime(mft_time)
                    si_accessed = filetime_to_datetime(a_time)

            # $FILE_NAME (0x30)
            elif attr_type == 0x30 and not non_resident:
                val_len = struct.unpack("<I", rec[curr + 16 : curr + 20])[0]
                val_off = struct.unpack("<H", rec[curr + 20 : curr + 22])[0]
                data_start = curr + val_off
                if data_start + 66 <= curr + attr_len:
                    parent_ref = struct.unpack("<Q", rec[data_start : data_start + 8])[0] & 0x0000FFFFFFFFFFFF
                    c_time = struct.unpack("<Q", rec[data_start + 8 : data_start + 16])[0]
                    m_time = struct.unpack("<Q", rec[data_start + 16 : data_start + 24])[0]
                    mft_time = struct.unpack("<Q", rec[data_start + 24 : data_start + 32])[0]
                    a_time = struct.unpack("<Q", rec[data_start + 32 : data_start + 40])[0]
                    fn_alloc = struct.unpack("<Q", rec[data_start + 40 : data_start + 48])[0]
                    fn_real = struct.unpack("<Q", rec[data_start + 48 : data_start + 56])[0]
                    n_len = rec[data_start + 64]
                    n_space = rec[data_start + 65]

                    if data_start + 66 + (n_len * 2) <= curr + attr_len:
                        parsed_name = rec[data_start + 66 : data_start + 66 + (n_len * 2)].decode("utf-16le", errors="replace")
                        # Favor Win32 or long filenames over DOS short names
                        if not filename or n_space in (1, 3) or len(parsed_name) > len(filename):
                            filename = parsed_name
                            parent_record = parent_ref
                            if file_size == 0:
                                file_size = fn_real
                                allocated_size = fn_alloc
                            fn_created = filetime_to_datetime(c_time)
                            fn_modified = filetime_to_datetime(m_time)
                            fn_mft_modified = filetime_to_datetime(mft_time)
                            fn_accessed = filetime_to_datetime(a_time)

            # $DATA (0x80)
            elif attr_type == 0x80 and attr_name == "":
                if not non_resident:
                    is_resident = True
                    val_len = struct.unpack("<I", rec[curr + 16 : curr + 20])[0]
                    val_off = struct.unpack("<H", rec[curr + 20 : curr + 22])[0]
                    if curr + val_off + val_len <= curr + attr_len:
                        resident_data = bytes(rec[curr + val_off : curr + val_off + val_len])
                        file_size = val_len
                        allocated_size = val_len
                else:
                    is_resident = False
                    allocated_size = struct.unpack("<Q", rec[curr + 40 : curr + 48])[0]
                    file_size = struct.unpack("<Q", rec[curr + 48 : curr + 56])[0]
                    run_off = struct.unpack("<H", rec[curr + 32 : curr + 34])[0]
                    if curr + run_off < curr + attr_len:
                        data_runs = self.parse_data_runs(bytes(rec[curr + run_off : curr + attr_len]))

            curr += attr_len

        # If no filename was recovered from $FILE_NAME, provide placeholder
        if not filename:
            if record_idx == 0:
                filename = "$MFT"
            elif record_idx == 3:
                filename = "$Volume"
            elif record_idx == 5:
                filename = "."
            else:
                filename = f"RECORD_{record_idx}"

        source_art = f"$MFT Record {record_idx} (Flags: 0x{flags:04X}, Seq: {seq_num})"

        return FileRecord(
            record_number=record_idx,
            sequence_number=seq_num,
            in_use=in_use,
            is_directory=is_directory,
            filename=filename,
            path="",  # Reconstructed after indexing
            parent_record=parent_record,
            file_size=file_size,
            allocated_size=allocated_size,
            is_resident=is_resident,
            resident_data=resident_data,
            data_runs=data_runs,
            si_created=si_created,
            si_modified=si_modified,
            si_mft_modified=si_mft_modified,
            si_accessed=si_accessed,
            fn_created=fn_created,
            fn_modified=fn_modified,
            fn_mft_modified=fn_mft_modified,
            fn_accessed=fn_accessed,
            dos_flags=dos_flags,
            source_artifact=source_art,
            raw_attributes=raw_attrs,
        )

    def scan_all_records(self, max_records: int = 4096) -> Dict[int, FileRecord]:
        """
        Scans all records in the $MFT.
        First parses Record 0 ($MFT), then reads sequential records up to max_records
        or until empty/invalid table bounds.
        """
        self.records.clear()

        # Seek to MFT start
        self.file_handle.seek(self.mft_start_byte)

        # Parse Record 0 ($MFT)
        rec0_data = self.file_handle.read(self.mft_record_size)
        if len(rec0_data) == self.mft_record_size:
            rec0 = self.parse_mft_record(rec0_data, 0)
            if rec0:
                self.records[0] = rec0

        # Scan sequential records
        for i in range(1, max_records):
            record_pos = self.mft_start_byte + (i * self.mft_record_size)
            self.file_handle.seek(record_pos)
            rec_data = self.file_handle.read(self.mft_record_size)
            if len(rec_data) < self.mft_record_size:
                break
            
            # Check for empty padding
            if rec_data[:4] not in (b"FILE", b"BAAD"):
                # If we encounter multiple empty records in a row past record 64, stop
                if i > 64 and all(b == 0 for b in rec_data[:16]):
                    # Check next record to ensure not just one blank slot
                    next_pos = record_pos + self.mft_record_size
                    self.file_handle.seek(next_pos)
                    next_head = self.file_handle.read(4)
                    if next_head not in (b"FILE", b"BAAD"):
                        break
                continue

            parsed = self.parse_mft_record(rec_data, i)
            if parsed:
                self.records[i] = parsed

        # Resolve paths
        self._resolve_paths()
        self.is_parsed = True
        return self.records

    def _resolve_paths(self):
        """Constructs full hierarchical paths by resolving parent MFT records."""
        for rec_num, rec in self.records.items():
            if rec.record_number == 5:
                rec.path = "\\"
                continue
            
            # Follow parent chain up to root (Record 5)
            curr_parent = rec.parent_record
            path_parts = [rec.filename]
            visited = {rec.record_number}

            while curr_parent in self.records and curr_parent not in visited:
                visited.add(curr_parent)
                parent_rec = self.records[curr_parent]
                if curr_parent == 5:
                    break
                path_parts.append(parent_rec.filename)
                curr_parent = parent_rec.parent_record

            rec.path = "\\" + "\\".join(reversed(path_parts))

    def search_files(
        self,
        query: str = "",
        status_filter: str = "ALL",  # "ALL", "ALLOCATED", "DELETED"
        extension_filter: str = "",
    ) -> List[FileRecord]:
        """Filters and searches parsed file records."""
        if not self.is_parsed:
            self.scan_all_records()

        results = []
        q = query.lower()
        ext = extension_filter.lower().lstrip(".")

        for rec in self.records.values():
            # Allocation filter
            if status_filter == "ALLOCATED" and not rec.in_use:
                continue
            if status_filter == "DELETED" and rec.in_use:
                continue

            # Extension filter
            if ext:
                if not rec.filename.lower().endswith(f".{ext}"):
                    continue

            # Query filter
            if q:
                if q not in rec.filename.lower() and q not in rec.path.lower() and q not in str(rec.record_number):
                    continue

            results.append(rec)

        return results

    def extract_non_resident_data(self, record: FileRecord) -> bytes:
        """
        Reads non-resident cluster runs directly from the evidence image.
        Returns file content up to record.file_size bytes.
        """
        if not record.data_runs:
            return b""

        extracted = bytearray()
        for cluster_offset, cluster_count in record.data_runs:
            if cluster_offset == 0:
                # Sparse run: fill with zeros
                extracted.extend(b"\x00" * (cluster_count * self.cluster_size))
            else:
                byte_offset = self.partition_offset + (cluster_offset * self.cluster_size)
                self.file_handle.seek(byte_offset)
                chunk = self.file_handle.read(cluster_count * self.cluster_size)
                extracted.extend(chunk)

        return bytes(extracted[: record.file_size])
