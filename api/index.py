"""
Vercel Serverless Function entry point for Digital Crime Scene: Investigation of a Deleted File.
Exposes web dashboard, full HTML forensic case report, and JSON API endpoints.
"""

import os
import sys
import json
import shutil
from pathlib import Path
from http.server import BaseHTTPRequestHandler

# Setup paths
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

# Import forensic modules
from src.forensics.image_integrity import (
    calculate_image_hashes,
    create_case_record,
    load_case_record,
    verify_image_immutability,
)
from src.forensics.ntfs_parser import NTFSParser, detect_partition_offset
from src.forensics.recovery import attempt_recovery, load_ground_truth
from src.forensics.timeline import build_forensic_timeline
from src.forensics.reporter import generate_case_report
from src.forensics import __version__


def ensure_evidence_and_report():
    """Ensures test evidence image and forensic report exist in the environment."""
    # Check if working copy exists; if not, generate it in /tmp or local directory
    target_evidence_dir = BASE_DIR / "evidence"
    master_path = target_evidence_dir / "master_image.raw"
    working_copy_path = target_evidence_dir / "working_copy.raw"
    ground_truth_path = target_evidence_dir / "ground_truth.json"

    # If read-only filesystem (like Vercel serverless), fallback to /tmp
    if not working_copy_path.exists() or not ground_truth_path.exists():
        tmp_dir = Path("/tmp") if os.name != "nt" else BASE_DIR / ".tmp_evidence"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        master_path = tmp_dir / "master_image.raw"
        working_copy_path = tmp_dir / "working_copy.raw"
        ground_truth_path = tmp_dir / "ground_truth.json"

        if not working_copy_path.exists():
            from scripts.create_test_image import create_raw_image, create_ground_truth_file
            create_raw_image(str(master_path), is_partitioned=False)
            shutil.copyfile(str(master_path), str(working_copy_path))
            create_ground_truth_file(str(ground_truth_path))

    return str(working_copy_path), str(ground_truth_path)


def run_full_forensic_analysis():
    """Runs complete NTFS analysis and returns structured forensic results."""
    working_copy, ground_truth = ensure_evidence_and_report()
    offset, desc = detect_partition_offset(working_copy)
    out_case_dir = Path("/tmp/cases") if os.name != "nt" else BASE_DIR / "outputs" / "cases"

    case = create_case_record(
        case_id="CASE-2026-001",
        case_name="Investigation of a Deleted File",
        examiner_name="Student Forensic Examiner",
        image_path=working_copy,
        is_working_copy=True,
        partition_offset_bytes=offset,
        examiner_notes="Automated forensic investigation on NTFS disk image",
        output_dir=str(out_case_dir),
    )

    parser = NTFSParser(working_copy, partition_offset=offset)
    records = parser.scan_all_records()

    target_rec = None
    target_name = "budget_draft.txt"
    for r in records.values():
        if r.filename.lower() == target_name:
            target_rec = r
            break

    gt_data = None
    if os.path.exists(ground_truth):
        gt_full = load_ground_truth(ground_truth)
        gt_data = gt_full.get("target_file") if "target_file" in gt_full else gt_full

    out_recov_base = "/tmp/recovered" if os.name != "nt" else str(BASE_DIR / "outputs" / "recovered")
    recovery_result = None
    if target_rec:
        recovery_result = attempt_recovery(
            parser=parser,
            record=target_rec,
            case_id=case.case_id,
            ground_truth_record=gt_data,
            output_base_dir=out_recov_base,
        )

    all_recs = list(records.values())
    timeline_events = build_forensic_timeline(all_recs)

    out_rep_dir = Path("/tmp/reports") if os.name != "nt" else BASE_DIR / "outputs" / "reports"
    report_path = generate_case_report(
        case_record=case,
        target_record=target_rec,
        all_records=all_recs,
        recovery_result=recovery_result,
        timeline_events=timeline_events,
        output_dir=str(out_rep_dir),
    )

    return {
        "case": case,
        "partition_desc": desc,
        "records": records,
        "target_rec": target_rec,
        "recovery": recovery_result,
        "timeline": timeline_events,
        "report_path": report_path,
    }


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        url_path = self.path.split("?")[0].rstrip("/")
        if not url_path:
            url_path = "/"

        if url_path in ("/api/health", "/health"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "healthy", "service": "deleted-file-forensics", "version": __version__}).encode("utf-8"))
            return

        if url_path in ("/api/data", "/api/scan"):
            try:
                results = run_full_forensic_analysis()
                data = {
                    "case_id": results["case"].case_id,
                    "image_sha256": results["case"].image_sha256,
                    "target_file": "BUDGET_DRAFT.txt",
                    "recovery_status": results["recovery"].status if results["recovery"] else "UNKNOWN",
                    "recovered_sha256": results["recovery"].recovered_sha256 if results["recovery"] else "",
                    "original_sha256": results["recovery"].ground_truth_sha256 if results["recovery"] else "",
                    "records_count": len(results["records"]),
                    "timeline_events_count": len(results["timeline"]),
                    "records": [
                        {
                            "record_number": r.record_number,
                            "sequence_number": r.sequence_number,
                            "filename": r.filename,
                            "path": r.path,
                            "allocated": r.in_use,
                            "status": r.status_label,
                            "size": r.file_size,
                            "is_resident": r.is_resident,
                        }
                        for r in results["records"].values()
                    ],
                }
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))
            except Exception as e:
                import traceback
                traceback.print_exc()
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode("utf-8"))
            return

        # Serve full HTML report
        try:
            results = run_full_forensic_analysis()
            report_file = Path(results["report_path"])
            if report_file.exists():
                with open(report_file, "r", encoding="utf-8") as f:
                    html_content = f.read()

                # Add a top floating banner indicating Vercel Deployment & Interactive Links
                banner = f"""
                <div style="background: #0f172a; color: #38bdf8; padding: 12px 24px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #0284c7;">
                    <div>
                        <span style="font-weight: bold; font-size: 15px; color: #ffffff;">🔍 Digital Crime Scene: Investigation of a Deleted File</span>
                        <span style="margin-left: 10px; background: #166534; color: #dcfce7; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold;">Vercel Serverless Ready (v{__version__})</span>
                    </div>
                    <div>
                        <a href="/api/data" target="_blank" style="color: #38bdf8; text-decoration: none; font-weight: 600; margin-left: 16px; border: 1px solid #0284c7; padding: 4px 10px; border-radius: 4px;">📡 JSON API</a>
                        <a href="https://github.com" target="_blank" style="color: #cbd5e1; text-decoration: none; font-weight: 500; margin-left: 12px;">GitHub Repo</a>
                    </div>
                </div>
                """
                if "<body" in html_content:
                    html_content = html_content.replace("<body", "<body style='margin-top:0; padding-top:0;'", 1)
                    html_content = html_content.replace("<body>", f"<body>{banner}", 1)
                    if "<body>" not in html_content and "<body style='margin-top:0; padding-top:0;'>" in html_content:
                        html_content = html_content.replace("<body style='margin-top:0; padding-top:0;'>", f"<body style='margin-top:0; padding-top:0;'>{banner}", 1)

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(html_content.encode("utf-8"))
                return
        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            err_html = f"<h1>Forensic Analysis Error</h1><p>{str(e)}</p>"
            self.wfile.write(err_html.encode("utf-8"))


if __name__ == "__main__":
    from http.server import HTTPServer
    port = int(os.environ.get("PORT", 8080))
    server = HTTPServer(("0.0.0.0", port), handler)
    print(f"[*] Serving Digital Crime Scene Forensics on http://localhost:{port}")
    server.serve_forever()

