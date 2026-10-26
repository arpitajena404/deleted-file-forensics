"""
Unit tests for Cross-Check Importer (The Sleuth Kit bodyfile and Autopsy CSV).
"""

from src.forensics.cross_check_importer import parse_bodyfile, parse_autopsy_csv


def test_parse_bodyfile():
    records = parse_bodyfile("evidence/cross_check_bodyfile.txt")
    assert len(records) >= 4

    # Check deleted file in bodyfile
    del_records = [r for r in records if not r["in_use"]]
    assert len(del_records) >= 1
    target = del_records[0]
    assert "BUDGET_DRAFT.txt" in target["filename"]
    assert target["record_number"] == "38"
    assert target["file_size"] == 327


def test_parse_autopsy_csv():
    records = parse_autopsy_csv("evidence/cross_check_autopsy.csv")
    assert len(records) == 3

    # Check BUDGET_DRAFT.txt
    target = [r for r in records if "BUDGET_DRAFT.txt" in r["filename"]][0]
    assert target["in_use"] is False
    assert target["record_number"] == "38"
    assert target["file_size"] == 327
    assert target["sha256"] == "812c8c38e44b0cf4a6501bf015b6e079c2b376b453f3b37874710a49598ce6b4"
