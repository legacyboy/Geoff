"""
Tests for FindingsWriter in geoff_integrated.py.

Covers: append, idempotency check, disk write, in-memory cap, thread safety.
"""

import json
import threading
import pytest
from pathlib import Path


def _get_writer_class():
    import geoff_integrated
    return geoff_integrated.FindingsWriter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_record(step_key, status="completed", data="x"):
    return {"step_key": step_key, "status": status, "data": data}


# ---------------------------------------------------------------------------
# Basic append and retrieval
# ---------------------------------------------------------------------------

def test_append_single_record(tmp_path):
    fw = _get_writer_class()(tmp_path / "findings.jsonl")
    rec = _make_record("step1")
    fw.append(rec)
    assert fw.all_records() == [rec]


def test_append_multiple_records(tmp_path):
    fw = _get_writer_class()(tmp_path / "findings.jsonl")
    records = [_make_record(f"step{i}") for i in range(5)]
    for r in records:
        fw.append(r)
    assert fw.all_records() == records


# ---------------------------------------------------------------------------
# Idempotency: is_completed
# ---------------------------------------------------------------------------

def test_is_completed_true_after_append(tmp_path):
    fw = _get_writer_class()(tmp_path / "findings.jsonl")
    fw.append(_make_record("vol_pslist", status="completed"))
    assert fw.is_completed("vol_pslist") is True


def test_is_completed_false_for_unknown_key(tmp_path):
    fw = _get_writer_class()(tmp_path / "findings.jsonl")
    assert fw.is_completed("does_not_exist") is False


def test_is_completed_false_for_non_completed_status(tmp_path):
    fw = _get_writer_class()(tmp_path / "findings.jsonl")
    fw.append(_make_record("step1", status="failed"))
    assert fw.is_completed("step1") is False


def test_is_completed_updated_by_latest_append(tmp_path):
    fw = _get_writer_class()(tmp_path / "findings.jsonl")
    fw.append(_make_record("step1", status="failed"))
    fw.append(_make_record("step1", status="completed"))
    assert fw.is_completed("step1") is True


# ---------------------------------------------------------------------------
# Disk writes
# ---------------------------------------------------------------------------

def test_records_written_to_disk(tmp_path):
    path = tmp_path / "findings.jsonl"
    fw = _get_writer_class()(path)
    fw.append(_make_record("step1"))
    fw.append(_make_record("step2"))

    lines = path.read_text().splitlines()
    assert len(lines) == 2
    parsed = [json.loads(l) for l in lines]
    assert parsed[0]["step_key"] == "step1"
    assert parsed[1]["step_key"] == "step2"


def test_disk_write_appends_not_overwrites(tmp_path):
    path = tmp_path / "findings.jsonl"
    fw = _get_writer_class()(path)
    fw.append(_make_record("step1"))

    # Create a second writer on the same path
    fw2 = _get_writer_class()(path)
    fw2.append(_make_record("step2"))

    lines = path.read_text().splitlines()
    assert len(lines) == 2


def test_parent_dir_created_if_missing(tmp_path):
    nested = tmp_path / "a" / "b" / "c" / "findings.jsonl"
    fw = _get_writer_class()(nested)
    fw.append(_make_record("step1"))
    assert nested.exists()


# ---------------------------------------------------------------------------
# In-memory cap
# ---------------------------------------------------------------------------

def test_in_memory_cap_limits_records(tmp_path, capsys):
    fw = _get_writer_class()(tmp_path / "findings.jsonl", max_in_memory=3)
    for i in range(6):
        fw.append(_make_record(f"step{i}"))

    # all_records() falls back to disk when cap is hit — no findings lost
    assert len(fw.all_records()) == 6
    # Internal _records list is capped at max_in_memory
    assert len(fw._records) == 3
    # All 6 written to disk
    lines = (tmp_path / "findings.jsonl").read_text().splitlines()
    assert len(lines) == 6


def test_in_memory_cap_prints_warning(tmp_path, capsys):
    fw = _get_writer_class()(tmp_path / "findings.jsonl", max_in_memory=2)
    for i in range(4):
        fw.append(_make_record(f"step{i}"))
    captured = capsys.readouterr()
    assert "cap" in captured.out.lower() or "in-memory" in captured.out.lower()


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------

def test_concurrent_appends_all_written(tmp_path):
    path = tmp_path / "findings.jsonl"
    fw = _get_writer_class()(path, max_in_memory=1000)
    errors = []

    def worker(n):
        try:
            for i in range(20):
                fw.append(_make_record(f"thread{n}_step{i}"))
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    lines = path.read_text().splitlines()
    assert len(lines) == 100  # 5 threads × 20 records
