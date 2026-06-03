#!/usr/bin/env python3
"""Recover missing timelines for existing Find Evil cases by re-running
SuperTimeline.build() with existing findings, skipping broken plaso."""

import sys, os, json, logging
from pathlib import Path

# Ensure Geoff src is on path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
log = logging.getLogger('recover_timelines')

# Find case directories
CASE_BASE = Path("/mnt/evidence-storage-2")

def load_findings(case_dir):
    path = case_dir / "findings.jsonl"
    if not path.exists():
        log.warning(f"No findings.jsonl in {case_dir}")
        return []
    findings = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    log.info(f"  Loaded {len(findings)} findings")
    return findings

def load_device_map(case_dir):
    path = case_dir / "device_map.json"
    if path.exists():
        with open(path) as f:
            return json.load(f)
    # Derive from findings
    log.info("  No device_map.json found — deriving from findings")
    dm = {}
    for f in load_findings(case_dir):
        dev = f.get("device_id") or f.get("device", "")
        if dev:
            dm[dev] = dm.get(dev, {"id": dev, "count": 0})
            dm[dev]["count"] = dm[dev].get("count", 0) + 1
    return dm

def needs_recovery(case_dir):
    """Check if this case needs timeline recovery."""
    tl_file = case_dir / "timeline" / "super_timeline.jsonl"
    if tl_file.exists():
        size = tl_file.stat().st_size
        if size > 50:  # has real data
            return False
    return True

def rebuild_timeline(case_dir, dry_run=False):
    """Rebuild timeline for a single case."""
    log.info(f"Processing {case_dir.name}")
    
    case_work_dir = case_dir
    findings = load_findings(case_work_dir)
    device_map = load_device_map(case_work_dir)
    
    if not findings:
        log.warning(f"  No findings — skipping")
        return False
    
    if dry_run:
        log.info(f"  [DRY RUN] Would rebuild with {len(findings)} findings, {len(device_map)} devices")
        return True
    
    # Patch: skip plaso extraction entirely since plaso files are broken
    from super_timeline import SuperTimeline
    
    original_extract = SuperTimeline._extract_plaso_events
    def _noop_plaso(*args, **kwargs):
        log.info("  [patched] Skipping Plaso timeline extraction (files are broken/empty)")
        return []
    SuperTimeline._extract_plaso_events = _noop_plaso
    
    st = SuperTimeline()
    # We need a plaso_specialist object — import a minimal one
    from sift_specialists_extended import PLASO_Specialist
    plaso_spec = PLASO_Specialist()
    
    try:
        tl_path, tl_events = st.build(
            device_map=device_map,
            findings=findings,
            case_work_dir=case_work_dir,
            plaso_specialist=plaso_spec,
            job_id=f"recovery-{case_dir.name[:20]}",
            fe_log_func=lambda jid, msg: log.info(f"  [{jid}] {msg}")
        )
        log.info(f"  Rebuilt timeline: {len(tl_events)} events, saved to {tl_path}")
        
        # Update the report JSON with timeline data
        report_path = case_work_dir / "reports" / "find_evil_report.json"
        if report_path.exists():
            try:
                with open(report_path) as f:
                    report = json.load(f)
                # Add timeline (capped to 10000 events in-memory)
                report["timeline"] = tl_events[:10000]
                with open(report_path, 'w') as f:
                    json.dump(report, f, indent=2, default=str)
                log.info(f"  Updated report JSON with {min(len(tl_events), 10000)} timeline events")
            except Exception as e:
                log.error(f"  Failed to update report JSON: {e}")
        
        return True
    except Exception as e:
        log.error(f"  Build failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Restore original method
        SuperTimeline._extract_plaso_events = original_extract


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Recover missing timelines for existing Geoff Find Evil cases")
    parser.add_argument('--dry-run', action='store_true', help="Scan and report without making changes")
    parser.add_argument('--case', type=str, help="Specific case directory name to recover (optional)")
    args = parser.parse_args()
    
    if args.case:
        case_dir = CASE_BASE / args.case
        if not case_dir.exists():
            log.error(f"Case directory not found: {case_dir}")
            sys.exit(1)
        dirs = [case_dir]
    else:
        dirs = sorted([d for d in CASE_BASE.iterdir() if d.is_dir() and '_findevil_' in d.name])
    
    log.info(f"Found {len(dirs)} Find Evil case directories")
    
    pending = [d for d in dirs if needs_recovery(d)]
    log.info(f"{len(pending)} need timeline recovery")
    
    if not pending:
        log.info("All cases already have timelines — nothing to do.")
        return
    
    if not args.dry_run:
        log.info("Starting recovery...")
        success = 0
        for d in pending:
            try:
                if rebuild_timeline(d, dry_run=False):
                    success += 1
            except Exception as e:
                log.error(f"Error processing {d.name}: {e}")
        log.info(f"Done: {success}/{len(pending)} cases recovered")
    else:
        log.info("DRY RUN — would recover:")
        for d in pending:
            rebuild_timeline(d, dry_run=True)


if __name__ == '__main__':
    main()
