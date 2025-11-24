from pathlib import Path
import json

BASE_DIR = Path("extracted_vulnerabilities")

REPORT_TYPES = {
    "cppcheck": "*_report.txt",
    "flawfinder": "*_flawfinder.txt"
}

project_stats = {rtype: {} for rtype in REPORT_TYPES}

for pair_dir in BASE_DIR.iterdir():
    if not pair_dir.is_dir():
        continue

    metadata_file = pair_dir / "metadata.json"
    project = "UNKNOWN"
    if metadata_file.exists():
        try:
            with open(metadata_file, "r", encoding="utf-8") as f:
                metadata = json.load(f)
                project = metadata.get("vulnerable", {}).get("project", "UNKNOWN")
        except Exception:
            pass

    for rtype, pattern in REPORT_TYPES.items():
        if project not in project_stats[rtype]:
            project_stats[rtype][project] = {"total_pairs": 0, "missing_files": 0}

        project_stats[rtype][project]["total_pairs"] += 1

        vuln_file = next(pair_dir.glob(pattern.replace("*", "*vuln*")), None)
        fixed_file = next(pair_dir.glob(pattern.replace("*", "*fixed*")), None)
        if not vuln_file or not fixed_file:
            project_stats[rtype][project]["missing_files"] += 1

for rtype in REPORT_TYPES:
    print(f"\n=== Stats for {rtype} reports ===")
    total_projects = len(project_stats[rtype])
    total_pairs = sum(s["total_pairs"] for s in project_stats[rtype].values())
    total_missing = sum(s["missing_files"] for s in project_stats[rtype].values())

    print(f"Total projects: {total_projects}")
    print(f"Total pairs: {total_pairs}")
    print(f"Total missing files: {total_missing}")

    if total_missing > 0:
        print("\nProjects with missing files:")
        print(f"{'Project':30} {'Total Pairs':>12} {'Missing Files':>14} {'% Complete':>12}")
        print("-" * 70)
        for proj, stats in sorted(project_stats[rtype].items()):
            if stats["missing_files"] == 0:
                continue
            total = stats["total_pairs"]
            missing = stats["missing_files"]
            complete_pct = (total - missing) / total * 100 if total else 0
            print(f"{proj:30} {total:12} {missing:14} {complete_pct:11.1f}%")
    else:
        print("All projects have complete files.")