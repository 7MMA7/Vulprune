from pathlib import Path
import re

REPORT_DIR = Path("extracted_vulnerabilities")
ANON_REPORT_DIR = Path("flawfinder")
ANON_REPORT_DIR.mkdir(exist_ok=True)

def anonymize_filename(file_path: str) -> str:
    path = Path(file_path)
    filename = path.name
    filename = re.sub(r"_vuln|_fixed", "", filename)
    return filename

def anonymize_report(report_path: Path, out_path: Path):
    with open(report_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    new_lines = []
    for line in lines:
        if ":" in line:
            parts = line.split(":", 1)
            file_part = parts[0]
            rest = parts[1]
            anon_file = anonymize_filename(file_part)
            new_lines.append(f"{anon_file}:{rest}")
        else:
            new_lines.append(line)

    with open(out_path, "w", encoding="utf-8") as f:
        f.writelines(new_lines)

for pair_dir in REPORT_DIR.iterdir():
    if not pair_dir.is_dir():
        continue

    match = re.match(r"pair_(\d+)_(\d+)", pair_dir.name)
    if not match:
        print(f"Skipping {pair_dir.name}, cannot extract idxs")
        continue
    idx1, idx2 = match.groups()

    vuln_report = next(pair_dir.glob("*vuln_flawfinder.txt"), None)
    fixed_report = next(pair_dir.glob("*fixed_flawfinder.txt"), None)

    if vuln_report:
        out_file = ANON_REPORT_DIR / f"{idx1}_report.txt"
        anonymize_report(vuln_report, out_file)
        print(f"Anonymized report written to {out_file}")

    if fixed_report:
        out_file = ANON_REPORT_DIR / f"{idx2}_report.txt"
        anonymize_report(fixed_report, out_file)
        print(f"Anonymized report written to {out_file}")
