import subprocess
from pathlib import Path

BASE_DIR = Path("../extracted_vulnerabilities")

def run_cppcheck(src_file: Path, out_file: Path):
    std_flag = "--std=c11" if src_file.suffix == ".c" else "--std=c++17"
    with open(out_file, "w", encoding="utf-8") as f:
        subprocess.run(
            [
                "cppcheck",
                "--enable=all",
                "--inconclusive",
                std_flag,
                "--force",
                "--inline-suppr",
                "--quiet",
                str(src_file)
            ],
            stderr=f, stdout=f
        )
    print(f"Analysis written to {out_file}")

def process_all_pairs():
    def find_pair_file(pair_dir, suffixes):
        for suffix in suffixes:
            file = next(pair_dir.glob(f"*{suffix}"), None)
            if file:
                return file
        return None

    for pair_dir in BASE_DIR.iterdir():
        if not pair_dir.is_dir():
            continue

        print(f"\n=== Analyzing folder {pair_dir.name} ===")

        vuln_file = find_pair_file(pair_dir, ["_vuln.c", "_vuln.cc", "_vuln.cpp", "_vuln.h"])
        fixed_file = find_pair_file(pair_dir, ["_fixed.c", "_fixed.cc", "_fixed.cpp", "_fixed.h"])

        if not vuln_file or not fixed_file:
            print(f"Vuln/fixed files not found in {pair_dir}")
            continue

        vuln_report = pair_dir / "vuln_report.txt"
        fixed_report = pair_dir / "fixed_report.txt"

        run_cppcheck(vuln_file, vuln_report)
        run_cppcheck(fixed_file, fixed_report)

if __name__ == "__main__":
    process_all_pairs()