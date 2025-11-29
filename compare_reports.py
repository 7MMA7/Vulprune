from pathlib import Path

CPP_DIR = Path("cppcheck/reports")
FLAW_DIR = Path("flawfinder/reports")
OUT = Path("comparison_table.txt")

def load_hit_status(path):
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        lines = [l.strip() for l in f.readlines() if l.strip()]
    if len(lines) == 1 and "No detected issues" in lines[0]:
        return 0
    if any("No hits found." in l for l in lines):
        return 0
    return 1

ids = set()
for p in CPP_DIR.glob("*_report.txt"):
    ids.add(p.stem.replace("_report", ""))
for p in FLAW_DIR.glob("*_report.txt"):
    ids.add(p.stem.replace("_report", ""))

rows = []
rows.append("id,cppcheck_hit,flawfinder_hit,status")

count_both = 0
count_cpp_only = 0
count_flawfinder_only = 0
count_none = 0

for idv in sorted(ids, key=lambda x: int(x)):
    cpp_path = CPP_DIR / f"{idv}_report.txt"
    flaw_path = FLAW_DIR / f"{idv}_report.txt"

    cpp_hit = load_hit_status(cpp_path)
    flaw_hit = load_hit_status(flaw_path)

    if cpp_hit is None and flaw_hit is None:
        status = "none"
        count_none += 1
    elif cpp_hit == 1 and flaw_hit == 1:
        status = "both"
        count_both += 1
    elif cpp_hit == 1 and flaw_hit != 1:
        status = "cpp_only"
        count_cpp_only += 1
    elif flaw_hit == 1 and cpp_hit != 1:
        status = "flawfinder_only"
        count_flawfinder_only += 1
    else:
        status = "none"
        count_none += 1

    rows.append(f"{idv},{cpp_hit},{flaw_hit},{status}")

rows.append("")
rows.append("counts")
rows.append(f"both,{count_both}")
rows.append(f"cpp_only,{count_cpp_only}")
rows.append(f"flawfinder_only,{count_flawfinder_only}")
rows.append(f"none,{count_none}")
rows.append(f"total,{len(ids)}")

with open(OUT, "w", encoding="utf-8") as f:
    f.write("\n".join(rows))

print(f"Result written to {OUT}")
