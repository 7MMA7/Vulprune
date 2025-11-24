import json
from collections import defaultdict

input_path = "PrimeVul/primevul_test_paired_enriched.jsonl"
output_path = "PrimeVul/primevul_filtered.jsonl"

entries_by_key = defaultdict(list)

with open(input_path, "r", encoding="utf-8") as fin:
    for line in fin:
        try:
            obj = json.loads(line)
        except:
            continue
        if obj.get("file_path") is None:
            continue
        key = (obj.get("commit_id"), obj.get("file_name"))
        entries_by_key[key].append(obj)

with open(output_path, "w", encoding="utf-8") as fout:
    for key, objs in entries_by_key.items():
        targets = {o.get("target") for o in objs}
        if targets == {0, 1}:
            for o in objs:
                fout.write(json.dumps(o) + "\n")
