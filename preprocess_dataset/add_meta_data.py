import json
import subprocess
import os
from pathlib import Path

INPUT_JSONL = Path("../PrimeVul/primevul_test_filtered.jsonl")
OUTPUT_JSONL = Path("../PrimeVul/primevul_test_paired_enriched.jsonl")
TMP_REPOS = Path("tmp_repos")
TMP_REPOS.mkdir(exist_ok=True)

def find_file_path(repo_dir, file_name):
    matches = list(repo_dir.rglob(file_name))
    return str(matches[0].relative_to(repo_dir)) if matches else None

def load_processed_indices():
    processed = set()
    if OUTPUT_JSONL.exists():
        with open(OUTPUT_JSONL, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    processed.add(data.get("idx"))
                except:
                    pass
    return processed

def enrich_jsonl():
    processed_indices = load_processed_indices()
    print(f"Already processed indices: {processed_indices}")
    repo_cache = {}
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"

    with open(INPUT_JSONL, "r", encoding="utf-8") as fin, \
         open(OUTPUT_JSONL, "a", encoding="utf-8") as fout:

        for line in fin:
            try:
                data = json.loads(line)
            except:
                continue

            idx = data.get("idx")
            if idx in processed_indices:
                print(f"Skipping idx={idx}, already processed")
                continue

            project = data.get("project")
            commit_id = data.get("commit_id")
            project_url = data.get("project_url")
            file_name = data.get("file_name")

            print(f"Processing idx={idx} ...")

            key = (project, commit_id)
            if key not in repo_cache:
                repo_dir = TMP_REPOS / f"{project}_{commit_id}"
                if not repo_dir.exists():
                    try:
                        subprocess.run(
                            ["git", "clone", "--depth", "1", project_url, str(repo_dir)],
                            check=True,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            env=env
                        )
                        subprocess.run(
                            ["git", "fetch", "--depth", "1", "origin", commit_id],
                            cwd=str(repo_dir),
                            check=True,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            env=env
                        )
                        subprocess.run(
                            ["git", "checkout", commit_id],
                            cwd=str(repo_dir),
                            check=True,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            env=env
                        )
                    except subprocess.CalledProcessError:
                        print(f"  Git error or authentication required for idx={idx}")
                        data["file_path"] = None
                        fout.write(json.dumps(data, ensure_ascii=False) + "\n")
                        continue
                    except Exception as e:
                        print(f"  Error while processing idx={idx}: {e}")
                        data["file_path"] = None
                        fout.write(json.dumps(data, ensure_ascii=False) + "\n")
                        continue
                repo_cache[key] = repo_dir
            else:
                repo_dir = repo_cache[key]

            rel_path = find_file_path(repo_dir, file_name)
            if rel_path:
                data["file_path"] = rel_path
                print(f"  Found file at {rel_path}")
            else:
                data["file_path"] = None
                print(f"  File {file_name} not found in commit {commit_id}")

            fout.write(json.dumps(data, ensure_ascii=False) + "\n")

if __name__ == "__main__":
    enrich_jsonl()