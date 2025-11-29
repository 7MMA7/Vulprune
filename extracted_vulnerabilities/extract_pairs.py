import json
from pathlib import Path

class VulnerabilityFileExtractor:
    def __init__(self, jsonl_path: str, output_dir: str = "./extracted_files"):
        self.jsonl_path = jsonl_path
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def process_jsonl(self):
        with open(self.jsonl_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        pairs_processed = 0
        pairs_failed = 0
        
        for i in range(0, len(lines), 2):
            if i + 1 >= len(lines):
                break
            
            vuln_data = json.loads(lines[i])
            fixed_data = json.loads(lines[i + 1])
            
            if vuln_data.get('target') != 1 or fixed_data.get('target') != 0:
                print(f"Warning: Invalid pair at lines {i} and {i+1}")
                pairs_failed += 1
                continue
            
            if vuln_data.get('commit_id') != fixed_data.get('commit_id'):
                print(f"Warning: Different commits for idx {vuln_data.get('idx')} and {fixed_data.get('idx')}")
                pairs_failed += 1
                continue
            
            file_name = vuln_data.get('file_name')
            if not file_name or str(file_name).lower() == "none":
                print(f"Skipping pair with invalid file_name at idx {vuln_data.get('idx')}")
                pairs_failed += 1
                continue
            
            try:
                print(f"\n{'='*60}")
                print(f"Processing pair {pairs_processed + 1}")
                print(f"CVE: {vuln_data.get('cve')}")
                print(f"File: {file_name}")
                print(f"Project: {vuln_data.get('project')}")

                pair_dir = self.output_dir / f"pair_{vuln_data.get('idx')}_{fixed_data.get('idx')}"
                pair_dir.mkdir(exist_ok=True)
                
                file_name_clean = file_name.replace('/', '_').replace('\\', '_')
                if '.' in file_name_clean:
                    name_part, ext_part = file_name_clean.rsplit('.', 1)
                    vuln_filename = f"{name_part}_vuln.{ext_part}"
                    fixed_filename = f"{name_part}_fixed.{ext_part}"
                else:
                    vuln_filename = f"{file_name_clean}_vuln"
                    fixed_filename = f"{file_name_clean}_fixed"
                
                vuln_file = pair_dir / vuln_filename
                fixed_file = pair_dir / fixed_filename
                
                with open(vuln_file, 'w', encoding='utf-8') as f:
                    f.write(vuln_data.get('func', ''))
                
                with open(fixed_file, 'w', encoding='utf-8') as f:
                    f.write(fixed_data.get('func', ''))
                
                metadata = {
                    'vulnerable': {
                        'idx': vuln_data.get('idx'),
                        'project': vuln_data.get('project'),
                        'commit_id': vuln_data.get('commit_id'),
                        'commit_url': vuln_data.get('commit_url'),
                        'commit_message': vuln_data.get('commit_message'),
                        'cve': vuln_data.get('cve'),
                        'cve_desc': vuln_data.get('cve_desc'),
                        'cwe': vuln_data.get('cwe'),
                        'nvd_url': vuln_data.get('nvd_url'),
                        'file_name': file_name,
                        'func_hash': vuln_data.get('func_hash'),
                        'file_hash': vuln_data.get('file_hash')
                    },
                    'fixed': {
                        'idx': fixed_data.get('idx'),
                        'func_hash': fixed_data.get('func_hash'),
                        'file_hash': fixed_data.get('file_hash')
                    }
                }
                with open(pair_dir / 'metadata.json', 'w', encoding='utf-8') as f:
                    json.dump(metadata, f, indent=2)
                
                print(f"Pair saved in {pair_dir}")
                pairs_processed += 1
                
            except Exception as e:
                print(f"Error processing pair: {e}")
                import traceback
                traceback.print_exc()
                pairs_failed += 1
        
        print(f"\n{'='*60}")
        print("Processing completed:")
        print(f"  - Successful pairs: {pairs_processed}")
        print(f"  - Failed pairs: {pairs_failed}")
        print(f"  - Output directory: {self.output_dir}")

if __name__ == "__main__":
    jsonl_path = "./PrimeVul/primevul_filtered.jsonl"
    output_dir = "./extracted_vulnerabilities"
    
    extractor = VulnerabilityFileExtractor(jsonl_path, output_dir)
    extractor.process_jsonl()