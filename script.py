import os
import json

def main():
    string_to_search = os.getenv('key1')
    file_database = "Database/malwaresignatures.txt"
    database_set = set()
    
    if not string_to_search:
        return false
    
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            database_set = {line.strip() for line in f if line.strip()}
  
    found = False
    
    if search_target in database_set:
        found = True

    result_text = "MALWARE" if found else "good"
    requests.post("https://github.com/fabiodefilipposoftware/fdsec.it", json={
        "string": search_target,
        "verdict": result_text
    })
if __name__ == "__main__":
    main()
