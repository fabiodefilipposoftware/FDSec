import os
import json

def main():
    string_to_search = os.getenv('key1')
    file_database = "Database/malwaresignatures.txt"
    
    if not string_to_search:
        # print("ERROR: no string riceived...")
        return

    # print(f"Searching {string_to_search} ...")
    found = False

    if os.path.exists(file_database):
        with open(file_database, 'r', encoding='utf-8') as f:
            for line in f:
                if string_to_search.strip() in line:
                    found = True
                    break
    else:
        # print(f"The file {file_database} does not exist.")

    result_text = "MALWARE" if found else "good"
    requests.post("https://github.com/fabiodefilipposoftware/fdsec.it", json={
        "string": search_target,
        "verdict": result_text
    })
if __name__ == "__main__":
    main()
