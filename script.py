import os
import json

def main():
    string_to_search = os.getenv('key1')
    file_database = "lista_eseguibili.txt"
    
    if not stringa_da_cercare:
        # print("ERROR: no string riceived...")
        return

    # print(f"Searching {string_to_search} ...")
    trovato = False

    if os.path.exists(file_database):
        with open(file_database, 'r', encoding='utf-8') as f:
            for riga in f:
                if string_to_search.strip() in riga:
                    trovato = True
                    break
    else:
        # print(f"The file {file_database} does not exist.")

    result_text = "MALWARE" if trovato else "good"
    requests.post("https://github.com/fabiodefilipposoftware/fdsec.it", json={
        "stringa": search_target,
        "verdict": result_text
    })
if __name__ == "__main__":
    main()
