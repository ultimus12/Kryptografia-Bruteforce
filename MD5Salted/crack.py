import sqlite3
import hashlib
import time
import os
import sys

# --- KONFIGURACJA ---
DATABASE = 'db_salted.db'
TARGET_USER = 'amogus' 
WORDLIST_FILE = 'rockyou.txt' # Nazwa pliku słownika

# Pieprz musi być ten sam, co w server_salted.py
PEPPER = "TajnySkladnik_Chroniac_Przed_RainbowTables"

def crack_salted_rockyou():
    print(f"--- ATAK SŁOWNIKOWY NA BAZĘ SOLONĄ (ROCKYOU) ---")
    
    # 1. Sprawdź czy plik słownika istnieje
    if not os.path.exists(WORDLIST_FILE):
        print(f"[BŁĄD] Nie znaleziono pliku '{WORDLIST_FILE}'!")
        print("Pobierz go i umieść w tym samym folderze.")
        return

    # 2. Wykradnij Hash i Sól z bazy
    try:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash, salt FROM users_salted WHERE username = ?", (TARGET_USER,))
        row = cursor.fetchone()
        conn.close()
    except Exception as e:
        print(f"[BŁĄD BAZY] {e}")
        return

    if not row:
        print(f"[BŁĄD] Użytkownik '{TARGET_USER}' nie istnieje w bazie db_salted.db.")
        return

    stolen_hash = row['password_hash']
    stolen_salt = row['salt']
    
    print(f"[INFO] Cel: {TARGET_USER}")
    print(f"[INFO] Hash: {stolen_hash}")
    print(f"[INFO] Salt: {stolen_salt}")
    print(f"[START] Rozpoczynam czytanie {WORDLIST_FILE}...")
    
    start_time = time.perf_counter()
    attempts = 0
    
    # 3. Otwieramy plik rockyou (tryb latin-1 jest bezpieczniejszy dla tego pliku niż utf-8)
    try:
        with open(WORDLIST_FILE, 'r', encoding='latin-1', errors='ignore') as f:
            for line in f:
                attempts += 1
                
                # Usuwamy znak nowej linii (\n) z końca
                guess = line.strip()
                
                # Konstrukcja hasha: Hasło_ze_słownika + Sól_z_bazy + Pieprz
                combined = guess + stolen_salt + PEPPER
                calculated_hash = hashlib.md5(combined.encode()).hexdigest()
                
                # Porównanie
                if calculated_hash == stolen_hash:
                    end_time = time.perf_counter()
                    duration = end_time - start_time
                    
                    print(f"\n{'-'*40}")
                    print(f"[SUKCES] HASŁO ZŁAMANE!")
                    print(f"{'-'*40}")
                    print(f"Hasło:       '{guess}'")
                    print(f"Czas ataku:  {duration:.4f} sekundy")
                    print(f"Próba nr:    {attempts}")
                    print(f"Prędkość:    {attempts/duration:,.0f} haseł/sek")
                    return

                # Pasek postępu co 100,000 haseł (żeby nie zaspamować konsoli)
                if attempts % 100000 == 0:
                    sys.stdout.write(f"\r[W TOKU] Sprawdzono {attempts:,} haseł...")
                    sys.stdout.flush()

    except KeyboardInterrupt:
        print("\n[PRZERWANO] Atak zatrzymany przez użytkownika.")
        return

    print(f"\n[FAIL] Przeszukano cały plik ({attempts} haseł) i nie znaleziono dopasowania.")

if __name__ == "__main__":
    crack_salted_rockyou()