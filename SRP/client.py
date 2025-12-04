import srp
import requests
import binascii
import getpass 

BASE_URL = "http://127.0.0.1:5000"

def hex_to_bytes(h): return binascii.unhexlify(h)
def bytes_to_hex(b): return binascii.hexlify(b).decode()

def register_user(username, password):
    print(f"\n--- REJESTRACJA UŻYTKOWNIKA: {username} ---")
    print("1. Klient: Generuję Sól i Verifier lokalnie...")
    
    salt, vkey = srp.create_salted_verification_key(username, password)
    
    print(f"   [SECRET] Password: {password} (Nigdy nie wysyłane!)")
    print(f"   [PUBLIC] Salt:     {bytes_to_hex(salt)}")
    print(f"   [PUBLIC] Verifier: {bytes_to_hex(vkey)[:20]}...")

    payload = {
        'username': username,
        'salt': bytes_to_hex(salt),
        'verifier': bytes_to_hex(vkey)
    }

    r = requests.post(f"{BASE_URL}/register", json=payload)
    if r.status_code == 201:
        print("2. Serwer: Rejestracja zakończona sukcesem.")
    else:
        print(f"Błąd rejestracji: {r.text}")

def login_srp(username, password):
    print(f"\n--- LOGOWANIE SRP (HANDSHAKE) ---")
    
    print("1. Klient: Generuję klucz publiczny A...")
    usr = srp.User(username, password)
    uname, A = usr.start_authentication()
    
    print(f"   [SENDING] Username: {username}")
    print(f"   [SENDING] A: {bytes_to_hex(A)[:20]}...")
    
    response_1 = requests.post(f"{BASE_URL}/handshake/start", json={
        'username': username,
        'A': bytes_to_hex(A)
    })
    
    if response_1.status_code != 200:
        print(f"Błąd serwera: {response_1.text}")
        return

    data_1 = response_1.json()
    salt = hex_to_bytes(data_1['salt'])
    B = hex_to_bytes(data_1['B'])
    
    print(f"2. Serwer: Odesłał Salt i klucz B.")
    print(f"   [RECEIVED] Salt: {bytes_to_hex(salt)}")
    print(f"   [RECEIVED] B:    {bytes_to_hex(B)[:20]}...")

    print("3. Klient: Obliczam dowód matematyczny M...")
    if not salt or not B:
        print("Błąd: Puste dane od serwera.")
        return

    M = usr.process_challenge(salt, B)
    
    if M is None:
        print("Błąd SRP: Nie udało się obliczyć M (może błędne dane?)")
        return

    print(f"   [SENDING] M (Dowód): {bytes_to_hex(M)[:20]}...")

    response_2 = requests.post(f"{BASE_URL}/handshake/verify", json={
        'username': username,
        'M': bytes_to_hex(M)
    })

    if response_2.status_code == 200:
        data_2 = response_2.json()
        HAMK_server = hex_to_bytes(data_2['HAMK'])
        
        print("4. Serwer: Zaakceptował dowód! Odesłał swój HAMK.")
        
        usr.verify_session(HAMK_server)
        
        print(f"\n[SUKCES] ZALOGOWANO BEZPIECZNIE! Serwer zweryfikowany.")
        print(f"Wiadomość z serwera: {data_2['message']}")
    else:
        print(f"\n[PORAŻKA] Serwer odrzucił logowanie (Złe hasło?).")

if __name__ == "__main__":
    import sys
    print("APLIKACJA KLIENTA (SECURE SRP)")
    
    mode = input("Wybierz tryb (1=Rejestracja, 2=Logowanie): ")
    user = input("Podaj login: ")
    pw = getpass.getpass("Podaj hasło: ") 

    if mode == '1':
        register_user(user, pw)
    elif mode == '2':
        login_srp(user, pw)