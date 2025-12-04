import time
import hashlib
import os
import srp
import sys

# --- KONFIGURACJA ---
PASSWORD = "superhaslo" 

# TERAZ JEST SPRAWIEDLIWIE: Tyle samo iteracji dla szybkich metod
ITERATIONS_MD5 = 5000000    
ITERATIONS_SHA = 5000000    

# SRP jest matematycznie tak ciężkie, że 200 prób to i tak dużo w porównaniu do milionów wyżej
ITERATIONS_SRP = 200      

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def draw_progress_bar(current, total, name, color):
    """Rysuje animowany pasek w jednej linii"""
    bar_length = 40
    percent = float(current) * 100 / total
    arrow = '█' * int(percent/100 * bar_length)
    spaces = '-' * (bar_length - len(arrow))
    
    sys.stdout.write(f"\r{color}{name:<15} |{arrow}{spaces}| {int(percent)}% {Colors.END}")
    sys.stdout.flush()

def benchmark_md5():
    target = hashlib.md5(PASSWORD.encode()).hexdigest()
    start = time.perf_counter()
    
    step = 50000
    for i in range(0, ITERATIONS_MD5, step):
        for _ in range(step):
            hashlib.md5(b"nietrafione").hexdigest()
        
        draw_progress_bar(i + step, ITERATIONS_MD5, "MD5 (Słabe)", Colors.RED)

    end = time.perf_counter()
    sys.stdout.write("\n") 
    return ITERATIONS_MD5 / (end - start)

def benchmark_sha256_salt():
    salt = os.urandom(16).hex()
    target = hashlib.sha256((PASSWORD + salt).encode()).hexdigest()
    start = time.perf_counter()
    
    step = 20000
    for i in range(0, ITERATIONS_SHA, step):
        for _ in range(step):
            hashlib.sha256((b"nietrafione" + salt.encode())).hexdigest()
            
        draw_progress_bar(i + step, ITERATIONS_SHA, "SHA256 (Średnie)", Colors.BLUE)

    end = time.perf_counter()
    sys.stdout.write("\n")
    return ITERATIONS_SHA / (end - start)

def benchmark_srp():
    username = "admin"
    salt, verifier = srp.create_salted_verification_key(username, PASSWORD)
    salt_bytes = salt
    verifier_bytes = verifier
    
    start = time.perf_counter()
    
    step = 1
    for i in range(0, ITERATIONS_SRP, step):
        usr = srp.User(username, "nietrafione")
        _, A = usr.start_authentication()
        svr = srp.Verifier(username, salt_bytes, verifier_bytes, A)
        
        if hasattr(svr, 'get_challenge'):
            s, B = svr.get_challenge()
        else:
            s, B = svr.challenge()
            
        if s and B:
            M = usr.process_challenge(s, B)
            if hasattr(svr, 'verify_session'):
                svr.verify_session(M)
            else:
                svr.verify(M)
        
        draw_progress_bar(i + step, ITERATIONS_SRP, "SRP (Silne)", Colors.GREEN)

    end = time.perf_counter()
    sys.stdout.write("\n")
    return ITERATIONS_SRP / (end - start)

def main():
    os.system('cls' if os.name == 'nt' else 'clear') 
    print(f"{Colors.HEADER}{Colors.BOLD}=== WIELKI WYŚCIG KRYPTOGRAFICZNY ==={Colors.END}")
    print("Symulacja obciążenia CPU dla różnych metod łamania haseł...\n")

    # Uruchamianie testów
    speed_md5 = benchmark_md5()
    speed_sha = benchmark_sha256_salt()
    speed_srp = benchmark_srp()

    print("\n" + "="*60)
    print(f"{Colors.BOLD}WYNIKI KOŃCOWE (PRĘDKOŚĆ ŁAMANIA):{Colors.END}")
    
    print(f"{Colors.RED}MD5:          {speed_md5:,.0f} haseł/sek {Colors.END}")
    print(f"{Colors.BLUE}SHA256+Salt:  {speed_sha:,.0f} haseł/sek {Colors.END}")
    print(f"{Colors.GREEN}SRP Protocol: {speed_srp:,.0f} haseł/sek {Colors.END}")
    
    print("\n" + "-"*60)
    print("WIZUALIZACJA PRZEPAŚCI (Skala Logarytmiczna):")
    
    def draw_final_bar(speed, color):
        import math
        width = int(math.log10(speed)) * 8 
        bar = '█' * width
        return f"{color}{bar} ({speed:,.0f}){Colors.END}"

    print(f"MD5: {draw_final_bar(speed_md5, Colors.RED)}")
    print(f"SHA: {draw_final_bar(speed_sha, Colors.BLUE)}")
    print(f"SRP: {draw_final_bar(speed_srp, Colors.GREEN)}")

    print("\n")
    ratio = speed_md5 / speed_srp
    print(f"WNIOSEK: Aby sprawdzić 1 hasło w SRP, haker traci tyle czasu,")
    print(f"co na sprawdzenie {Colors.RED}{ratio:,.0f}{Colors.END} haseł w MD5.")

if __name__ == "__main__":
    main()