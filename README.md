# Kryptografia-Bruteforce

**GitHub Repository:** [https://github.com/ultimus12/Kryptografia-Bruteforce](https://github.com/ultimus12/Kryptografia-Bruteforce)

Projekt ten ma na celu demonstrację różnych podejść do przechowywania haseł i uwierzytelniania, oraz analizę ich odporności na ataki typu brute-force (siłowe).

Repozytorium zawiera trzy poziomy zabezpieczeń ("Słabe", "Średnie", "Silne") oraz skrypt porównujący ich wydajność.

## Cel Projektu
Głównym celem jest pokazanie, dlaczego **szybkość** algorytmu hashującego jest wrogiem bezpieczeństwa haseł. Projekt ilustruje ewolucję od prostego hashowania, przez stosowanie soli (salt) i pieprzu (pepper), aż po zaawansowane protokoły kryptograficzne (SRP).

## Struktura i Użyte Technologie

W projekcie zaimplementowano trzy niezależne aplikacje webowe (Flask) oraz skrypt benchmarkowy:

### 1. Poziom Słaby: MD5 (`/MD5`)
*   **Technologia**: Czyste hashowanie MD5.
*   **Działanie**: Aplikacja przechowuje hasła użytkowników jako prosty skrót MD5.
*   **Wnioski**:
    *   Algorytm MD5 jest ekstremalnie szybki.
    *   Podatny na ataki przy użyciu **Rainbow Tables** (Tablic Tęczowych) - odnalezienie hasła dla skrótu następuje w ułamku sekundy.
    *   Podatny na kolizje.

### 2. Poziom Średni: MD5 + Salt + Pepper (`/MD5Salted`)
*   **Technologia**: MD5 z losową solą (dla każdego usera) i stałym pieprzem (ukrytym w kodzie).
*   **Mechanizm**: `Hash = MD5(Hasło + Salt + Pepper)`
*   **Działanie**:
    *   **Salt** (Sól) chroni przed Rainbow Tables (każdy użytkownik ma inny hash dla tego samego hasła).
    *   **Pepper** (Pieprz) dodaje warstwę bezpieczeństwa w przypadku wycieku samej bazy danych (ale nie kodu).
*   **Wnioski**: Mimo użycia soli, sam algorytm MD5 jest nadal bardzo szybki. Jeśli atakujący przejmie bazę i zna kod (zna pepper), może przeprowadzić bardzo wydajny atak słownikowy (prezentowany przez skrypt `crack.py` z użyciem listy `rockyou.txt`).

### 3. Poziom Silny: Protokół SRP (`/SRP`)
*   **Technologia**: Secure Remote Password (SRP) Protocol / Zero-Knowledge Proof.
*   **Działanie**:
    *   Serwer **NIGDY** nie widzi czystego hasła, nawet podczas rejestracji czy logowania.
    *   Baza danych przechowuje jedynie "Verifier" i Salt.
    *   Logowanie odbywa się poprzez wymianę dowodów matematycznych.
*   **Wnioski**: SRP jest obliczeniowo kosztowny. Weryfikacja to skomplikowane operacje modulo na bardzo dużych liczbach. Bruteforce jest tutaj praktycznie niemożliwy ze względu na czas potrzebny na sprawdzenie pojedynczego kandydata.

---

## Benchmark: Wyścig Kryptograficzny (`race.py`)

W głównym folderze znajduje się skrypt `race.py`, który symuluje atak na wszystkie trzy metody i porównuje ich prędkość.

**Przykładowe wyniki (zależne od CPU):**
*   **MD5**: Miliony haseł na sekundę.
*   **SHA/MD5+Salt**: Nieznacznie wolniej, ale nadal bardzo szybko.
*   **SRP**: Zaledwie kilkaset weryfikacji na sekundę.

### Wnioski Końcowe
Aby skutecznie zabezpieczyć hasła, nie wystarczy ukryć ich pod hashem. Należy użyć algorytmu (lub protokołu), który jest **wolny** (slow hashing), aby drastycznie zwiększyć koszt ataku dla hakera. W tym projekcie rolę "bezpiecznika" pełni protokół SRP, który naturalnie spowalnia proces weryfikacji.

## Zespół Projektowy i Podział Obowiązków

| Osoba | Zadania |
| :--- | :--- |
| **Maciej Popławski** | Pomysł, Planowanie struktury projektu, Implementacja techniczna (Backend & Frontend) |
| **Klaudiusz Kapała** | Opracowanie teorii kryptograficznej, Przygotowanie prezentacji, Weryfikacja i końcowe szlify projektu |

## Koncepcja i Realizacja

Projekt udało się zrealizować niemal w 100% zgodnie z pierwotnymi założeniami. Zaimplementowano działające przykłady dla wszystkich trzech poziomów bezpieczeństwa.

*   **Co się udało**: Stworzenie w pełni funkcjonalnych aplikacji demonstrujących różnice w bezpieczeństwie oraz napisanie narzędzia wizualizującego różnice w prędkości łamania haseł.
*   **Uwagi**: Moduł benchmarku (`race.py`) jest symulacją mającą na celu zobrazowanie rzędu wielkości problemu. W środowisku produkcyjnym testy wydajności mogłyby być bardziej rygorystyczne, jednak obecna forma w zupełności wystarcza do celów edukacyjnych i prezentacyjnych.

## Instrukcja Uruchomienia / How to Run

### Wymagania
Upewnij się, że masz zainstalowanego Pythona 3. Następnie zainstaluj wymagane biblioteki:

```bash
pip install flask srp
```

### 1. Uruchomienie aplikacji webowych (Prezentacja)

Możesz uruchomić każdą z aplikacji oddzielnie w osobnych terminalach, aby przetestować działanie logowania i rejestracji.

*   **Aplikacja MD5 (Podatna, Port 5001):**
    ```bash
    python MD5/app.py
    ```
    Otwórz w przeglądarce: http://127.0.0.1:5001

*   **Aplikacja MD5 + Salt (Lepsza, Port 5002):**
    ```bash
    python MD5Salted/app.py
    ```
    Otwórz w przeglądarce: http://127.0.0.1:5002

*   **Aplikacja SRP (Bezpieczna, Port 5000):**
    ```bash
    python SRP/app.py
    ```
    Otwórz w przeglądarce: http://127.0.0.1:5000

### 2. Uruchomienie Benchmarku (Porównanie prędkości)

Aby zobaczyć różnicę między algorytmami w terminalu:

```bash
python race.py
```

### 3. Próba łamania haseł (MD5 Salted)

W katalogu `MD5Salted` znajduje się skrypt, który próbuje złamać hasło użytkownika używając ataku słownikowego i pliku `rockyou.txt`.

```bash
cd MD5Salted
python crack.py
```
*(Uwaga: Skrypt wymaga obecności pliku `rockyou.txt` w tym samym katalogu).*
