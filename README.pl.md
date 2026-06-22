```
                                             :       ====:.-:..........
                             .==:     =--+-+-:+ .. :=-+=--=.-          .
                      :+=-  +-  .+=+--+   -====#-   +##= :+=+==+====++ +-
                -   :+:  .=-   ++ ===-==+=- +#=++++*- -*#===:          *.
              -= --+-   =- :+=  --+ -=*+####+*****- ++==-*#:=======+=-=======
            -+   =:   ++   +=.++:-==+:###-+##--=-------:--=##-      -=      =:::::::::::-+.
          ++   +=            +==:+-**##+     *#*====------=:*##=+.+--+ ++    ==+++-.  -:
 ==                            --++##+        *#*#========++=
-+-#****************************-###=          +##+-=-+=====:+:=.=:==.+=:+=:+=-+=
 -===+==+================+-==- --###=        =##+*:=-=+: ==-=
       *  =  ------------== -= -::- +###-  =##+*-+-=:=-=-=-
       + =+                =----=-==:==##*##**:===-=--                       =
    ==:=-=--=:=-==.=-:=-==:=-==:=+=+=-==*#**-========:-=:  -+   :=   -+  -*:=-
                   =+=+===+-     =-  =-+- -=-+-==-=-    =.=-  :=: ==*: :+:+-
                           .====-    +- =-  =:  =:+-=-  +-+  +-      .+:=.
                                      :+   -=:-=      +=   --
                                             -  =+
```

# AccessGuy — Read-only tool pod audyt uprawnień Microsoft Entra ID (Azure AD)

🌐 **Polski** · [English](README.md)

**AccessGuy to read-only narzędzie do przeglądu uprawnień Microsoft Entra ID (Azure AD).** Łączy się
raz (tylko odczyt), inwentaryzuje użytkowników, grupy i aplikacje i punktuje ryzyko — braki MFA, 
konta uprzywilejowane bez MFA, legacy auth, ryzykowne logowania, stałe role poza PIM, pokrycie
Conditional Access i nadmiarowe uprawnienia aplikacji — w czytelny **raport postawy A–F** pod
przeglądy i audyty dostępu (ISO 27001 / NIS2).

Autor: **Daniel „NewLife" Budyn**
- LinkedIn: https://www.linkedin.com/in/daniel-b-4295a421a/
- GitHub: https://github.com/NewLife-Org/AccessGuy
- YouTube: https://www.youtube.com/@NewLife-org-pl
---

## ▶ Szybki start (uruchom to)

```bash
# Linux / macOS:
sudo pwsh ./NewLife-AccessGuy.ps1
```
```powershell
# Windows (PowerShell 7+):
pwsh .\NewLife-AccessGuy.ps1
```

Jeden launcher prowadzi Cię za rękę:
1. wybierasz **[1] Skan** → logujesz się do tenanta (na Linux: **[2] kod / device code**) → skaner zbiera dane,
2. wybierasz **[2] Raport** → wskazujesz plik skanu → dostajesz gotowy raport HTML.

> **Język / Language.** Domyślnie wszystko jest po **angielsku**. Zmienisz w menu pozycją **[L] Language / Język**
> (PL teraz, kolejne języki w drodze) albo parametrem: `pwsh ./NewLife-AccessGuy.ps1 -Lang pl`.
> Bezpośrednio w procesorze: `python -m accessguy_processor process dataset.json --lang pl`.

> **Sprawdzenie przed skanem.** Pozycja menu **[D] Komponenty** (check before scan) pokazuje status komponentów pakietu,
> wykorzystywane uprawnienia Graph (z opisem), obecność Pythona i 7-Zip oraz prawa zapisu do folderów `out/` i `reports/`.

To wszystko. Reszta tego dokumentu to szczegóły.

---

## Po co to jest

AccessGuy odpowiada na pytanie, które pada na każdym audycie i przeglądzie ISO 27001 / NIS2:

> **„Kto ma dostęp do czego w naszym Entra ID i co z tym pilnie zrobić?"**

Łączysz się **raz** (read-only, jako Global Reader / Global Admin), a narzędzie:
- inwentaryzuje wszystkie konta (internal / external / guest), **grupy** i **aplikacje**, role i licencje,
- punktuje ryzyko wg jasnej rubryki (nieaktywność, role uprzywilejowane bez MFA, legacy auth, ryzykowne logowania, stałe role poza PIM, nieużywane uprawnienia…),
- **koreluje moduły między sobą** — łączy tożsamości, grupy i aplikacje z logami sign-in i pokazuje **imienne ścieżki eskalacji** (np. „konto bez MFA → członek grupy z rolą Global Admin → pełny dostęp”),
- generuje **czytelny raport HTML** z oceną postawy **A–F**, streszczeniem dla zarządu i **planem działań „od czego zacząć”**.

**Nic nie zmienia w tenancie.** Żadnych uprawnień zapisu, żadnych sekretów po stronie raportu.

---

## Jak to działa — dwie fazy, jeden plik

```
[ TENANT ] --(SKANER: PowerShell)--> <tenant>_<data>.json --(BUILDER: Python)--> raport HTML/CSV
            read-only, u klienta            plik = kontrakt           scoring + ładny raport, u Ciebie
```

| Faza | Co robi | Gdzie |
|---|---|---|
| **[1] AccessGuy-EntraID-Scanner** | łączy się z Entra ID (tylko odczyt), zbiera dane → `out/<tenant8>_<data>.json` | u klienta / w tenancie |
| **[2] AccessGuy-Report-Builder** | czyta plik skanu, liczy scoring, generuje raport HTML/CSV | u Ciebie (Python 3) |

Granicą jest **plik JSON** (kontrakt `contracts/dataset.schema.json`). Skanujesz u klienta, wynosisz JSON, raport robisz u siebie — builder **nigdy nie dotyka tenanta**. Jak u klienta nie ma Pythona, skaner zrobi *lekki* raport HTML sam (`out/*.lite.html`).

---

## Użycie krok po kroku

### Tryb [1] — Skan

```bash
sudo pwsh ./NewLife-AccessGuy.ps1     # → wybierz [1]
```
- Wybierz logowanie: **[1] przeglądarka** (Windows) albo **[2] kod / device code** (zalecane na Linux).
- Przy device code zobaczysz: *„open https://microsoft.com/device and enter code XXXX"* — wpisz kod, potwierdź w **Authenticatorze**.
- Po zalogowaniu: efektowny reveal logo, liczniki łapanych danych i podsumowanie „co złapaliśmy".
- Wynik: `out/<tenant8>_<data>.json` (+ `.lite.html`).
- Na koniec (interaktywnie) możesz **opcjonalnie** zaszyfrować dataset w archiwum chronionym hasłem (7-Zip / AES-256). Uwaga: zaszyfrowanego datasetu builder nie odczyta, dopóki go nie rozpakujesz.

Bezpośrednio, bez launchera:
```bash
pwsh ./scanner/Invoke-AccessGuyScan.ps1 -DeviceCode -LiteReport
```

### Tryb [2] — Raport

```bash
sudo pwsh ./NewLife-AccessGuy.ps1     # → wybierz [2]
```
- Builder sam utworzy środowisko Python (venv), doinstaluje zależności i **wylistuje pliki skanu** z `out/` do wyboru.
- Wynik: **jeden interaktywny raport HTML** `reports/<NazwaTenanta>_<data>.html` — ocena postawy na górze, pod nią cztery zakładki (Konta / Grupy / Aplikacje / Conditional Access) — plus eksporty `.csv` per moduł.
- Po zbudowaniu możesz **opcjonalnie** spakować raport + dataset w jedno zaszyfrowane archiwum (7-Zip / AES-256); hasło pokazywane jest **raz** i nigdzie nie zapisywane.

Bezpośrednio:
```bash
cd processor && python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/python -m accessguy_processor build --dir ../out --out ../reports
```

### Tryb cykliczny (app-only, bez człowieka)
```powershell
./scanner/Invoke-AccessGuyScan.ps1 -AuthMode App -UseManagedIdentity
```

---

## Co znajdziesz w raporcie

- **Ocena postawy A–F** + streszczenie dla zarządu (najgorsze konta na wierzchu).
- **Ścieżki eskalacji** — imienne łańcuchy ataku z dowodem z logów (korelacja tożsamość × grupa × aplikacja).
- **Plan działań „od czego zacząć”** — wszystkie ustalenia z trzech modułów zagregowane w priorytetyzowaną listę zadań, z głębokimi linkami do konkretnych kart.
- **Charakterystyka tenanta:** liczba kont, Global Adminów, kont bez MFA, **pokrycie MFA %**, licencje M365, **10 ostatnio założonych kont**, **legacy auth wg protokołu**.
- **Conditional Access i postawa tenanta** — każda polityka CA z rozwiązanym zakresem (kogo i jakie aplikacje obejmuje, kto jest wykluczony), czy MFA jest wymuszane **szeroko** (wszyscy użytkownicy + wszystkie aplikacje) czy tylko **wąsko zakresowanymi** politykami, blokada legacy auth, polityki report-only, konta wykluczone z MFA oraz konta ryzykowne z Identity Protection.
- **Konta / grupy / aplikacje wg ryzyka** — rozwijana karta na obiekt (klikasz → pełne detale), z filtrowaniem i wyszukiwarką: ostatnie logowanie, zmiana hasła, MFA, licencje, **aktywność 30 dni** (logowania / nieudane / nocne 20–04 / ryzykowne / legacy / top-aplikacje), role, członkowie/właściciele, flagi z rekomendacjami.
- Bogata rubryka scoringu (konta + grupy + aplikacje + **reguły korelacyjne**) m.in.: konto nieaktywne, gość/zewnętrzny z rolą uprzywilejowaną, **stałe role poza PIM**, **uprawnienia posiadane ale nieużywane**, **konto uprzywilejowane bez MFA**, **legacy auth (omija MFA)**, **ryzykowne logowania**, **ukryty admin przez grupę**, **sygnały ataku na koncie uprzywilejowanym**, **słaby właściciel aplikacji app-only**, zgody na aplikacje wysokiego ryzyka. Pełna lista i progi: [`contracts/rules.yaml`](contracts/rules.yaml).

---

## Prerekwizyty

**Skan (faza 1):**
- PowerShell 7+ (`pwsh`)
- moduł `Microsoft.Graph.Authentication`:
  ```powershell
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
  ```
- konto operatora z rolą **Global Reader** (lub Global Admin / Security Reader + Reports Reader)
- tenant **Entra ID P1/P2** dla pełnych danych logowań (`signInActivity`, signIns)

**Raport (faza 2):**
- Python 3.11+ (builder sam tworzy venv i dociąga zależności)
- (opcjonalnie PDF) na Debian/Kali: `sudo apt install -y libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev`

**Ochrona wyniku (opcjonalnie):**
- **7-Zip** (`7z` / `7za` / `7zz`, na Windows także domyślna instalacja `7-Zip`) — tylko jeśli chcesz szyfrować dataset/raporty. Bez niego wszystko działa, pliki zostają jawne.

---

## Uprawnienia (zawsze read-only)

`User.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`, `RoleManagement.Read.All` (wymagane) + `Application.Read.All`, `UserAuthenticationMethod.Read.All`, `Policy.Read.All`, `IdentityRiskyUser.Read.All` (zalecane). **Żadnych `*.ReadWrite.*`.**

> Logujesz się raz jako Global Admin/Reader — to wystarcza. Token przy logowaniu kodem żyje tylko w pamięci procesu (`-ContextScope Process`), nie ląduje w keyringu.

---

## Struktura repo

```
NewLife-AccessGuy.ps1     ← główny launcher (start tutaj)
scanner/                  ← faza SKAN (PowerShell): Invoke-AccessGuyScan.ps1 + lib/
processor/                ← faza RAPORT (Python): src/accessguy_processor/ + testy
contracts/                ← kontrakt: dataset.schema.json + rules.yaml + sample
```

---

## Licencja

Używaj, modyfikuj, wdrażaj — śmiało. Ale **nie podszywaj się pod autora i nie przypisuj sobie autorstwa**. Pełna treść: [`LICENSE`](LICENSE).

> *Używaj jak chcesz — ale jak się podszyjesz i ukradniesz, ryzykujesz własnymi nogami.* — NewLife
