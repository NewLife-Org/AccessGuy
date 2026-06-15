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

# AccessGuy

**Read-only audyt uprawnień Microsoft Entra ID — od jednego logowania do raportu dla zarządu.**
Autor: **Daniel „NewLife" Budyn**

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

Bezpośrednio, bez launchera:
```bash
pwsh ./scanner/Invoke-AccessGuyScan.ps1 -DeviceCode -LiteReport
```

### Tryb [2] — Raport

```bash
sudo pwsh ./NewLife-AccessGuy.ps1     # → wybierz [2]
```
- Builder sam utworzy środowisko Python (venv), doinstaluje zależności, **wylistuje pliki skanu** z `out/` i pozwoli wybrać (oraz który raport zbudować: zbiorczy / konta / grupy / aplikacje).
- Wynik: `reports/<NazwaTenanta>_<data>_{summary,users,groups,apps}.html` (+ `.csv`).

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

---

## Uprawnienia (zawsze read-only)

`User.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`, `RoleManagement.Read.All` (wymagane) + `Application.Read.All`, `UserAuthenticationMethod.Read.All` (zalecane). **Żadnych `*.ReadWrite.*`.** Szczegóły: [`docs/PERMISSIONS.md`](docs/PERMISSIONS.md).

> Logujesz się raz jako Global Admin/Reader — to wystarcza. Token przy logowaniu kodem żyje tylko w pamięci procesu (`-ContextScope Process`), nie ląduje w keyringu.

---

## Struktura repo

```
NewLife-AccessGuy.ps1     ← główny launcher (start tutaj)
scanner/                  ← faza SKAN (PowerShell): Invoke-AccessGuyScan.ps1 + lib/
processor/                ← faza RAPORT (Python): src/accessguy_processor/ + testy
contracts/                ← kontrakt: dataset.schema.json + rules.yaml + sample
docs/                     ← ARCHITECTURE · PERMISSIONS · RUNBOOK
```

Więcej: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) · [`docs/PERMISSIONS.md`](docs/PERMISSIONS.md) · [`docs/RUNBOOK.md`](docs/RUNBOOK.md).

---

## Kontakt

**Daniel „NewLife" Budyn**
- LinkedIn: https://www.linkedin.com/in/daniel-b-4295a421a/
- GitHub: https://github.com/NewLife-Org/AccessGuy

---

## Licencja

Używaj, modyfikuj, wdrażaj — śmiało. Ale **nie podszywaj się pod autora i nie przypisuj sobie autorstwa**. Pełna treść: [`LICENSE`](LICENSE).

> *Używaj jak chcesz — ale jak się podszyjesz i ukradniesz, ryzykujesz własnymi nogami.* — NewLife
