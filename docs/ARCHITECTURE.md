# Architektura AccessGuy

## Zasada naczelna: granicą jest plik, nie biblioteka

AccessGuy celowo dzieli się na dwie fazy, które łączy **jeden artefakt** — `dataset.json`:

```
┌──────────────┐     dataset.json      ┌───────────────┐
│   SCANNER    │  (contracts/schema)   │   PROCESSOR   │
│  PowerShell  │ ───────────────────▶  │    Python     │
│  w tenancie  │   kanoniczny kontrakt │   u Ciebie    │
└──────────────┘                       └───────────────┘
   zbiera dane                          scoring + raport
   (read-only)                          (zero dostępu do tenanta)
```

Dlaczego tak, a nie współdzielona biblioteka między językami:

- **Mniej błędów.** Brak wspólnego runtime PS↔Python; każda strona testowana niezależnie. Stykiem jest walidowalny JSON, nie kruche FFI/most.
- **Bezpieczeństwo audytu.** U klienta wykonuje się tylko read-only skan; cała obróbka i scoring dzieją się później, u Ciebie, na wyniesionym pliku. Procesor nigdy nie potrzebuje poświadczeń do tenanta.
- **Właściwy język do właściwej roli.** PowerShell + moduł Microsoft.Graph jest trywialny do uruchomienia u klienta. Python daje czytelny scoring i ładny raport.

## Co świadomie odrzucono

**Python jako skaner (osobne kolektory w drugim języku).** Skanowanie u klienta to rola PowerShella (najłatwiejsze wdrożenie). Duplikowanie kolekcji danych w dwóch językach zwielokrotnia powierzchnię błędów bez realnej korzyści. Scoring żyje **wyłącznie** w Pythonie.

## Granice odpowiedzialności

| | Skaner (PS) | Procesor (Python) |
|---|---|---|
| Łączy się z Graph | ✅ | ❌ (nigdy) |
| Zbiera dane | ✅ | ❌ |
| Liczy scoring | ❌ | ✅ |
| Ładny raport HTML/PDF | ❌ | ✅ |
| Lekki raport (fallback) | ✅ (`-LiteReport`) | — |

Skaner nie ocenia ryzyka (poza trywialnym „traffic light" w lekkim raporcie). Procesor nie pobiera danych. Ta granica jest nienaruszalna — chroni przed rozjechaniem logiki na dwa języki.

## Kontrakt

- `contracts/dataset.schema.json` — JSON Schema (draft 2020-12), `schemaVersion`. Producent: skaner. Konsument: procesor (waliduje przy wczytaniu).
- `contracts/rules.yaml` — rubryka scoringu jako dane: progi, punkty, severity, rekomendacje. Czyta tylko procesor.

Zmiana kontraktu = zmiana w trzech miejscach: schema → `Dataset.ps1` (producent) → `models.py` (konsument). Zmiana łamiąca = bump `schemaVersion` (major).

## Scoring: dane + predykaty (hybryda)

Świadomie unikamy „silnika wyrażeń"/DSL w YAML (przekombinowane, łatwo o błędy). Zamiast tego:
- **`rules.yaml`** trzyma metadane i progi (zmieniasz bez dotykania kodu).
- **`predicates.py`** trzyma logikę „czy reguła się odpala" jako małe, testowalne funkcje `(account, ctx) -> str | None`.

Engine iteruje reguły z YAML i woła predykat o tym samym `id`. Nowa reguła = wpis w YAML + funkcja w `predicates.py` (lub `predicates_group.py` / `predicates_app.py`).

## Korelacja: tożsamość × grupa × aplikacja × logi sign-in

Reguły bazowe oceniają każdy obiekt **w izolacji**. Najwięcej wartości jest jednak w powiązaniach
między modułami — i to robi warstwa korelacji (`scoring/correlation.py`):

- `CorrelationIndex.build(dataset)` buduje **raz** mapy: konta po id/UPN/nazwie, grupy po id, oraz
  „użytkownik → grupy nadające role uprzywilejowane, których jest członkiem". Indeks trafia do
  `ScoringContext.index` i jest dostępny dla wszystkich predykatów (bez skanów O(n²)).
- Wspólne helpery `account_weaknesses()` / `attack_signals()` dają **jedną** definicję „słabego konta"
  (brak MFA, udane legacy auth, ryzykowne logowania) w całym raporcie — konta, grupy i aplikacje
  mierzą tożsamość identyczną miarą.

Reguły korelacyjne (świadomie nakładają się punktowo na bazowe — ta sama aktywność na koncie
z realną władzą to inna klasa ryzyka):

| Reguła | Co koreluje |
|---|---|
| `SHADOW_PRIVILEGE` | konto bez bezpośredniej roli, ale członek grupy z rolą uprzywilejowaną (ukryty admin) |
| `PRIV_COMPROMISE_SIGNALS` | konto z efektywną rolą uprzywilejowaną + sygnały ataku z logów = potencjalny incydent |
| `GROUP_PRIV_WEAK_MEMBERS` | grupa uprzywilejowana ze słabo chronionymi członkami (imiennie) |
| `APP_PRIV_OWNER_WEAK` | słabo chroniony właściciel aplikacji z app-only high-risk (owner → sekret → przejęcie) |
| `APP_GUEST_REACH` | goście z dostępem do aplikacji — bezpośrednio lub przez przypisaną grupę |

Na tym samym indeksie raport `summary` buduje **imienne ścieżki eskalacji**
(`community.build_escalation_paths`) — gotowe łańcuchy „słabe konto → grupa/aplikacja → rola
uprzywilejowana" z dowodem z logów, zamiast samego licznika.

## Determinizm

„Dni od logowania" liczone względem `dataset.generatedAt`, nigdy względem `now()`. Ten sam dataset → ten sam raport, niezależnie od tego, kiedy go obrabiasz.
