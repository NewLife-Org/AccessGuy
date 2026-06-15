# Uprawnienia i prerekwizyty

AccessGuy jest **read-only**. Nie używa i nie powinien nigdy używać scope'ów `*.ReadWrite.*` ani zapisowych API.

## Wymagane uprawnienia Microsoft Graph

| Scope | Po co | Wymagane? |
|---|---|---|
| `User.Read.All` | inwentarz kont, atrybuty, typ użytkownika | tak |
| `Directory.Read.All` | organizacja, zweryfikowane domeny, kontekst | tak |
| `AuditLog.Read.All` | `signInActivity`, **logi `signIns`** (nocne/legacy/ryzykowne logowania, top-aplikacje) oraz **historia PIM** (directory audits) | tak |
| `RoleManagement.Read.All` | przypisania i kwalifikowalność ról (PIM unified RBAC); także role nadane **grupom** role-assignable | tak |
| `Application.Read.All` | enterprise apps / service principals / zgody OAuth; **moduł Aplikacje**: rejestracje, poświadczenia (wygasanie), uprawnienia aplikacyjne/delegowane | zalecane |
| `UserAuthenticationMethod.Read.All` | stan rejestracji MFA | zalecane |
| `Policy.Read.All` | **1.3**: polityki Conditional Access (`/identity/conditionalAccess/policies`) + postawa tenanta (`/policies/authorizationPolicy`, `identitySecurityDefaultsEnforcementPolicy`, `authenticationMethodsPolicy`) | zalecane |
| `IdentityRiskyUser.Read.All` | **1.3**: bieżący stan ryzyka kont (`/identityProtection/riskyUsers`, wymaga P2) — reguła `RISKY_USER_UNREMEDIATED` | zalecane |

> Historię aktywacji PIM bierzemy z `auditLogs/directoryAudits` (filtr `category eq 'RoleManagement'`). To utrzymuje pełny read-only — **nie** potrzeba zapisowych uprawnień do PIM.

### Kolektory 1.3 (schema 1.3)

- **`spSignIns`** — `/beta/reports/servicePrincipalSignInActivities` (pokrywa `AuditLog.Read.All`, które już mamy). Wypełnia `application.lastSignInDateTime` → reguła `APP_DORMANT_PRIVILEGED` (uśpiona aplikacja z uprawnieniami high-risk).
- **`caPolicies`** — `/identity/conditionalAccess/policies` (`Policy.Read.All`). Skaner normalizuje: `requiresMfa` (builtInControls `mfa` lub authenticationStrength), `blocksLegacyAuth` (`block` + clientAppTypes `exchangeActiveSync`/`other`), wykluczenia (surowe id; procesor wiąże je z kontami/grupami → reguła `CA_MFA_EXCLUDED`).
- **`tenantPolicies`** — trzy pojedyncze GET-y (`Policy.Read.All`): security defaults, polityka zgód użytkowników (`permissionGrantPoliciesAssigned`), słabe metody MFA (Sms/Voice/Email). Sekcja „Konfiguracja tenanta" w summary.
- **`riskyUsers`** — `/identityProtection/riskyUsers` z filtrem `riskState eq 'atRisk' or 'confirmedCompromised'` (`IdentityRiskyUser.Read.All`, P2). Bez P2 endpoint zwraca błąd → warning, skan jedzie dalej.
- **audit `ApplicationManagement`** — rozszerzony filtr istniejącego kolektora `audit` (to samo `AuditLog.Read.All`): zdarzenia na sekretach/certach → `application.credentialEvents[]` → reguła `APP_CREDENTIAL_ADDED` + twardszy dowód w `APP_PRIV_OWNER_WEAK`.

### Moduły Grupy i Aplikacje (schema 1.2)

Nie wymagają **nowych** scope'ów — pokrywa je `Directory.Read.All` (grupy, właściciele, licencje grupowe, role nadane grupie) i `Application.Read.All` (rejestracje, poświadczenia, uprawnienia). Wyjątki:

- **Liczność członków/gości grup** liczymy przez `GET /groups/{id}/members/$count` z nagłówkiem `ConsistencyLevel: eventual` (advanced query). To best-effort: przy braku uprawnień/błędzie `memberCount`/`guestCount` zostają puste, a powyżej progu `CountCap` (domyślnie 3000 grup) pomijamy zliczanie, by nie obciążać Grapha.
- **Uprawnienia aplikacyjne** czytamy przez `$expand=appRoleAssignments` na `/servicePrincipals` (z fallbackiem bez expand, gdy tenant go odrzuci). `isHighRisk` wyznacza skaner po przecięciu z `rules.yaml → highRiskAppRoles`.
- **Konkretni członkowie grup** — `GET /groups/{id}/members` (bounded: lista przycinana do `MemberCap`, domyślnie 200; pełna liczba dalej z `$count`). Pokrywa `Directory.Read.All` / `GroupMember.Read.All`.
- **Użytkownicy podpięci do aplikacji** — przypisani przez `$expand=appRoleAssignedTo` na `/servicePrincipals` + ci, którzy wyrazili zgodę (`oauth2PermissionGrants.principalId`). Bez nowych scope'ów (`Application.Read.All` + `Directory.Read.All`).

## Rola operatora (tryb delegated)

Minimalnie: **Global Reader** (czyta wszystko, nic nie zmienia). Alternatywa: **Security Reader + Reports Reader**. Operator loguje się interaktywnie, przechodzi MFA — nic nie zostaje w tenancie po skanie.

## Tryb app-only (cykliczny)

Rejestracja aplikacji z **Application permissions** (admin consent) z tej samej listy co wyżej. Preferencja poświadczeń (od najlepszego):

1. **Managed Identity** — gdy skaner biegnie w Azure (Automation/Container). Brak sekretów. `Connect-MgGraph -Identity`.
2. **Federated / Workload Identity** — bez długoterminowych sekretów.
3. **Certyfikat** z Key Vault — `Connect-MgGraph -ClientId -TenantId -CertificateThumbprint`.
4. **Client secret** — ostateczność; świadomie pominięty w szkielecie. Jeśli musisz, pobierz z Key Vault, nie trzymaj w repo.

> Od września 2025 Microsoft wymusza MFA dla automatyzacji opartej o konta użytkownika — to dodatkowy argument za app-only/MI w trybie cyklicznym.

## Licencje tenanta

- **Entra ID P1/P2** — `signInActivity` (`lastSignInDateTime`) zwraca dane. Bez P1/P2 pole jest puste → scoring nieaktywności działa „best-effort" (skaner ustawia `scanContext.premiumLicense=false`, procesor obniża pewność tych reguł).
- **P2** — pełny PIM (eligible/active schedules, aktywacje). Bez P2 część sygnałów PIM będzie niedostępna.

## Uwagi o `signInActivity`

- Najlepiej czytać z endpointu **beta** (`/beta/users?$select=signInActivity`).
- `null` oznacza: konto nigdy się nie logowało **albo** logowanie sprzed kwietnia 2020 (granica zbierania danych). Reguła `NEVER_SIGNED_IN` traktuje `null` ostrożnie (tylko dla kont aktywnych i licencjonowanych).

## Legacy auth: dlaczego widać je mimo Conditional Access

Conditional Access (blokada legacy) **odrzuca** próbę uwierzytelnienia, ale logi `signIns` i tak **rejestrują** tę próbę — ze statusem błędu (typowo `errorCode 53003 = Blocked by Conditional Access`). Dlatego sam fakt wykrycia legacy w logu to norma, nie incydent. AccessGuy rozróżnia to per protokół (`clientAppUsed`):

- **`legacySuccessCount` / „Udane"** (errorCode 0) — protokół legacy **uwierzytelnił** konto = realne ominięcie MFA. Reguła `LEGACY_AUTH_SUCCESS` (high). To trzeba ścigać.
- **próby zablokowane** (success = 0) — `LEGACY_AUTH_BLOCKED` (low), informacyjnie. Tu weryfikujesz, **które** protokoły próbują (raport pokazuje listę + opis), bo część bywa świadomie akceptowana (np. `Authenticated SMTP` dla drukarek/skanerów). Jeśli żaden nie jest potrzebny — domknij na poziomie skrzynek (`Set-CASMailbox`), nie tylko CA.
