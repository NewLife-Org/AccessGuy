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

# AccessGuy — Read-only Microsoft Entra ID (Azure AD) Access Review

🌐 **English** · [Polski](README.pl.md)

**Read-only Microsoft Entra ID access review — from a single sign-in to a board-ready report.**
It connects once (read-only), inventories users, groups and applications, and scores risk — MFA gaps, privileged
roles without MFA, legacy authentication, risky sign-ins, standing roles outside PIM, Conditional
Access coverage and over-privileged app permissions — into a clear **A–F posture report** for
ISO 27001 / NIS2 access reviews and audits.

Author: **Daniel „NewLife" Budyn**
- LinkedIn: https://www.linkedin.com/in/daniel-b-4295a421a/
- GitHub: https://github.com/NewLife-Org/AccessGuy
- YouTube: https://www.youtube.com/@NewLife-org-pl
---

## ▶ Quick start (just run it)

```bash
# Linux / macOS:
sudo pwsh ./NewLife-AccessGuy.ps1
```
```powershell
# Windows (PowerShell 7+):
pwsh .\NewLife-AccessGuy.ps1
```

One launcher walks you through it:
1. pick **[1] Scan** → sign in to the tenant (on Linux: **[2] device code**) → the scanner collects the data,
2. pick **[2] Report** → point it at the scan file → get a ready HTML report.

> **Language.** Everything defaults to **English**. Switch it from the menu via **[L] Language / Język**
> (PL available now, more languages on the way) or with a flag: `pwsh ./NewLife-AccessGuy.ps1 -Lang pl`.
> Directly in the processor: `python -m accessguy_processor process dataset.json --lang pl`.

> **Pre-scan check.** The menu item **[D] Dependencies** (check before scan) shows the package component status,
> the Graph permissions used (with descriptions), whether Python and 7-Zip are present, and write access to the `out/` and `reports/` folders.

That's it. The rest of this document is the details.

---

## What it's for

AccessGuy answers the question that comes up in every audit and ISO 27001 / NIS2 review:

> **"Who has access to what in our Entra ID, and what should we fix first?"**

You connect **once** (read-only, as Global Reader / Global Admin) and the tool:
- inventories all accounts (internal / external / guest), **groups** and **applications**, roles and licenses,
- scores risk against a clear rubric (inactivity, privileged roles without MFA, legacy auth, risky sign-ins, standing roles outside PIM, unused permissions…),
- **correlates the modules with each other** — links identities, groups and applications with sign-in logs and surfaces **named escalation paths** (e.g. "account without MFA → member of a group with the Global Admin role → full access"),
- generates a **readable HTML report** with an **A–F** posture grade, an executive summary, and a **"where to start" action plan**.

**It changes nothing in the tenant.** No write permissions, no secrets on the report side.

---

## How it works — two phases, one file

```
[ TENANT ] --(SCANNER: PowerShell)--> <tenant>_<date>.json --(BUILDER: Python)--> HTML/CSV report
            read-only, at the client       file = contract        scoring + nice report, on your box
```

| Phase | What it does | Where |
|---|---|---|
| **[1] AccessGuy-EntraID-Scanner** | connects to Entra ID (read-only), collects data → `out/<tenant8>_<date>.json` | at the client / in the tenant |
| **[2] AccessGuy-Report-Builder** | reads the scan file, computes scoring, generates the HTML/CSV report | on your box (Python 3) |

The boundary is the **JSON file** (the `contracts/dataset.schema.json` contract). You scan at the client, take the JSON out, and build the report on your own machine — the builder **never touches the tenant**. If the client has no Python, the scanner produces a *lite* HTML report on its own (`out/*.lite.html`).

---

## Step-by-step usage

### Mode [1] — Scan

```bash
sudo pwsh ./NewLife-AccessGuy.ps1     # → pick [1]
```
- Choose sign-in: **[1] browser** (Windows) or **[2] device code** (recommended on Linux).
- With device code you'll see: *"open https://microsoft.com/device and enter code XXXX"* — enter the code, confirm in **Authenticator**.
- After sign-in: a slick logo reveal, live counters of captured data, and a "what we captured" summary.
- Output: `out/<tenant8>_<date>.json` (+ `.lite.html`).
- At the end (interactively) you can **optionally** encrypt the dataset into a password-protected archive (7-Zip / AES-256). Note: an encrypted dataset cannot be read by the builder until you extract it.

Directly, without the launcher:
```bash
pwsh ./scanner/Invoke-AccessGuyScan.ps1 -DeviceCode -LiteReport
```

### Mode [2] — Report

```bash
sudo pwsh ./NewLife-AccessGuy.ps1     # → pick [2]
```
- The builder creates a Python environment (venv) on its own, installs dependencies, and **lists the scan files** from `out/` to choose from.
- Output: **one interactive HTML report** `reports/<TenantName>_<date>.html` — a posture grade on top of four tabs (Accounts / Groups / Applications / Conditional Access) — plus per-module `.csv` exports.
- After building you can **optionally** pack the report + dataset into a single encrypted archive (7-Zip / AES-256); the password is shown **once** and stored nowhere.

Directly:
```bash
cd processor && python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/python -m accessguy_processor build --dir ../out --out ../reports
```

### Scheduled mode (app-only, no human)
```powershell
./scanner/Invoke-AccessGuyScan.ps1 -AuthMode App -UseManagedIdentity
```

---

## What's in the report

- **A–F posture grade** + an executive summary (the worst accounts on top).
- **Escalation paths** — named attack chains with evidence from the logs (identity × group × application correlation).
- **"Where to start" action plan** — every finding from the three modules aggregated into a prioritized task list, with deep links to specific cards.
- **Tenant profile:** number of accounts, Global Admins, accounts without MFA, **MFA coverage %**, M365 licenses, **10 most recently created accounts**, **legacy auth by protocol**.
- **Conditional Access & tenant posture** — every CA policy with its resolved scope (which users/apps it targets, who is excluded), whether MFA is enforced **broadly** (all users + all apps) or only through **narrowly scoped** policies, legacy-auth blocking, report-only policies, accounts excluded from MFA, and risky users from Identity Protection.
- **Accounts / groups / applications by risk** — an expandable card per object (click → full details), with filtering and search: last sign-in, password change, MFA, licenses, **30-day activity** (sign-ins / failed / night 20:00–04:00 / risky / legacy / top apps), roles, members/owners, flags with recommendations.
- A rich scoring rubric (accounts + groups + applications + **correlation rules**), including: inactive account, guest/external with a privileged role, **standing roles outside PIM**, **permissions held but unused**, **privileged account without MFA**, **legacy auth (bypasses MFA)**, **risky sign-ins**, **hidden admin via a group**, **attack signals on a privileged account**, **weak owner of an app-only application**, consent to high-risk applications. Full list and thresholds: [`contracts/rules.yaml`](contracts/rules.yaml).

---

## Prerequisites

**Scan (phase 1):**
- PowerShell 7+ (`pwsh`)
- the `Microsoft.Graph.Authentication` module:
  ```powershell
  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force
  ```
- an operator account with the **Global Reader** role (or Global Admin / Security Reader + Reports Reader)
- an **Entra ID P1/P2** tenant for full sign-in data (`signInActivity`, signIns)

**Report (phase 2):**
- Python 3.11+ (the builder creates the venv and pulls dependencies on its own)
- (optional PDF) on Debian/Kali: `sudo apt install -y libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev`

**Output protection (optional):**
- **7-Zip** (`7z` / `7za` / `7zz`, on Windows also the default `7-Zip` install) — only if you want to encrypt the dataset/reports. Without it everything still works; files stay in plaintext.

---

## Permissions (always read-only)

`User.Read.All`, `Directory.Read.All`, `AuditLog.Read.All`, `RoleManagement.Read.All` (required) + `Application.Read.All`, `UserAuthenticationMethod.Read.All`, `Policy.Read.All`, `IdentityRiskyUser.Read.All` (recommended). **No `*.ReadWrite.*`.**

> You sign in once as Global Admin/Reader — that's enough. With device-code sign-in the token lives only in process memory (`-ContextScope Process`); it never lands in the keyring.

---

## Repo structure

```
NewLife-AccessGuy.ps1     ← main launcher (start here)
scanner/                  ← SCAN phase (PowerShell): Invoke-AccessGuyScan.ps1 + lib/
processor/                ← REPORT phase (Python): src/accessguy_processor/ + tests
contracts/                ← contract: dataset.schema.json + rules.yaml + sample
```


---

## License

Use it, modify it, deploy it — go ahead. But **do not impersonate the author or claim authorship**. Full text: [`LICENSE`](LICENSE).

> *Use it as you like — but if you impersonate and steal it, you risk your own legs.* — NewLife
