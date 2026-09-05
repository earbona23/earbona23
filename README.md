## Eduard Arbona

Security engineering — detection and response, identity, automation. Santo Domingo,
Dominican Republic.

By day I run Defender XDR and Sentinel for a tenant covering several group entities and a
public commercial platform: alert triage, KQL threat hunting, Conditional Access and
privileged identity in Entra ID, Intune across 132 endpoints, and the policies and runbooks
that have to survive an audit. Most of what is here started as something I needed at work
and could not find.

I also build and operate a services marketplace in production, solo, end to end.

---

### The rule everything here follows

Security tooling fails in a specific, quiet way: it reports success without having done
anything. A gate that never ran, a query that came back empty because it was denied, a
scanner that skipped a directory it could not read — all of them look exactly like a clean
result. So every tool in this list is built to the same three rules.

**Read-only by construction, not by intention.** Where a tool touches a live tenant, the
read path physically cannot write — no method parameter, no body, a hardcoded verb — and a
test walks the source and fails the build if that stops being true.

**Three outcomes, never two.** `clean`, `finding`, and *I could not check*. A tool that
only has the first two will always disguise the third as the first, and the day it matters
is the day you believe it.

**A test suite is not evidence until you have watched it fail.** The three newest projects
ship a mutation harness you can run yourself: it breaks the code on purpose, one defect at
a time, and fails if the tests stay green — or if a mutation never applied, which looks
identical to a mutant that survived. Writing that harness for `revtriage` is how I found
that its headline guarantee had been passing on two empty sets.

Every README states what the tool cannot do, in its own section. That part is not modesty.
A tool that oversells its coverage is worse than no tool, because you stop looking.

---

### The Active Defense Trilogy

Three tools, one idea: an intruder who is already inside leaves traces that a vulnerability
scan will never find. Each stands alone; they share a posture, not a library.

| | | |
|---|---|---|
| **Detect** | [entra-tripwire](https://github.com/earbona23/entra-tripwire) | Decoy identities, apps and credentials nothing legitimate should touch — and a false-positive engine so the alert survives contact with a real tenant. `PowerShell` |
| **Analyse** | [revtriage](https://github.com/earbona23/revtriage) | Offline triage of a suspicious file: capability graph, indicators with provenance, an explainable score, STIX 2.1. Never uploads, never executes. `Python` |
| **Contain** | [containment-cut](https://github.com/earbona23/containment-cut) | The cheapest set of actions that *provably* severs the compromise from the crown jewels — with a max-flow optimality certificate. `Python` |

---

### Identity and tenant posture — Microsoft 365 / Entra ID

All read-only. All run on synthetic data with zero setup, so you can see what they do
before deciding whether to point one at a tenant.

- **[identity-blast-radius](https://github.com/earbona23/identity-blast-radius)** — if this
  one account is phished, what does the attacker reach? Roles held, roles one step away via
  PIM, and the path almost nobody models: permissions inherited from apps the account *owns*.
- **[entra-privilege-auditor](https://github.com/earbona23/entra-privilege-auditor)** —
  over-privileged and abandoned app registrations, ranked by exposure. An uncatalogued
  permission scores as *unknown*, never as harmless.
- **[oauth-consent-monitor](https://github.com/earbona23/oauth-consent-monitor)** — illicit
  consent grants. The signal is not one scope, it is the combination: `offline_access` plus
  a data scope, consented by a user rather than an admin, to an app from another tenant.
- **[intune-drift](https://github.com/earbona23/intune-drift)** — diffs two Intune snapshots
  with a security lens. Not *what changed* — which change **weakened** the posture.
- **[EntraHygiene](https://github.com/earbona23/EntraHygiene)** — PowerShell module, five
  read-only cmdlets: stale accounts, privileged accounts without strong MFA, permanent vs
  PIM-eligible roles, Conditional Access gaps. Outputs objects, not text.
- **[m365-tenant-hygiene](https://github.com/earbona23/m365-tenant-hygiene)** — tenant
  hygiene audit over Microsoft Graph, self-contained HTML report.
- **[m365-command-center](https://github.com/earbona23/m365-command-center)** — one-page
  read-only console: failed logins, risky users, service health, mail exfiltration.

### Detection engineering

- **[sentinel-detection-as-code](https://github.com/earbona23/sentinel-detection-as-code)** —
  KQL detections validated with Microsoft's own parser and mapped to ATT&CK against the
  official catalogue, so a technique ID cannot be invented.
- **[detection-coverage](https://github.com/earbona23/detection-coverage)** — coverage matrix
  against MITRE ATT&CK that flags **phantom coverage**: a rule citing a revoked or
  non-existent technique covers nothing, and inflating a map with dead IDs is the exact
  self-deception a coverage map exists to prevent.

### Code and supply chain

- **[secret-scout](https://github.com/earbona23/secret-scout)** — finds secrets in git
  *history*, not just the working tree. Deleting a secret and committing does not remove it.
  Never prints the secret; entropy-gated so people do not switch it off.
- **[blastradius](https://github.com/earbona23/blastradius)** — what breaks if you change
  this? Ranks files by criticality and shows which impacted files have no test.
- **[certadel](https://github.com/earbona23/certadel)** — passive, authorized external
  posture assessment: TLS, headers, cookies, DNS, email auth. Inspects, never exploits.
- **[entraform](https://github.com/earbona23/entraform)** — identity-aware linter for
  Terraform: over-privileged Entra app permissions, dangerous Azure role assignments and
  fail-open Conditional Access, caught in CI before `apply`, not after.

### Writing

- **[security-writeups](https://github.com/earbona23/security-writeups)** — methodology and
  code on Microsoft security engineering. No organization-specific detail, ever.

### Upstream

I send fixes to the tools I depend on, not only to my own. Open pull requests, each a real
defect with a test:
[BloodHound](https://github.com/SpecterOps/BloodHound/pull/3254) (an Azure attack-path edge
that targeted managed identities it cannot actually abuse),
[Prowler](https://github.com/prowler-cloud/prowler/pull/12732) (a CISA ScuBA Entra ID
baseline),
[Maester](https://github.com/maester365/maester/pull/2165),
[Elastic detection-rules](https://github.com/elastic/detection-rules/pull/6729),
[Sigma](https://github.com/SigmaHQ/sigma/pull/6277),
[entra-powershell](https://github.com/microsoftgraph/entra-powershell/pull/1611) and
[msgraph-sdk-python](https://github.com/microsoftgraph/msgraph-sdk-python/pull/1572).

---

### Support this work

Every tool here is MIT and stays free. Four of them (revtriage, entra-tripwire,
containment-cut, vantage) are open-core: a Pro tier adds live-tenant import and gated
execution, and funds the maintained rule catalogues the free engine reads from.

- **Sponsor** → [github.com/sponsors/earbona23](https://github.com/sponsors/earbona23). From
  $5 a month. At $50 you get a Pro license for one tool; at $250, Pro across every tool for
  your whole org.
- **Work with me** → I run read-only Microsoft 365 and Entra ID posture assessments for MSPs
  and their clients, on the same tooling you see here.
  [consulting.arrankago.com](https://consulting.arrankago.com)

---

<sub>Microsoft SC-500 and SC-100 in preparation · Defender XDR · Sentinel · KQL · Entra ID ·
Conditional Access · Intune · Purview · Microsoft Graph · PowerShell · Python</sub>
