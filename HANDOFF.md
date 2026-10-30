# HANDOFF: stathe, stand van zaken op 30 oktober 2026

Dit bestand is de overdracht van een lange sessie (Claude Code op het web) naar
VS Code. Lees het helemaal voordat je iets bouwt. Het noemt wat besloten is,
wat gecontroleerd is, wat niet, en wat de volgende stappen zijn.

Repo: https://github.com/stathe-io/stathe (Go 1.24, Apache-2.0, private beta,
~21 commits, v0.3.0). Image: `ghcr.io/stathe-io/stathe` met tags `v0.3.0` en
`latest`. De digest op de packagepagina was `sha256:ca435649e8a650bd6fca19ad7aac49ce83fe515aa6e8b2093b23cfd009d59856`;
controleer die opnieuw, want de image werd net daarvoor handmatig gepusht.

## 1. Wat stathe is

Read-only Kubernetes-assessment: één commando, niets geïnstalleerd, niets
gewijzigd. Commando's: `preflight`, `check`, `report`, `baseline`, `compliance`.
Zes checks (SC-01 netwerkscheiding, SC-04 credentials in ConfigMaps, SC-05
privileges/hostPath, SC-06 cluster-admin, SC-07 mutable image tags, SC-09 limits).
Geen SC-02, SC-03, SC-08, SC-10 (gaten staan bewust in de nummering).

Principes in de repo die behouden moeten blijven:

- Finding-ID's (`SC-nn`) veranderen nooit van betekenis en worden nooit hergebruikt.
- Niets stil onderdrukken of weglaten: een run die 17 meldt terwijl hij er 2
  onderdrukte, is een leugen. Malformed input is een fout, geen skip.
- `baseline` past nooit iets toe. `warn/` (veilig) en `enforcing/` (change window,
  met rollback) blijven gescheiden. Geen `enforce`-label in `warn/`, ook niet in comments.
- Geen certificering of compliance-claims. Het rapport zegt dat op de voorkant.
- Een test is pas af als hij gezien is falen om de juiste reden.
- Toon: nuchter, eerlijk over beperkingen.

## 2. Positionering (besloten richting)

Het gaat niet om weer een scanner. Kubescape (CNCF-incubatie, ARMO, Apache-2.0,
NSA-CISA/MITRE/CIS, JSON/JUnit/SARIF/HTML/PDF/CSV, optioneel operator met
continue scans en eBPF) en Trivy zijn breder en gratis. Daar concurreren we niet.

De wig: een kleine, volledig controleerbare assessmentkit voor consultants bij
gereguleerde Nederlandse/Europese klanten (NIS2/Cbw, BIO, DORA, ISO 27001),
inclusief omgevingen zonder internet. De waarde zit in het pakket rond de
checks: vooraf goed te keuren minimale rechten, preflight, rapport dat een
auditor leest, veilige baseline, uitzonderingenregister, eerlijke NIS2-dekking.
Trivy/Kubescape-uitvoer moet straks inleesbaar zijn, zodat die tools leveranciers
zijn en geen rivalen. De tool is ook een visitekaartje voor opdrachten en trainingen.

Eerlijke kanttekening: de tagline "See how far an attacker can get" belooft meer
dan zes statische configuratiechecks leveren. Dat is de reden voor roadmap-punt 1.

## 3. Wat is gevonden bij het lezen van de code

Alles hieronder is gelezen, niet gedraaid, tenzij anders vermeld.

1. **ConfigMap-claim was te sterk.** README en `readonly-rbac.yaml` zeiden "never
   reads a value of any kind". De Kubernetes-API kan geen keys-only lijst geven,
   dus de waarden komen wel mee in de response; `fromUnstructured` in
   `internal/scan/cluster.go` gooit ze direct weg. Teksten zijn aangepast.
2. **Path traversal en YAML-injectie in `baseline --manifests`.** Het namespace uit
   een manifest werd ongevalideerd een bestandsnaam (`warn/%s-pod-security.yaml`).
   `namespace: ../../../tmp/x` schreef buiten `--out`; een newline voegde YAML toe.
   Gerepareerd (zie patch) met `ValidNamespace`, `InvalidNamespaces` en een pad-controle
   in `main.go`. **Geverifieerd:** de originele code leverde `warn/../../../tmp/x-...yaml`;
   de nieuwe tests in `internal/baseline/hostile_test.go` slagen (gedraaid in een
   stdlib-only kopie van de package).
3. **`preflight` doet één `create`** (SelfSubjectAccessReview). Stateless en standaard
   toegestaan voor elke geauthenticeerde identiteit, maar zichtbaar in de audit-log.
   Docs zijn daarop aangepast; zeg het de klant vooraf.
4. **Vermoedelijk gat in SC-06 (NIET geverifieerd).** `isPlatformSubject` slaat elk
   subject over waarvan de naam met `system:` begint. Dat omvat ook
   `system:serviceaccounts`, `system:serviceaccounts:<ns>`, `system:authenticated`
   en `system:unauthenticated`. Een cluster-admin-binding daarop zou dan ten
   onrechte onzichtbaar zijn. Eerst een falende test schrijven, dan repareren:
   alleen bekende platformnamen filteren (`system:masters`, `system:kube-*`,
   `system:node*`, ...) en groepsbindings juist melden.
5. **Afhankelijkheden zijn oud.** `go.mod`: client-go/apimachinery v0.31.3,
   `golang.org/x/net` v0.26.0. Waarschijnlijk met bekende kwetsbaarheden; bevestigen
   met `govulncheck`.
6. **Zelfconsistentie:** stathe's eigen SC-07 keurt tags af, maar Dockerfile-basisimages
   en CI-actions stonden op tags en de image werd op tag gepubliceerd.
7. **Report gebruikt `html/template`** (auto-escaping): goed. Er is nog geen test met
   een vijandige resourcenaam.

## 4. De patch (`stathe-improvements.patch`)

Toepassen: `git checkout -b hardening && git apply stathe-improvements.patch`.
Bevat: ConfigMap-correcties, sectie "What stathe is for" in de README, pad- en
namespace-fix + test, `SECURITY.md`, `docs/threat-model.md`, `.github/workflows/ci.yml`
en `release.yml` (cosign keyless, SBOM, provenance, binaries met SHA256SUMS),
`.github/dependabot.yml`, `internal/scan/fuzz_test.go`, Dockerfile (`go mod verify`,
versie-/revisielabels), Makefile (`make vuln`, `make fuzz`), README-sectie
"Verify what you run", en image-tag `v0.3.0` in de pipelinevoorbeelden.

**Niet gecontroleerd:** `cmd/stathe/main.go` en `fuzz_test.go` zijn niet gecompileerd,
want de Go-modules waren in die omgeving geblokkeerd. De workflows en de
cosign/gh-attestation-commando's zijn nooit uitgevoerd. Actions staan nog op tags en
basisimages op tags (TODO's staan in de bestanden). Draai eerst
`gofmt -l . && go vet ./... && go test -race ./...`.

## 5. Roadmap (volgorde)

1. **Aanvalsketens** (maakt de tagline waar). Nieuw `internal/scan/paths.go`; een `Path`
   verwijst naar bestaande finding-ID's, met eigen reeks `AP-nn`.
   - Nieuwe resources, alleen `list`: `services` en `ingresses` (in `wanted` in
     `cluster.go` en in `readonly-rbac.yaml`; README "six resource types" wordt acht;
     zeg het ook tegen de beheerder).
   - Keten: Service/Ingress -> Workload (selector vs. pod-template-labels, zelfde
     namespace) -> privileged/hostPath (node) en/of ServiceAccount (`serviceAccountName`,
     anders `default`) -> cluster-admin via ClusterRoleBinding.
   - Per finding tellen in hoeveel paden hij zit; het rapport noemt de ene wijziging
     die de meeste paden breekt. Bovenaan het rapport: top drie paden.
   - Taal: "bereikbaar volgens de configuratie", nooit "exploiteerbaar". Een
     NetworkPolicy is een verzachtende factor, geen reden om het pad te schrappen.
   - Tests: ClusterIP telt niet als blootstelling; `automountServiceAccountToken: false`
     breekt de tokenhop; selector zonder match geeft geen pad; platform-SA niet
     ketenen; `default`-SA-geval; voeg een keten toe aan `cluster/northwind`.
   - JSON-formaat verandert van lijst naar object (`findings` + `paths`): versie ophogen,
     vermelden op de cover van het rapport.
2. **`stathe diff`** (hertest, vóór/na) en SARIF-uitvoer.
3. **Importeren van Trivy/Kubescape-uitvoer** in het rapport (`report --import`).
4. NIS2/Cbw/BIO-mapping verdiepen als echte reden voor Nederlandse klanten.
5. SC-06-groepsfix (zie 3.4), eventueel eerder dan 1 omdat het klein is.

## 6. Bouwstappen voor vandaag (samenvatting)

Patch toepassen en testen; handmatig `baseline --manifests` met vijandig namespace
proberen (verwacht: weigering); nulmeting op het PoC-cluster met de ongewijzigde
v0.3.0; GitHub-instellingen (private vulnerability reporting, Dependabot,
branch protection, read-only workflow-token); PR + CI; dependencies bijwerken;
Actions op SHA en basisimages op digest pinnen (`pinact`); proefrelease
`v0.3.1-rc.1` en de verificatiecommando's uit `SECURITY.md` echt draaien; fuzz
20 minuten op de achtergrond.

## 7. Openstaand uit het gesprek

- De nulmeting op het PoC-cluster (preflight, `check --json`, rapport, en
  `kubectl get clusterrolebindings -o wide | grep -i "system:"` voor het SC-06-vermoeden).
  Resultaten worden geanonimiseerd teruggekoppeld; daarop baseren we de volgende bouwstap.
- Het conceptmail aan de clusterbeheerder (rechten via `cluster/readonly-rbac.yaml`,
  kubeconfig voor de ServiceAccount, uitleg over de ConfigMap-waarden). Noem daar ook
  de `SelfSubjectAccessReview` van `preflight`.
- Het hele bouwen/testen van de patch: nog niet gedaan.

## 8. Beperkingen van de vorige omgeving (niet herhalen)

Geen GitHub-koppeling (alleen read-only clone), Go-modules niet te downloaden, officiële
Claude Code-docs niet bereikbaar. Alles in dit bestand dat "niet geverifieerd" heet,
moet in jouw omgeving eerst bewezen worden voordat je erop bouwt.
