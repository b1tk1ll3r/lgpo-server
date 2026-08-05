# GPO Distributor

Ein kleines, dateibasiertes System zur zentralen Verteilung von Microsoft-GPO-Sicherungen an Windows-Server, die nicht Mitglied derselben Active-Directory-Domäne sind.

Das Projekt besteht aus:

- `gpo-server`: Go-Backend mit eingebetteter WebUI für Richtlinien, Versionen, Profile, Artefakte und Client-Status.
- `gpo-agent`: Windows-Agent, der ein Profil abruft, Artefakte prüft, lokale Richtlinien sichert und die GPO-Sicherungen mit `LGPO.exe` anwendet.
- `gpoctl`: Admin-CLI zum Hochladen von Sicherungen und Verwalten von Profilen.
- WebUI unter `/ui/` für die vollständige tägliche Administration im Browser.
- PowerShell-Skripten für automatisierten AD-Export/Upload und die Agent-Installation als geplante Aufgabe.

## Architektur

```text
+----------------------+                 +----------------------+
| AD/GPMC / Backup-GPO |                 | Browser / WebUI      |
+----------+-----------+                 +----------+-----------+
           | ZIP + Admin-Token                      | HTTPS
           +-------------------+   +----------------+
                               v   v
                         +-----+---+--------+
                         | gpo-server       |
                         | Policies         |
                         | Versionen        |
                         | Profile          |
                         | Clientstatus     |
                         +--------+---------+
                                  |
                    Manifest/ZIP  |  Statusbericht
                                  |
                                  v
                         +--------+---------+
                         | Windows Standalone|
                         | gpo-agent (SYSTEM)|
                         | LGPO.exe /g       |
                         | gpupdate /force   |
                         +-------------------+
```

Ein **Policy-Objekt** enthält mehrere unveränderliche Versionen. Ein **Profil** ist eine geordnete Liste von Policy-Objekten. Konflikte werden durch die Reihenfolge aufgelöst: Die zuletzt angewendete Richtlinie gewinnt.

## Wichtige fachliche Grenzen

Dieses System ersetzt nicht die komplette Active-Directory-Gruppenrichtlinienverarbeitung. Auf einem nicht domänengebundenen System gibt es insbesondere keine OU-Verknüpfungen, Vererbung, Security Filtering, Loopback Processing oder WMI-Filterung. Das Profil und seine Reihenfolge ersetzen lediglich die Auswahl und Reihenfolge der anzuwendenden lokalen Richtlinien.

`LGPO.exe` eignet sich offiziell für lokale Richtlinien und nicht domänengebundene Systeme. Es unterstützt unter anderem `Registry.pol`, Sicherheitsvorlagen und erweiterte Überwachungsrichtlinien. Nicht jede Gruppenrichtlinienerweiterung und nicht jedes Group Policy Preference-Element wird dadurch automatisch funktionsgleich umgesetzt.

Weitere Grenzen:

- Skriptdateien, MSI-Pakete, Zertifikate, Dateien oder andere externe Abhängigkeiten müssen separat auf dem Zielsystem vorhanden sein.
- Domänenkonten, Domänen-SIDs und Netzwerkpfade aus der Quell-GPO können auf Standalone-Systemen ungültig sein.
- Das Anwenden ist standardmäßig **merge-orientiert**. Wird eine Einstellung aus einer neuen GPO-Version entfernt, ist sie im Backup nur noch abwesend und kann lokal bestehen bleiben. Für eine saubere Deaktivierung sollte die Richtlinie die Einstellung ausdrücklich zurücksetzen oder ein separates Deconfiguration-Policy-Objekt verwendet werden.
- Eine Member-Server-Baseline kann auf Standalone-Systemen lokale Remoteanmeldung blockieren. Vor Produktionseinführung immer mit Snapshot und Out-of-Band-/Konsolenzugriff testen.

## Versionierung

Beim Upload berechnet der Server zwei Hashes:

1. `artifact_sha256`: SHA-256 über die exakte ZIP-Datei.
2. `semantic_sha256`: kanonischer Hash über die tatsächlichen Dateien unter `DomainSysvol/GPO`, sortiert nach Windows-unabhängig normalisiertem Pfad.

Dadurch führen geänderte Sicherungszeitpunkte, Backup-IDs, Kommentare oder Reportdateien nicht automatisch zu einer neuen Version. Ist der semantische Hash bereits vorhanden, antwortet der Server mit der existierenden Version und `"created": false`. Mit `gpoctl upload -force` kann für Sonderfälle trotzdem eine neue Version angelegt werden, etwa wenn nur importrelevante Backup-Metadaten geändert wurden.

## Sicherheitsmodell

- HTTPS ist für Clients zwingend; unverschlüsseltes HTTP ist nur mit einer expliziten Testoption möglich.
- Admin- und Client-Zugriffe verwenden getrennte Bearer-Tokens.
- Die WebUI tauscht das Admin-Token gegen eine acht Stunden gültige, mit dem Admin-Token signierte `HttpOnly`-Session aus; das Admin-Token wird nicht im Browser gespeichert.
- Schreibende WebUI-Aufrufe sind zusätzlich mit einem zufälligen CSRF-Token geschützt.
- Die Oberfläche setzt eine restriktive Content Security Policy, `SameSite=Strict`, `X-Frame-Options: DENY` und weitere Browser-Sicherheitsheader.
- Das Manifest wird zusätzlich mit HMAC-SHA-256 signiert.
- Der Agent prüft Größe und SHA-256 jedes ZIP-Artefakts vor dem Entpacken.
- ZIP-Pfade, Symlinks, Dateianzahl und entpackte Gesamtgröße werden begrenzt.
- Vor jeder Änderung erstellt der Agent mit `LGPO.exe /b` eine lokale Rollback-Sicherung.
- Bei einem Importfehler versucht der Agent automatisch, die vorherige lokale Richtlinie wiederherzustellen.
- Agent-Konfiguration, Tokens, Cache und Rollback-Dateien sollten nur für `SYSTEM` und lokale Administratoren lesbar sein. Das Installationsskript setzt entsprechende ACLs.

Tokens und Signaturschlüssel sollten lang und zufällig sein, zum Beispiel jeweils mindestens 32 zufällige Bytes.

## Voraussetzungen

### Backend

- Go 1.23 oder ein Container-Host.
- TLS-Zertifikat, entweder direkt im Server oder an einem Reverse Proxy.

### Windows-Client

- Windows Server 2016 oder neuer wird als Ziel angenommen.
- Lokale Administratorrechte beziehungsweise Ausführung als `SYSTEM`.
- `LGPO.exe` aus dem Microsoft Security Compliance Toolkit. Die Binärdatei wird aus Lizenz- und Aktualitätsgründen nicht in diesem Repository mitgeliefert.

Offizielle Microsoft-Quellen:

- Security Compliance Toolkit und LGPO: https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/security-compliance-toolkit-10
- Download Center: https://www.microsoft.com/download/details.aspx?id=55319
- `Backup-GPO`: https://learn.microsoft.com/powershell/module/grouppolicy/backup-gpo

## Build

Linux/macOS:

```bash
make test
make build VERSION=0.2.1
```

Windows PowerShell:

```powershell
.\scripts\Build.ps1 -Version 0.2.1
```

Erzeugte Dateien:

```text
bin/gpo-server
bin/gpoctl
bin/gpo-agent-windows-amd64.exe
bin/gpoctl-windows-amd64.exe
```

## Backend starten

### Direkt

```bash
export GPO_SERVER_ADMIN_TOKEN="<zufälliger-admin-token>"
export GPO_SERVER_CLIENT_TOKEN="<zufälliger-client-token>"
export GPO_SERVER_SIGNING_KEY="<zufälliger-signaturschlüssel>"
export GPO_SERVER_TLS_CERT="/etc/gpo-distributor/server.crt"
export GPO_SERVER_TLS_KEY="/etc/gpo-distributor/server.key"

./bin/gpo-server -listen :8443 -data /var/lib/gpo-distributor
```

### Docker Compose

Im Projektwurzelverzeichnis liegen ein Multi-Stage-`Dockerfile`, `compose.yml`,
`.dockerignore` und eine `.env.example`. Das Image baut den Server aus dem
Quellcode, läuft als nicht privilegierter Benutzer und speichert ausschließlich
`/data` in einem benannten Docker-Volume. Temporäre Uploads landen unter
`/data/.tmp`, damit große GPO-Pakete nicht den Container-Arbeitsspeicher als
`tmpfs` belegen.

```bash
cp .env.example .env
chmod 600 .env

# In .env drei voneinander unabhängige, zufällige Geheimnisse eintragen.
# Beispielsweise jeweils separat erzeugen:
openssl rand -base64 48

# Bei direktem TLS Zertifikat und Schlüssel ablegen:
mkdir -p tls
# cp /pfad/server.crt tls/server.crt
# cp /pfad/server.key tls/server.key

docker compose config
docker compose up -d --build
docker compose ps
docker compose logs -f gpo-server
```

Bei einem bereits vorhandenen Volume aus einer älteren Container-Version müssen
dessen Besitzrechte gegebenenfalls einmalig auf UID/GID `10001` angepasst werden:

```bash
docker run --rm -u 0 \
  -v gpo-distributor-data:/data \
  alpine:3.21 chown -R 10001:10001 /data
```


Die WebUI ist anschließend standardmäßig unter
`https://<server>:8443/ui/` erreichbar. Der Healthcheck verwendet
`/healthz` und erkennt automatisch, ob internes HTTP oder HTTPS konfiguriert
ist.

Für TLS an einem Reverse Proxy werden in `.env` beide TLS-Pfade leer gesetzt:

```dotenv
GPO_SERVER_TLS_CERT=
GPO_SERVER_TLS_KEY=
```

In diesem Fall sollte `GPO_SERVER_BIND_ADDRESS` auf `127.0.0.1` gesetzt oder
der Port ausschließlich in einem internen Docker-Netz veröffentlicht werden.
Geheimnisse werden nicht in `compose.yml` hinterlegt; Compose bricht den Start
ab, wenn Admin-Token, Client-Token oder Signaturschlüssel fehlen.

Nützliche Betriebsbefehle:

```bash
# Nur das Image neu bauen und den Server ersetzen
docker compose up -d --build --no-deps gpo-server

# Datenvolume sichern
docker run --rm \
  -v gpo-distributor-data:/data:ro \
  -v "$PWD:/backup" \
  alpine:3.21 tar -czf /backup/gpo-data-backup.tgz -C /data .

# Server stoppen; das persistente Volume bleibt erhalten
docker compose down
```

## WebUI verwenden

Nach dem Start des Backends ist die Verwaltung unter folgender Adresse erreichbar:

```text
https://gpo.example.org:8443/ui/
```

Zur Anmeldung wird derselbe Admin-Token verwendet wie bei `gpoctl`. Der Browser erhält danach nur eine `HttpOnly`-Session; der Token wird weder in `localStorage` noch in `sessionStorage` abgelegt.

Die Oberfläche bietet:

- Dashboard mit Anzahl der Richtlinien, Versionen, Profile und Clients sowie Client-Gesundheit.
- Upload neuer Policy-Objekte und Versionen einschließlich Notiz und optionalem `force`.
- Anzeige von semantischem Hash, Artefaktgröße, Dateizahlen und Versionshistorie.
- Abruf und kontrolliertes Löschen einzelner ZIP-Artefakte oder kompletter Policy-Objekte.
- Erstellen, Bearbeiten, Sortieren und Löschen geordneter Profile mit `latest` oder fest angehefteten Versionen.
- Suche und Filterung der letzten Clientmeldungen sowie Entfernen veralteter Statusdatensätze.

Das Löschen einer Policy ist gesperrt, solange sie von einem Profil referenziert wird. Eine fest angeheftete Version kann ebenfalls erst gelöscht werden, nachdem das betreffende Profil angepasst wurde. Die letzte Version eines Policy-Objekts wird nicht einzeln gelöscht; dafür wird das gesamte Policy-Objekt entfernt.

Bei TLS-Terminierung an einem Reverse Proxy muss dieser `X-Forwarded-Proto: https` setzen, damit das Session-Cookie als `Secure` markiert wird. Der Backend-Port sollte dann nur vom Reverse Proxy erreichbar sein. Ohne TLS darf die WebUI ausschließlich in einem isolierten Testnetz verwendet werden.

## GPO-Sicherung hochladen

### Vorhandene GPMC-Sicherung

Der ZIP-Inhalt sollte direkt so beginnen:

```text
manifest.xml
{BACKUP-GUID}/
  backup.xml
  bkupInfo.xml
  gpreport.xml
  DomainSysvol/GPO/...
```

Beim Komprimieren nicht unnötig mehrere äußere Verzeichnisse hinzufügen. Der Agent erkennt einen üblichen zusätzlichen Wrapper-Ordner trotzdem automatisch.

```powershell
.\gpoctl-windows-amd64.exe upload `
  -server https://gpo.example.org:8443 `
  -token $env:GPO_ADMIN_TOKEN `
  -policy windows-firewall `
  -file C:\GPO\windows-firewall.zip `
  -note "Change CHG-2026-0042"
```

Optionaler Sonderfall: trotz identischem semantischem Hash eine Version erzwingen:

```powershell
.\gpoctl-windows-amd64.exe upload `
  -server https://gpo.example.org:8443 `
  -token $env:GPO_ADMIN_TOKEN `
  -policy windows-firewall `
  -file C:\GPO\windows-firewall.zip `
  -force
```

### Automatischer Export aus AD und Upload

```powershell
.\scripts\Export-And-Publish.ps1 `
  -GpoName 'Server - Windows Firewall' `
  -PolicyName 'windows-firewall' `
  -ServerUrl 'https://gpo.example.org:8443' `
  -AdminToken $env:GPO_ADMIN_TOKEN `
  -GpoCtl '.\bin\gpoctl-windows-amd64.exe' `
  -Note 'Change CHG-2026-0042'
```

Das Skript verwendet `Backup-GPO`, erstellt ein ZIP mit korrektem Sicherungswurzelverzeichnis und lädt es hoch. Bei unverändertem Richtlinieninhalt wird keine neue Version erzeugt.

## Profil erstellen

Das folgende Profil verwendet jeweils die aktuelle Version. Die Reihenfolge ist relevant:

```powershell
.\gpoctl-windows-amd64.exe profile-set `
  -server https://gpo.example.org:8443 `
  -token $env:GPO_ADMIN_TOKEN `
  -name standalone-servers `
  -policy base-hardening@latest `
  -policy audit-policy@latest `
  -policy windows-firewall@latest
```

Eine Version kann auch fest angeheftet werden:

```text
-policy base-hardening@v20260805-071500-a1b2c3d4e5
```

`latest` wird bei jedem Manifestabruf auf die neueste vorhandene Version aufgelöst. Sobald eine neue Version hochgeladen wurde, ändert sich automatisch die Profil-Generation und die Clients erkennen das Update.

## Agent installieren

1. `LGPO.zip` aus dem offiziellen Microsoft Security Compliance Toolkit herunterladen und `LGPO.exe` extrahieren.
2. Agent-Binärdatei und `LGPO.exe` auf den Zielserver kopieren.
3. Als Administrator ausführen:

```powershell
.\scripts\Install-Agent.ps1 `
  -AgentExe '.\bin\gpo-agent-windows-amd64.exe' `
  -LGPOExe '.\LGPO.exe' `
  -ServerUrl 'https://gpo.example.org:8443' `
  -Profile 'standalone-servers' `
  -ClientToken '<client-token>' `
  -SigningKey '<signaturschlüssel>' `
  -IntervalMinutes 15
```

Das Skript:

- installiert Agent und `LGPO.exe` unter `%ProgramFiles%\GPO-Distributor`,
- legt die geschützte Konfiguration unter `%ProgramData%\GPO-Distributor\agent.json` ab,
- registriert eine geplante Aufgabe als `SYSTEM`,
- startet einen ersten Synchronisationslauf.

Manueller Test:

```powershell
& 'C:\Program Files\GPO-Distributor\gpo-agent.exe' `
  -config 'C:\ProgramData\GPO-Distributor\agent.json' `
  -once
```

## Update-Ablauf

1. Eine GPO wird in AD geändert.
2. Die Sicherung wird erneut hochgeladen.
3. Der Server erkennt anhand des semantischen Hashes, ob sich wirksame Richtliniendateien geändert haben.
4. Ein Profil mit `@latest` erhält automatisch eine neue Generation.
5. Der Agent ruft das signierte Manifest ab.
6. Nur noch nicht gecachte ZIP-Dateien werden heruntergeladen.
7. Der Agent sichert die aktuelle lokale Richtlinie.
8. Alle Profil-Policies werden in definierter Reihenfolge mit `LGPO.exe /g` importiert.
9. `gpupdate /force` wird ausgeführt.
10. Der Agent speichert seinen Zustand und meldet Erfolg oder Fehler an das Backend.

## Admin-Abfragen

```bash
gpoctl policies -server https://gpo.example.org:8443 -token "$GPO_ADMIN_TOKEN"
gpoctl profiles -server https://gpo.example.org:8443 -token "$GPO_ADMIN_TOKEN"
gpoctl clients  -server https://gpo.example.org:8443 -token "$GPO_ADMIN_TOKEN"
```

## API-Übersicht

| Methode | Pfad | Rolle | Zweck |
|---|---|---|---|
| `POST` | `/api/v1/admin/policies/{name}/versions` | Admin | GPO-ZIP hochladen |
| `DELETE` | `/api/v1/admin/policies/{name}` | Admin | Policy mit allen Versionen löschen |
| `DELETE` | `/api/v1/admin/policies/{name}/versions/{version}` | Admin | Einzelne, nicht referenzierte Version löschen |
| `GET` | `/api/v1/admin/policies/{policy}/versions/{version}/artifact` | Admin | ZIP-Artefakt administrativ abrufen |
| `GET` | `/api/v1/admin/policies` | Admin | Policies und Versionen auflisten |
| `PUT` | `/api/v1/admin/profiles/{name}` | Admin | Profil setzen |
| `DELETE` | `/api/v1/admin/profiles/{name}` | Admin | Profil löschen |
| `GET` | `/api/v1/admin/profiles` | Admin | Profile auflisten |
| `GET` | `/api/v1/admin/clients` | Admin | Letzten Clientstatus auflisten |
| `DELETE` | `/api/v1/admin/clients/{id}` | Admin | Gespeicherten Clientstatus entfernen |
| `POST` | `/ui/api/session` | WebUI | Admin-Session erstellen |
| `GET` | `/ui/api/session` | WebUI | Session und CSRF-Token lesen |
| `DELETE` | `/ui/api/session` | WebUI | Session beenden |
| `GET` | `/api/v1/profiles/{name}/manifest` | Client | Signiertes, aufgelöstes Manifest |
| `GET` | `/api/v1/artifacts/{policy}/{version}` | Client | Unveränderliches ZIP herunterladen |
| `POST` | `/api/v1/client/report` | Client | Anwendungsstatus melden |
| `GET` | `/healthz` | öffentlich | Health Check |

## Datenhaltung und Backup

Der Server verwendet absichtlich keine externe Datenbank:

```text
data/
  catalog.json
  artifacts/
    policy-name/
      version.zip
```

Für ein Server-Backup müssen `catalog.json` und `artifacts/` konsistent zusammen gesichert werden. Das Verzeichnis kann auf einem verschlüsselten Volume liegen. Schreibzugriff darf ausschließlich der Serverprozess besitzen.

## Betriebsempfehlungen

- Richtlinien zuerst auf einem repräsentativen Snapshot-Klon testen.
- Für Standalone-Server immer eine lokale oder Out-of-Band-Anmeldemöglichkeit vorhalten.
- Client-Token regelmäßig rotieren. Bei Rotation Agent-Konfiguration kontrolliert aktualisieren.
- Signaturschlüssel getrennt vom Client-Token behandeln.
- Backend-Zugriff zusätzlich per Netzwerk-ACL auf erwartete Quellnetze begrenzen.
- Ein eigenes Profil pro Serverrolle verwenden, zum Beispiel `standalone-web`, `standalone-sql` und `standalone-management`.
- Änderungen über Change-ID im Upload-`note` dokumentieren.
