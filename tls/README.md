# TLS-Dateien

Für direktes TLS im Container werden hier folgende Dateien erwartet:

- `server.crt`: Serverzertifikat inklusive erforderlicher Zwischenzertifikate
- `server.key`: unverschlüsselter privater Schlüssel, nur für den Container lesbar

Die Pfade werden in `.env` als `/tls/server.crt` und `/tls/server.key` gesetzt.

Wird TLS bereits von einem Reverse Proxy terminiert, bleiben `GPO_SERVER_TLS_CERT` und
`GPO_SERVER_TLS_KEY` in `.env` leer. Der Container lauscht dann intern per HTTP auf Port
8443. Der Port sollte in diesem Fall nur an Loopback oder ein internes Docker-Netz
gebunden werden.
