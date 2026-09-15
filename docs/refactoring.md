# Refactoring-Plan: cmdcode2api CLI-Kompatibilität & Account-Pool

refactoring um alle anti-detection Mechanismen des offiziellen CLI-Clients zu berücksichtigen.
basierend auf: https://github.com/MAXeaglet/commandcode-proxy

## Entscheidungsstand (2026-09-12)
Ist-Stand: Alle 15 Anti-Detection-Mechanismen wurden im Code inventarisiert (siehe Ist-Stand-Audit) — **0 von 15 sind vollständig vorhanden**. Die fünf daraus abgeleiteten Blocker sind entschieden; die Tasks und Akzeptanzkriterien stehen in "Anti-Detection: Tasks & Akzeptanzkriterien".

| # | Frage | Entscheidung | Ort |
| --- | --- | --- | --- |
| 1 | Wofür gilt die `user_…`-Regex? | Nur für **Upstream-Account-Keys**, strikt auf allen Schreibpfaden; beim Laden einer bestehenden `config.yaml` nur `[WARN]`. Lokale Client-Keys bleiben `ccgw-…` | AD-5.1a/1b |
| 2 | `x-api-key`? | Nur im Client-Pfad ergänzen; Admin-Auth bleibt Bearer-only; CORS-Preflight muss den Header erlauben | AD-5.1b |
| 3 | 30s/90s vs. 600s? | Beides sind **Idle-Watchdogs** (30s Streaming, 90s `stream:false`, Reset pro Chunk, `Retry-After: 5`); die beiden 600s-Wände entfallen, dafür `ReadHeaderTimeout` 10s; **kein** Failover bei Timeout. **Nach Referenz-Abgleich korrigiert** (90s ist kein Gesamtbudget); Timeout-Zähler **prozess-global** wie in der Referenz | AD-5.2a-2d, AD-5.3, AD-5.5 |
| 4 | Zero-Output-Guard? | Referenz: **immer** bei `outputTokens=0` → 429 `Retry-After: 10` vor dem ersten Frame, sonst SSE-Fehlerframe; ausgeliefertes Usage nullt Input-/Cache-Tokens. **Nach Referenz-Abgleich korrigiert** — strikt, kein Toleranzpfad für bereits ausgelieferte Inhalte | AD-5.4a-4c |
| 5 | Fingerprint/Session persistieren? | Eigene `detection.json`, keyed by `Account.ID` (nie der Roh-Key); Key-Rotation verwirft den State; WebUI zeigt Kurzform + „re-record“/„neue Session“ | AD-3.6a-6c |

Nachgezogen nach dem Referenz-Abgleich (2026-09-12): Der Timeout-Zähler ist **prozess-global** wie in der Referenz (der Hinweis meint die Kontextlänge des Clients; im Pool verteilen sich Timeouts auf verschiedene Accounts), der Zero-Output-Guard ist **strikt** wie in der Referenz (kein Toleranzpfad), und **alle sieben** nachgefundenen Mechanismen (x-session-id, ZDR, Empty-System-Placeholder, Parameter-Pass-through, Backpressure/Drain, In-Flight-Cap + 413, Status-Mapping) sind im Plan.

Nicht am Code entscheidbar und daher weiterhin offen: Bewertung der Nutzungsbedingungen und Zweck der Randomisierung (Phase 0), Verifikation der echten CLI-Werte und Endpunkte per HTTP-Capture (Phase 1 — Voraussetzung für AD-2, AD-3, AD-4.5 und für die strikte Variante von AD-5.1a) sowie die Nebenwirkung der zusätzlichen Fingerprint-/Lifecycle-Requests auf Rate-Limits und Pool-Failover.

Nächste Schritte: Phase 1 (Capture) → v1 (AD-1, AD-2, AD-4) → v2 (AD-3) → v3 (AD-5, AD-6).

## Referenz-Abgleich: commandcode-proxy (geprüft 2026-09-12, Nachlauf 2026-09-13)
Geprüft gegen README + `proxy.mjs` (Branch `master`). Ergebnis: Die Mechanismus-Liste ist inhaltlich vollständig erfasst, aber **sieben Annahmen im Plan wichen vom Referenzverhalten ab** (unten korrigiert) und **sieben Mechanismen fehlten**, die die Auftrags-Tabelle nicht nennt, die Referenz aber implementiert.

**Zweiter Prüflauf (2026-09-12, erneutes Live-Lesen von `proxy.mjs` + `README.md`):** zusätzlich korrigiert wurden die Jitter-Grenzen (einseitiger Aufschlag wie im Code: Session-TTL [12h, 13h], Refresh [8h, 10h] — nicht ±), das Initialisierungs-Fehlerverhalten (`nextInitAt` wird auch bei HTTP-Fehlern und abgefangenen Transportfehlern gesetzt), der Timeout-Pfad nach dem ersten Frame (Fehlerframe + Verbindung schließen, **kein** `[DONE]`), die In-Flight-Ausnahmen (`/health` **und** `/`), der npm-Paketname (`command-code`), die Herkunft des 7653→85-Belegs (Code/issue #17, **nicht** README) sowie `config.date` (Referenz: UTC via `new Date().toISOString().slice(0,10)`; Code hatte `time.Now()` lokal — am 2026-09-13 auf UTC umgestellt).

### Korrigierte Annahmen
| Thema | Referenz (`proxy.mjs`) | Frühere Plan-Annahme | Korrektur |
| --- | --- | --- | --- |
| 30s/90s | **Beide** sind Idle-Watchdogs über `reader.read()` (`createIdleWatchdog` + `Promise.race([reader.read(), idle.arm()])`), Reset bei jedem Chunk | 90s = Gesamtbudget für `stream:false` | 90s ist ebenfalls ein **Idle**-Timeout |
| Timeout-Antwort | 429 mit `retry_after: 5`; Text "Response timeout - request timed out", ab dem 3. Mal "... try reducing context length (summarize earlier messages)"; nach dem ersten Frame zusätzlich `res.destroy()` | nur "reduce context"-Hinweis | Werte und Texte übernehmen |
| Timeout-Zähler | **prozess-global** (`let consecutiveTimeouts = 0`), Reset bei jedem Erfolg | pro Account | Entschieden: **prozess-global** (AD-5.3) |
| Zero-Output | Rein `outputTokens === 0`, **kein** "nichts emittiert"-Kriterium; 429 `retry_after: 10` solange kein Frame gesendet wurde, sonst SSE-Fehlerframe; `normalizeUsage` nullt bei 0 Output zusätzlich `inputTokens` und `cachedInputTokens` (anti false billing) | 429 nur wenn nichts emittiert, sonst 200 + `[WARN]`; Prompt-Tokens weiter buchen | Entschieden: **strikt wie die Referenz** (AD-5.4) |
| Key-Extraktion | Regex-**Match irgendwo** im Headerwert (`auth.slice(7).match(/user_[a-zA-Z0-9_-]+/)`, ebenso für `x-api-key`); `Bearer `-Präfix nur bei `Authorization` Pflicht | `^user_…$` nach Präfix-/Pfad-Strip | Match-Extraktion übernehmen |
| Auth-Fehler | 401 mit `{type: "auth_error"}` | `invalid_api_key` | Typisierung angleichen |
| Handshake-Requests | Nutzen nur Version + Environment + Auth (+ ZDR), **kein** `traceparent` und **kein** `x-project-slug` | implizit dieselben Metadaten | Metadaten trennen |

### In der Auftrags-Tabelle fehlende Mechanismen (in der Referenz vorhanden)
1. **`x-session-id`** — Pflicht-Header auf `/alpha/generate`, plus Session-Quellen-Kette: eingehend `x-session-id` > `x-claude-code-session-id` > `session_id` > `prompt_cache_key` (≥ 8 Zeichen) > eigene Per-Key-Session (UUID, 12h + 1h).
2. **`x-cmd-zdr: 1`** (ZDR-Routing) auf `/alpha/generate` **und** auf Fingerprint/Lifecycle; aktiv per `zdr`/`CMD_ZDR` oder wenn der Client `x-cmd-zdr: 1` sendet. Die Referenz setzt ihn **nicht** auf den npm-Version-Check und **nicht** auf `/provider/v1/models` (README).
3. **Empty-System-Placeholder:** fehlt ein System-Prompt, wird `params.system = " "` gesendet (Default an) — verhindert, dass der Upstream ~7,5k Token eigenen Default-Prompt injiziert (belegt im Referenz-Code `proxy.mjs`, Kommentar zu issue #17: prompt_tokens 7653 → 85; das README nennt diese Zahl **nicht**).
4. **Parameter-Pass-through:** `temperature`, `tool_choice` (OpenAI → `{type: auto|none|any|tool}`), `parallel_tool_calls`; Tools als `{type, name, description, input_schema}`; `prompt_cache_key` ⇒ `cache_control: {type: "ephemeral"}` am letzten Text-Teil der ersten User-Message.
5. **Downstream-Backpressure:** Nach jedem Write auf `waitDrain(res)` warten (die Referenz schreibt zuerst und awaited den Drain vor dem nächsten Write, statt vor dem Schreiben zu blockieren); optionaler Stall-Timeout `CC_CLIENT_DRAIN_TIMEOUT_MS` (Default **aus**), weil ein Stall-Client von einem Client "blocked on tool execution" nicht unterscheidbar ist.
6. **In-Flight-Cap** (`CC_MAX_INFLIGHT`, Default aus) ⇒ 503 + `Retry-After: 5` + Type `server_busy`, `/health` **und** `/` ausgenommen; Body-Limit 100 MB ⇒ 413 mit Drain statt Connection-Reset.
7. **Status-Mapping:** 402 → 429 `rate_limit_error`, 403 → **401 `authentication_error`**, 422 → 400, 500/502 → 502 `upstream_error`, 503 → 503 `temporarily_unavailable`; `retry_after` 30 (429), 10 (Zero-Output), 5 (Timeout).

### Bewusst beibehaltene Abweichungen von der Referenz
- **Persistenz:** Die Referenz hält Session/Fingerprint in In-Process-Maps (der Code-Kommentar behauptet "写回 config.json", die Implementierung tut es nicht) und warnt selbst, dass zwei Instanzen pro Key zwei Sessions und zwei Fingerprints erzeugen. Unsere `detection.json` (Entscheidung 5) behebt genau dieses Problem, sofern die Datei geteilt wird.
- **Privacy:** Die Referenz loggt `keyPrefix: apiKey.slice(0, 8)` — ein echtes Key-Fragment entgegen ihrer eigenen Zusage "no API key fragments". AD-6 bleibt strikt und kopiert das nicht. Ebenso loggt sie Upstream-Fehlerbodies über `summarizeUpstreamError` (auf 500 Zeichen gekürzt) — gleichfalls entgegen ihrer README-Zusage "no error bodies"; AD-6 übernimmt nur normalisierte `code`/`message`, keine Rohbodies (AD-5.6).
- **`projectSlug`-Config:** Das README dokumentiert einen konfigurierbaren `x-project-slug` (Default `cc-proxy`), der Code leitet ihn aber **immer** aus der Session ab (`fakeProjectSlug`). Wir folgen dem Code, nicht dem README.

## Umsetzungsstand (2026-09-13)

AD-1 bis AD-6 sind implementiert und durch Tests abgedeckt:

| Bereich | Dateien | Tests |
| --- | --- | --- |
| AD-1 Version | `cliversion.go`, Admin-Endpunkte, Settings-UI | `cliversion_test.go` |
| AD-2 Metadaten | `metadata.go`, `SendWithHeaders` | `metadata_test.go` |
| AD-3 Detection | `detection.go`, `handshake.go`, `detection.json`, Admin/WebUI | `detection_test.go`, `detection_admin_test.go` |
| AD-4 Envelope | `types.go`, `cc.go` (`toolChoiceToCC`, `applyPromptCacheMarker`) | `envelope_params_test.go` |
| AD-5 Gateway | `robustness.go`, `idlebody.go`, `keys.go`, `handler.go`, `server.go` | `gateway_robustness_test.go` |
| AD-6 Privacy | `logging.go` (Redaction), Gate-Test | `logging_redaction_test.go` |

**Weiterhin von Phase 1 abhängig (Referenz-Annahmen im Code markiert):** das genaue `x-project-slug`-Format
(`projectSlugFromSession`), die Feldnamen der Fingerprint-/Lifecycle-Bodies (`fingerprintPayload`,
`lifecyclePayload`) und der `user_`-Präfix (strikte Ablehnung ist per `requireUserAccountKeys` noch
warn-only). Sobald der Capture vorliegt, sind das Ein-Zeilen-Anpassungen plus Test-Update.

**Bekannte Einschränkung:** `go test -race` ist in dieser Umgebung nicht lauffähig (kein gcc/cgo);
parallelisierte Pfade (Version-Provider, Detection-Store, Idle-Body) sind stattdessen mit
`-count=3` und atomaren Zugriffen abgesichert.

## Ziel: Anti-Detection-Parität
**Ziel:** Alle Anti-Detection-Funktionen von commandcode-proxy (https://github.com/MAXeaglet/commandcode-proxy) sollen implementiert sein. Referenz ist die Analyse des offiziellen CLI-Traffic (CLI-Version wird automatisch aus der npm-Registry ermittelt).

| Mechanismus | Implementierung |
| --- | --- |
| Device Fingerprint | `POST /alpha/fingerprint/record` vor dem ersten Request pro Key; zufälliger Fingerprint-Pool (15 CPUs, globale Zeitzonen), SHA-256-gehasht, Per-Key-Bindung, Refresh alle 8h + 2h Jitter |
| Lifecycle Events | `POST /alpha/lifecycle-events` (`cli_session_exists`) parallel zum Fingerprint bei Session-Init |
| Per-Key Session | Eine Session pro API-Key, 12h Ablauf + 1h zufälliger Jitter |
| Version | `x-command-code-version` automatisch aus der npm-Registry bezogen (24h Refresh) |
| CLI Envelope | `config`/`memory`/`taste`/`skills`/`permissionMode`/`params` |
| OpenTelemetry | `traceparent` (W3C Trace Context) |
| Environment | `x-cli-environment: production`, `x-co-flag: "false"`, `x-taste-learning: "false"` |
| Project Slug | `x-project-slug` aus der Session-ID generiert (CLI-kompatibles Format) |
| Reasoning Effort | `reasoning_effort` Pass-through (low/medium/high/max) |
| Key Validation | Regex `user_[a-zA-Z0-9_-]+` auf `Authorization: Bearer` oder `x-api-key`; entfernt automatisch zusätzliche Pfade/Präfixe, lehnt `sk-xxx`-Format ab — **Scope entschieden: gilt für Upstream-Account-Keys, siehe AD-5** |
| Stream Timeout | 30s Streaming / 90s Non-Streaming → 429 mit SDK-Auto-Retry |
| Consecutive Timeout | 3 aufeinanderfolgende Timeouts → "reduce context"-Hinweis |
| Zero-Output Guard | `outputTokens=0` → 429 `rate_limit_error` (SDK-Auto-Retry, Schutz vor False Billing) |
| Upstream Abort | AbortController bei Client-Disconnect + auf allen Fehlerpfaden |
| Privacy Logging | Keine API-Key-Fragmente, keine Error-Bodies, keine Stacktraces in Logs |

**Zuordnung zu den Phasen:**
- Version-Refresh → Phase 2 (CLI-Version-Provider).
- Environment-Header, `traceparent`, `x-project-slug`, Device Fingerprint, Lifecycle Events → Phase 4 (`CLIRequestMetadata`) bzw. neue Metadaten-Achse.
- CLI Envelope + `reasoning_effort` Pass-through → Phase 6 (Request Builder).
- Per-Key Session + Session-TTL/Jitter → Phase 5 (durch dieses Ziel **verbindlich**, siehe AD-3; PENDING ist nur noch die Feld-/Endpunkt-Ausgestaltung aus Phase 1).
- Key Validation, Stream-/Consecutive-Timeouts, Zero-Output Guard, Upstream Abort → Phase 11 (neu, Gateway-Robustheit, AD-5), nicht Teil der Client-Simulation.
- Privacy Logging → Phase 8 (Observability).

**Vor Start zu klären:**
- Fingerprint-Pool und Session-Jitter sind bewusst randomisiert; Zweck und Vereinbarkeit mit den Nutzungsbedingungen müssen in Phase 0 dokumentiert werden (die frühere Ausnahme "Anti-Erkennungs-Randomisierung ist ausgeschlossen" gilt damit nicht mehr).
- Fingerprint-/Lifecycle-Aufrufe sind zusätzliche Requests pro Key: Auswirkung auf Rate-Limits, Fehlerbehandlung und Pool-Failover klären (die ersten beiden Requests pro Key sind **nicht** am Account-Cooling beteiligt und dürfen den Completion-Pfad nicht blockieren).
- Persistenz: **entschieden** in Punkt 5 des Ist-Stand-Audits (`detection.json`, Bindung an `Account.ID`).

## Anti-Detection: Tasks & Akzeptanzkriterien
Status je Mechanismus: **fehlt** / **teilweise** / **vorhanden**. Jede Phase bekommt eine eigene ID (AD-1 … AD-6), damit v1/v2/v3 eindeutig referenzierbar bleiben.

| ID | Thema | Plan-Phase | Release | Vorhanden heute |
| --- | --- | --- | --- | --- |
| AD-1 | CLI-Version-Provider (npm) | Phase 2 | v1 | **vorhanden** (`cliversion.go`, 24h-Ticker, Fallback, Admin/WebUI) |
| AD-2 | CLI-Header/Metadaten | Phase 4 | v1 | **vorhanden** (`metadata.go`; `x-project-slug`-Format ist Referenz-Annahme, siehe Phase 1) |
| AD-3 | Fingerprint / Lifecycle / Per-Key-Session | Phase 5 | v2 | **vorhanden** (`detection.go` + `detection.json`, Logik aus Referenz; Feld-/Endpunkt-Ausgestaltung Phase 1) |
| AD-4 | Request-Envelope + reasoning_effort | Phase 6 | v1/v4 | **vorhanden** (`reasoning_effort`, `temperature`, `tool_choice`, `parallel_tool_calls`, `cache_control`) |
| AD-5 | Gateway-Robustheit (Key-Validierung, Timeouts, Zero-Output, Abort, Backpressure, In-Flight-Cap, Status-Mapping) | Phase 11 (neu) | v3 | **vorhanden** (Idle-Watchdogs, Zero-Output, Key-Hygiene, 413, 503, Status-Mapping; strikte `user_`-Ablehnung hinter Flag) |
| AD-6 | Privacy Logging | Phase 8 | v3 | **vorhanden** (`logging.go`-Redaction + Gate-Test) |

### Ist-Stand-Audit (2026-09-12)
Geprüft in `internal/app/*.go` (kein Netzwerkzugriff, reine Code-Analyse). Upstream wird ausschließlich über `POST /alpha/generate` angesprochen (`cc.go:282`) — es gibt **keinen** zweiten Upstream-Endpunkt im Code. Status und Zeilenverweise wurden am 2026-09-12 gegen den Arbeitsstand nachgezogen (inkl. der erledigten AD-4.5/AD-4.6); nach der `config.date`-Umstellung auf UTC am 2026-09-13 wurden die `cc.go`-Verweise hinter dem neuen Helper nachgezogen. Bei diesem Nachlauf wurden **alle** Statusmarkierungen (11× `fehlt`, 4× `teilweise`) erneut gegen den Code geprüft und unverändert bestätigt — nur `config.date` war zuvor fälschlich als offen geführt.

| Mechanismus | Status | Beleg | Konkrete Lücke |
| --- | --- | --- | --- |
| Device Fingerprint | **fehlt** | kein Vorkommen von `fingerprint` in `internal/` | gesamter Ablauf inkl. Pool, Hashing, Per-Key-Bindung, 8h/2h-Refresh |
| Lifecycle Events | **fehlt** | kein Vorkommen von `lifecycle-events`/`cli_session_exists` | kompletter Aufruf, parallel zum Fingerprint |
| Per-Key-Session | **fehlt** | kein `SessionID`/`ClientContext` in `internal/`; `Account` (`accounts.go:22-34`) hat kein Session-Feld | Feld, TTL 12h + 1h Jitter, Erneuerung |
| Version (npm, 24h) | **fehlt** (Hardcode) | Literal in `cc.go:288`; `registry.npmjs.org` nirgends | Provider, Cache, Refresh-Ticker, Fallback |
| CLI Envelope | **teilweise** | `CCRequest`/`CCConfig`/`CCParams` (`types.go:270-298`), Füllung in `cc.go:557-598` (Envelope-Werte `cc.go:570-587`), Golden-Test `cc_test.go:158` | Werte seit 2026-09-12 angeglichen: `workingDir` = `cliWorkingDir()` (`cc.go:542`), `environment` = `cliEnvironment()` (`cc.go:517`), `memory`/`taste` = `null`, `skills` = `""`, Empty-System-Placeholder (`cc.go:508-513`), `date` = `cliConfigDate()` in UTC (seit 2026-09-13, `cc.go:553`) — offen bleiben `reasoning_effort` (eigene Zeile) und der Parameter-Pass-through (`temperature`, `tool_choice`, `parallel_tool_calls`, `cache_control`); weiterhin nie gegen echtes CLI verifiziert |
| OpenTelemetry (`traceparent`) | **fehlt** | kein Vorkommen | Generierung + Header |
| Environment-Header | **teilweise** | `x-cli-environment: production` (`cc.go:289`) | `x-co-flag`, `x-taste-learning` fehlen |
| Project Slug | **fehlt** | kein `x-project-slug` | Format + Ableitung aus Session-ID |
| Reasoning Effort | **fehlt** | `CCParams` (`types.go:291-298`) und `ChatRequest` kennen kein Feld | Feld + Validierung + Pass-through |
| Key Validation | **fehlt** (Scope geklärt) | Auth: nur `Bearer `-Präfix + Pool-Lookup (`server.go:53-63`); Gateway-Keys sind `ccgw-<48 hex>` (`config.go:127-133`); Upstream-Key-Test prüft nichts (`admin.go:430-447`) | Regex + Auto-Cleanup für Upstream-Keys (AD-5.1a), `x-api-key`/Normalisierung für Client-Keys (AD-5.1b) |
| Stream Timeout 30s/90s | **fehlt** | nur global `http.Client{Timeout: 600s}` (`cc.go:44`); `server.go:210-212` (`ReadTimeout: 30s`) betrifft nur das Lesen des Client-Requests | 30s/90s-Idle-Watchdog → 429, konfigurierbar |
| Consecutive Timeout | **fehlt** | es existiert nur `authFailures` für 401/403 (`Account.RecordFailure`, `accounts.go:71-93`) + `authErrorThreshold=3` als reine UI-Anzeige (`accounts.go:97`) | Timeout-Zähler + „reduce context“-Hinweis in der Response |
| Zero-Output Guard | **fehlt** | `finish` mit `outputTokens=0` ⇒ 200 mit leerem Content; Usage wird unbedingt gebucht (`handler.go:274`, `handler.go:352`) | Guard in `finishStream` und `handleNonStream` |
| Upstream Abort | **teilweise** | Client-ctx wird durchgereicht (`handler.go:51` → `cc.go:282`); Body-Close auf Fehlerpfad (`cc.go:297`) und per `defer` in `parseStreamEvents` (`cc.go:365`) | keine Deadline pro Request (hängender Upstream blockiert bis 600s), keine Prüfung zwischen Stream-Events, kein Abort im Non-Stream-Pfad |
| Privacy Logging | **teilweise** | Admin maskiert: `MaskedKey()` (`accounts.go:49-52`), `accountID()` = SHA-256-Kürzel (`accounts.go:43-46`), Tests `admin_test.go:89/290`; OAuth loggt Key-Name statt Key (`oauth.go:376`) | Debug loggt komplette Request-Bodies (`handler.go:29-31`) und rohe Upstream-Events (`handler.go:229-232`, `294-297`); Fehlerlogs geben Upstream-Messages aus (`handler.go:60`, `70`); `Account.lastError` speichert `err.Error()` (`accounts.go:77`) und wird als `last_error` ausgeliefert (`accounts.go:130`) |

Kurzfassung: **0 von 15 Mechanismen sind vollständig vorhanden.** Vorhanden sind nur die CLI-Envelope-Struktur (Werte seit 2026-09-12 angeglichen, inkl. Empty-System-Placeholder), ein Teil der Environment-Header und punktuelle Key-Maskierung. Elf Mechanismen fehlen komplett (Fingerprint, Lifecycle, Session, npm-Version, `traceparent`, `x-project-slug`, `reasoning_effort`, Key-Validierung, Stream-Timeout, Consecutive-Timeout, Zero-Output-Guard), vier sind unvollständig (Envelope, Environment, Abort, Privacy).

**Offene Punkte aus dem Audit — alle entschieden (2026-09-12):**
1. **Key-Format-Konflikt — ENTSCHIEDEN (2026-09-12):** Die `user_[A-Za-z0-9_-]+`-Regex gilt ausschließlich für **Upstream-Account-Keys** und wird auf den Schreibpfaden (`AccountPool.Add` `accounts.go:244`, `SetKey` `accounts.go:292`, OAuth-Übernahme `app.go:67`/`admin.go:649`, WebUI-Add/-Patch `admin.go:142/184`) durchgesetzt. Beim **Laden** einer bestehenden `config.yaml` gilt **Warnung statt Ablehnung**: ungültige/abweichende Keys werden geloggt und in der WebUI markiert, der Account bleibt aber aktiv (sonst würden Bestandsinstallationen beim Upgrade lahmgelegt). Die lokal generierten Client-Keys bleiben `ccgw-…` und werden **nicht** auf `user_` umgestellt; auf der Client-Seite werden nur die Syntax-Regeln übernommen (`x-api-key`, Trimmen/Präfix- und Pfad-Bereinigung, Ablehnung von `sk-…`/leer). Details: AD-5.
2. **`x-api-key`:** heute existiert ausschließlich `Authorization` (`server.go:53`). **ENTSCHIEDEN:** nur im Client-Pfad ergänzen (`authMiddleware`); Admin-Auth bleibt Bearer-only. Zusätzlich muss der CORS-Preflight den Header erlauben (`server.go:146`), sonst schlägt der Browser-Preflight fehl.
3. **30s/90s-Budget — ENTSCHIEDEN (2026-09-12, nach Referenz-Abgleich):** **Beides sind Idle-Watchdogs** — 30s für Streaming, 90s für den clientseitigen Modus `stream:false` — und werden bei jedem Upstream-Chunk zurückgesetzt (inklusive Comment-Keepalive-Zeilen); ein **Gesamtbudget gibt es nicht**, weil ein tröpfelnder Upstream den Watchdog nie auslösen darf und ein hartes Totalcap unvereinbar mit dem Haupt-Agent der CLI wäre (lange Tool-Läufe, bis 64k Output-Tokens). Timeout **vor** dem ersten Byte ⇒ 429 `rate_limit_error` mit `Retry-After: 5` (Client-SDK retryt), **kein** interner Failover; Timeout **nach** dem ersten Byte ⇒ SSE-Fehler-Event, danach Verbindung schließen (`res.destroy()`; die Referenz sendet **kein** `[DONE]`), weil die Header bereits gesendet sind. Die bisherigen 600s-Wände (Client-Timeout `cc.go:44` + `WriteTimeout` `server.go:211`) werden entfernt, damit der Idle-Watchdog die einzige bindende Grenze ist. Details: AD-5.2/AD-5.5.
4. **Zero-Output — ENTSCHIEDEN (2026-09-12, nach Referenz-Abgleich):** Der Guard greift **strikt** bei `outputTokens == 0` — **ohne** Toleranzpfad für bereits ausgelieferte Inhalte. Noch kein Frame gesendet ⇒ 429 `rate_limit_error` mit `Retry-After: 10`; nach dem ersten Frame ⇒ SSE-Fehlerframe (429 ist dann physisch unmöglich). Usage: Prompt-/Cache-Tokens werden verbucht, Completion bleibt 0, der Request zählt aber **nicht als Erfolg**, und im **ausgelieferten** Usage werden bei 0 Output zusätzlich `inputTokens`/`cachedInputTokens` genullt (anti false billing); der Fehler läuft über `Account.RecordFailure` in den bestehenden `Account.Errors`-Zähler. Details: AD-5.4a-4c.
5. **Fingerprint-Persistenz — ENTSCHIEDEN (2026-09-12):** Eigene Datei `detection.json` neben `config.yaml`/`usage.json` (Muster von `usageFile`/`save()`, tmp + `os.Rename`, Package-Var für Tests); Einträge **keyed by `Account.ID`** (`accounts.go:43`, kein Roh-Key auf Platte). Pro Eintrag: Fingerprint-Hash, Profilattribute (CPU/TZ), Refresh-Deadline, Session-ID + Ablauf und die `base_url`, gegen die aufgezeichnet wurde — bei `base_url`-Wechsel wird neu aufgezeichnet (`cc.SetBaseURL`, `cc.go:54`). Bei **Key-Rotation** (`SetKey`, `accounts.go:292`) wird der alte Eintrag **verworfen** und eine frische Bindung erzeugt (kein `MoveAccount`): ein geteiltes Profil über mehrere Keys würde die Accounts upstream verknüpfbar machen und damit das Anti-Detection-Ziel untergraben. Die WebUI zeigt Kurzform + Profil + nächsten Refresh + Session-Ablauf und bietet „re-record“/„neue Session“. Details: AD-3.6a-6c.

### AD-1 – CLI-Version dynamisch aus npm (Phase 2)
Ist: `httpReq.Header.Set("x-command-code-version", "0.24.1")` in `cc.go:288`.

Tasks:
1. Neue Datei `internal/app/cliversion.go`: `VersionProvider` mit `Current() string` und Start-/Hintergrund-Refresh.
2. npm-Registry-Abruf (`https://registry.npmjs.org/command-code/latest` — Paketname aus der Referenz, Phase 1 bestätigt nur noch, dass der offizielle Client denselben Namen nutzt), JSON-Feld `version`, HTTP-Timeout 10s.
3. Refresh-Intervall 24h per Ticker; zusätzlich Refresh beim Start. Zugriff thread-safe (`atomic.Value`), kein Lock im Request-Pfad.
4. Fallback-Kette: letzte bekannte Version (Cache/Config) → hartcodierte Fallback-Konstante. Registry-Fehler nur `[WARN]`, niemals request-fatal.
5. `CCClient` erhält den Provider per Konstruktor/Setter; `doSend` liest aus dem Provider statt Literal.
6. Admin/WebUI: aktuelle Version, Quelle (npm/Cache/Fallback), manueller Refresh-Button.

Akzeptanzkriterien:
- Suche nach `"0.24.1"` in `internal/app` liefert nur noch die Fallback-Konstante als Treffer.
- Unit-Tests mit `httptest`-npm-Mock: (a) 200 → neue Version wird verwendet; (b) 500/Timeout/Müll-JSON → Fallback bleibt, kein Panic, kein Request-Fehler; (c) parallele Requests während eines Refreshs sind race-frei (`go test -race`).
- Integrationstest: erster `/alpha/generate` trägt die gemockte npm-Version; 100 Completions erzeugen ≤1 Registry-Aufruf (kein Request-pro-Completion).
- Bestehende Tests (`cc_test.go`, `accounts_test.go`, `models_test.go`) bleiben grün.

### AD-2 – CLI-Header/Metadaten zentralisieren (Phase 4)
Ist: nur `Authorization`, `x-command-code-version`, `x-cli-environment` (`cc.go:287-289`). Fehlt: `traceparent`, `x-project-slug`, `x-co-flag`, `x-taste-learning`.

Tasks:
1. `CLIRequestMetadata` (Phase 4) um `Version`, `Environment`, `ProjectSlug`, `Traceparent`, `CoFlag`, `TasteLearning` erweitern.
2. `traceparent` im W3C-Format `00-<32 hex trace-id>-<16 hex span-id>-01`, pro Request neu, IDs aus `crypto/rand`.
3. `x-project-slug` deterministisch aus der Session-ID ableiten (Slug-Format aus Phase-1-Capture); darf keine lokalen Pfade, Hostnamen oder Benutzernamen enthalten.
4. `x-co-flag: "false"` und `x-taste-learning: "false"` konstant setzen (Werte in Phase 1 gegen echtes CLI verifizieren).
4b. **`x-session-id` (fehlte in der Auftrags-Tabelle, ist aber Pflicht):** Session-ID des Keys als Header; Auflösungsreihenfolge wie in der Referenz: eingehend `x-session-id` > `x-claude-code-session-id` > `session_id` > `prompt_cache_key` (nur wenn ≥ 8 Zeichen) > eigene Per-Key-Session. Auch die Referenz schickt diesen Header auf `/alpha/generate`, aber **nicht** in den Handshake-Requests.
4c. **Optional `x-cmd-zdr: 1`**, wenn `zdr`-Config bzw. `CMD_ZDR` aktiv ist oder der eingehende Request `x-cmd-zdr: 1` trägt — auf `/alpha/generate` **und** auf Fingerprint/Lifecycle (`x-cmd-zdr` ist in `server.go:146` zusätzlich in die CORS-Allow-Liste aufzunehmen).
5. `Apply(req)` wird die **einzige** Stelle, die CC-Header setzt; `doSend` ruft nur noch `Apply`.

Akzeptanzkriterien:
- Golden-Test `TestCLIRequestMetadataApply`: exakter Header-Satz, `traceparent` matcht `^00-[0-9a-f]{32}-[0-9a-f]{16}-01$`; zwei Aufrufe ⇒ unterschiedliche trace-IDs.
- Test: `x-project-slug` entspricht dem CLI-Format und enthält keinen Substring aus WorkingDir, Hostname oder Username.
- Snapshot-/Golden-Test auf den vollständigen Upstream-Request: Header-Literale existieren nur noch in `CLIRequestMetadata`.
- `go test -race` grün; keine bestehende Header-Erwartung in `cc_test.go`/`accounts_test.go` bricht (sonst Test bewusst mitziehen).

### AD-3 – Fingerprint, Lifecycle Events, Per-Key-Session (Phase 5)
Ist: vollständig **fehlt** — kein `/alpha/fingerprint/record`, kein `/alpha/lifecycle-events`, kein Session-State im `Account`.

Tasks:
1. Neue Datei `internal/app/fingerprint.go`, Struktur exakt wie in der Referenz: Pool aus 15 CPU-Einträgen (Modell + Kernzahl: i7-12650H/10, i5-12400F/6, …, Ryzen 7 5800X3D/8), Speichergrößen `[8,16,24,32,48,64]` GiB, 15 globale Zeitzonen, 2–5 MAC-Einträge. Zufällige Komponenten werden per SHA-256 gehasht (`machineIdHash`, `macHashes[]`, `osUserHash`, `hostnameHash`, `gitEmailHash`), fest sind `platform: win32`, `arch: x64`, `osRelease: 10.0.22631`, `isContainer: false`, `runtime: cli`, `collectorVersion: 1`; `thumbmark` = SHA-256 über die mit `|` verbundenen `thumbData` in genau dieser Reihenfolge: `machineIdHash`, alle `macHashes`, `osUserHash`, `hostnameHash`, `gitEmailHash`, `'win32'`, `'10.0.22631'`, CPU-Modell, Kernzahl, `memGiB` (**nicht** enthalten: Zeitzone, `arch`, `runtime`, `isContainer`, `collectorVersion`). Bindung als Feld in `Account` (in-memory) und persistiert über `detection.json` (siehe 6a).
2. `POST /alpha/fingerprint/record` vor dem ersten `/alpha/generate` pro Key; Response/Timestamp cachen; Refresh nach 8h + bis zu 2h Jitter (einseitig also [8h, 10h], nicht ±2h; Deadline pro Account).
3. `POST /alpha/lifecycle-events` mit `cli_session_exists` **parallel** zum Fingerprint (`Promise.all` in der Referenz); Body: `metadata.sessionId` als **frischer** Zufallswert `sess_<16 hex>` (nicht die 12h-Session), `cliVersion`, `mode: "interactive"`, `os: "<platform>-<arch>"`. Darf den ersten Completion-Request nicht messbar verzögern; wir ergänzen eine In-Flight-Sperre pro Key, die die Referenz nicht hat (dort können parallele Erst-Requests doppelt feuern).
4. Session pro Key: 12h Ablauf + 1h Jitter, `SessionID` in `ClientContext` (Phase 3/7), Session-ID als Eingang für `x-project-slug` (AD-2.3).
5. Fehlerverhalten wie die Referenz: jeder Nicht-OK-Status wird nur als `[WARN]` geloggt, die Completion läuft weiter. **Aber:** Die Refresh-Deadline wird in der Referenz nach **jedem** abgeschlossenen Versuch gesetzt — jeder `fetch` hat sein eigenes `.catch`, das HTTP- und Transportfehler verschluckt, also resolved `Promise.all` auch bei HTTP 500 und `state.nextInitAt` wird gesetzt. Ein erneuter Versuch findet daher erst nach [8h, 10h] statt, **nicht** beim nächsten Request; nur ein synchroner Fehler im `try`-Block würde beim nächsten Request wiederholen (der äußere `catch` ist praktisch unerreichbar). Wir übernehmen dieses Fenster und dokumentieren es als bewusste Abweichung von einem Retry pro Request. Eine Sonderbehandlung von 401/403 gibt es in der Referenz nicht; ob wir sie wie bei `/alpha/generate` auf den Account anwenden wollen, ist eine eigene Entscheidung (Abweichungsnotiz).
6a. **Datei + Struktur:** neues `detection.json` nach dem Vorbild von `usageFile` (`usage.go:274-321`): Package-Var (in Tests per `t.TempDir()` umgebogen, siehe `accounts_test.go:320`), Laden beim Start mit sinnvollen Defaults, Speichern atomar via tmp + `os.Rename`. Eintrag pro `Account.ID` mit `fingerprint`, `profile` (CPU/TZ), `fingerprint_refresh_at`, `session_id`, `session_expires_at`, `base_url`. Der Speicherzugriff ist thread-safe (Mutex wie `UsageTracker.accMu`) — mehrere Accounts und Streams greifen parallel zu.
6b. **Bindung + Invalidierung:** Ein Eintrag gilt nur für die `base_url`, gegen die er aufgezeichnet wurde (Mismatch ⇒ neu aufzeichnen). Bei `SetKey` (`accounts.go:292`) wird der alte Eintrag gelöscht und die neue ID startet ohne State (neues Profil + neue Session) — bewusst **kein** `MoveAccount`. Bei `Remove` wird der Eintrag mitgelöscht; Re-Add desselben Keys startet frisch. `Rename` (`accounts.go:280-287`) lässt den State unverändert.
6c. **WebUI/Sichtbarkeit:** pro Account Fingerprint-Kurzform (z. B. erste und letzte 8 Zeichen des Hashes), Profilattribute, nächster Refresh und Session-Ablauf; zusätzlich Aktionen "re-record" und "neue Session" (auch für Tests/Debug nötig). Der Fingerprint-Hash ist kein Credential, wird aber ebenfalls nie vollständig geloggt.

Akzeptanzkriterien:
- Mock-Upstream: erster Request pro Key erzeugt genau 1× fingerprint + 1× lifecycle, beide abgeschlossen bevor die Completion eintrifft; zweiter Request im selben Zeitfenster erzeugt **keine** weiteren Aufrufe.
- Test prüft, dass der gesendete Fingerprint 64 Hex-Zeichen lang ist (SHA-256) und für denselben Key stabil; zwei Keys ⇒ zwei verschiedene Fingerprints (kein Sharing).
- Jitter-Grenzen über injizierbare Uhr/Rand-Zquelle (Aufschlag einseitig wie in der Referenz: `now + DURATION + random(0, JITTER)`): Session-TTL ∈ [12h, 13h], Refresh ∈ [8h, 10h].
- Nach TTL-Ablauf: neue Session-ID, neuer `x-project-slug`, genau ein erneuter Fingerprint-Aufruf.
- Fingerprint-/Lifecycle-Ausfall (500) ⇒ Completion bleibt 200; 401 ⇒ Account wird deaktiviert und aus `Acquire` entfernt (`TestAccountPoolSkipsDisabledAndRateLimited`-Muster).
- **Persistenz über Neustart:** Fingerprint-Hash, Profil, Session-ID und Deadlines bleiben nach einem Neustart identisch (State wird aus `detection.json` geladen); genau 1× Speichern pro Änderung, Datei enthält **keinen** Roh-API-Key (nur `Account.ID`).
- **base_url-Wechsel:** Eintrag mit alter `base_url` wird nicht wiederverwendet ⇒ neu aufzeichnen, neue Session, neuer `x-project-slug`.
- **Rotation/Removal:** `SetKey` erzeugt neues Profil + neue Session und entfernt den alten Eintrag; `Remove` löscht den Eintrag; `Rename` lässt ihn unverändert.
- **Defekte/fehlende Datei:** fehlende Datei = Erststart ohne Fehler; korruptes JSON ⇒ `[WARN]` + kompletter Neuaufbau, kein Startabbruch.
- **WebUI:** Kurzform, Profil, nächster Refresh und Session-Ablauf sind sichtbar; „re-record“ löst genau einen neuen `fingerprint/record`-Aufruf aus, „neue Session“ genau einen `lifecycle-events`-Aufruf mit neuer Session-ID.
- Der PENDING-Vorbehalt bezieht sich nur noch auf die Feld-/Endpunkt-Ausgestaltung (Phase 1); die Umsetzung von Fingerprint, Lifecycle und Session ist **beschlossen** (siehe Phase 5).

### AD-4 – Request-Envelope + `reasoning_effort` (Phase 6)
Ist: Envelope **vorhanden**, Werte angeglichen (siehe 5/6, inkl. UTC-`date`). Offen: `reasoning_effort`, `temperature`, `tool_choice`, `parallel_tool_calls` und der `cache_control`-Marker für `prompt_cache_key` — `CCParams` hat weiterhin nur model/messages/tools/system/max_tokens/stream.

Tasks:
1. Golden-Test in `cc_test.go:158` bleibt die Referenz für das Wire-Format; Erweiterungen nur additiv.
2. Feld `ReasoningEffort` in `CCParams` mit JSON-Tag `reasoning_effort,omitempty` ergänzen; `ChatRequest` parst `reasoning_effort`.
3. **Pass-through wie die Referenz** (die sendet jeden Wert, sobald er `!== undefined` ist). Eine Whitelist auf low/medium/high/max ist optional und darf nur `[WARN]` erzeugen, nicht das Feld entfernen — die frühere Fassung ("unbekannte Werte werden nicht gesendet") war eine Abweichung.
4. `OutputTokenBudget()` bleibt; die Referenz klemmt zusätzlich auf `min(max_tokens || 64000, 200000)` — entspricht `defaultCCMaxTokens`/`maximumCCMaxTokens` in `cc.go`, also nur verifizieren.
5. ~~**Envelope-Werte an die Referenz angleichen** …~~ **ERLEDIGT (2026-09-12):** `CCRequest.Memory`/`Taste` sind jetzt `*string` (`null`), `Skills` ist `string` (`""`); `config.environment` kommt aus `cliEnvironment()` (`win32-x64, Node.js v24.16.0`-Form mit Mapping `windows`→`win32`, `amd64`→`x64`), `config.workingDir` aus `cliWorkingDir()` (`os.Getwd()`, Fallback `/`). Golden-Test angepasst. Bei diesem Abgleich zusätzlich gefunden: `config.date` kam aus `time.Now()` (lokal), die Referenz nutzt UTC (`new Date().toISOString().slice(0,10)`). **ERLEDIGT (2026-09-13):** `cliConfigDate(now)` formatiert in UTC und `openAIToCC` nutzt es; neuer Test `TestOpenAIToCCUsesUTCDateLikeTheCLI`. Neue Tests aus diesem Abgleich: `TestOpenAIToCCSendsCLIEnvelopeValues`, `TestOpenAIToCCUsesNodeShapedEnvironment`, `TestOpenAIToCCReportsWorkingDirectory`.
6. ~~**Empty-System-Placeholder** …~~ **ERLEDIGT (2026-09-12):** `emptySystemPlaceholder = " "` (Default an, per Package-Var auf `""` abschaltbar) wird in `openAIToCC` eingesetzt, wenn `extractSystem` leer bleibt; ein expliziter System-Prompt wird unverändert durchgereicht. Test: `TestOpenAIToCCFillsEmptySystemPromptLikeTheCLI`.
7. **Weitere params der Referenz:** `temperature` durchreichen (heute verworfen), `tool_choice` nach `{type: auto|none|any|tool}` mappen, `parallel_tool_calls` durchreichen, Tools als `{type, name, description, input_schema}` senden, und bei vorhandenem `prompt_cache_key` (ohne vorhandenen Cache-Marker) `cache_control: {type: "ephemeral"}` am letzten Text-Teil der ersten User-Message setzen.

Akzeptanzkriterien:
- Neue Tests: `reasoning_effort:"high"` ⇒ `params.reasoning_effort == "high"`; leer ⇒ Key existiert im JSON nicht; `"ultra"`/Zahl ⇒ Key fehlt und Request bleibt 200.
- Golden-Test ohne gesetztes `reasoning_effort` ist byte-identisch zu heute; mit gesetztem Feld um genau dieses Feld erweitert.
- Envelope-Test: die 6 CLI-Envelope-Felder (`config`, `memory`, `taste`, `skills`, `permissionMode`, `params`) existieren genau einmal und mit den CLI-erwarteten Typen (String / null / Array).
- `budget_test.go`, `structured_tool_protocol_test.go`, `precision_test.go` bleiben grün.

### AD-5 – Gateway-Robustheit (Phase 11, neu, v3)
Ist: `http.Client{Timeout: 600 * time.Second}` (`cc.go:44`), Server-Read 30s / Write 600s (`server.go:210-212`). **Fehlt:** 30s/90s-Stream-Timeout → 429, Consecutive-Timeout-Zähler, Zero-Output-Guard, Key-Validierungsregex. Abort **teilweise:** `cc.Send(r.Context(), …)` (`handler.go:51`) bricht bei Client-Disconnect den Upstream-ctx ab; Body-Cleanup und Stream-Abbruch sind nicht systematisch abgesichert.

Tasks:
1a. **Upstream-Account-Keys (strikt)** — zentraler `normalizeAccountKey(raw string) (string, error)`: Whitespace/Quotes trimmen, führendes `Bearer ` entfernen, URL-/Pfad-Präfixe (`https://…/provider/v1/`, `/v1/`) abschneiden, dann `^user_[A-Za-z0-9_-]+$` prüfen; `sk-…`, leere Werte und Nicht-Matches ⇒ klare Fehlermeldung. Durchsetzen in `AccountPool.Add` (`accounts.go:244`), `SetKey` (`accounts.go:292`), OAuth-Übernahme (`app.go:67`, `admin.go:649`) und WebUI-Add/-Patch (`admin.go:142/184`); zusätzlich kann `testAccountKey` (`admin.go:430`) das Ergebnis melden, statt erst den Upstream-401 zu zeigen. **Ausnahme Ladepfad:** `config.go:154-159` akzeptiert abweichende Bestands-Keys mit `[WARN]` + WebUI-Markierung (kein Startabbruch, Account bleibt aktiv). **Bis Phase 1 den Präfix bestätigt hat, bleibt die strikte Ablehnung auf den Schreibpfaden hinter einem Flag (Default: warn-only)** — im Repo ist `user_` nicht belegt (`oauth.go:25` liest nur `apiKey`), ein blindes Ablehnen könnte gültige OAuth-Keys sperren; nach der Bestätigung wird strikt zum Standard.
1b. **Client-Keys (nur Syntax)** — `ccgw-…` bleibt das Format. Auth-Middleware (`server.go:53-63`) erweitern: Key aus `Authorization: Bearer …` **oder** `x-api-key` lesen, `Bearer`-Präfix/Pfad-Suffixe/Whitespace normalisieren, `sk-…` und leer ⇒ 401 `invalid_api_key`. Admin-Auth (`adminAuth`) bleibt Bearer-only; CORS-Preflight muss `x-api-key` erlauben (`server.go:146`).
2a. **Streaming: Idle-Watchdog 30s.** Gemessen wird **nur die Wartezeit im Upstream-Read** (Referenz: `Promise.race([reader.read(), idle.arm()])`), zurückgesetzt bei **jedem** empfangenen Chunk, nicht bei jedem Event — also auch bei `:`-Comment-Zeilen (`cc.go:406`) und aufeinanderfolgenden Rumpf-Chunks. Läuft er ab: Upstream-Abbruch, `retry_after: 5`, Text "Response timeout - request timed out"; **vor dem ersten Byte** ⇒ HTTP 429 `rate_limit_error`, **danach** ⇒ SSE-Fehler-Event (wie die Referenz zusätzlich Verbindung schließen, da die Response committed ist).
2b. **Non-streaming: Idle-Watchdog 90s** für den gepufferten Drain in `handleNonStream` (`parseStreamEvents`, `handler.go:293`) — **ebenfalls** idlebasiert mit Reset pro Chunk, **kein** Gesamtbudget: Ein tröpfelnder Upstream darf den Watchdog nie auslösen. Bei Überschreitung 429 `rate_limit_error` mit `retry_after: 5` (dort ist per Definition noch nichts geschrieben). Werte konfigurierbar (`CC_STREAM_IDLE_MS`/`CC_NONSTREAM_IDLE_MS`), Defaults 30s/90s, im Test injizierbar (kein echtes Warten). Hinweis aus der Referenz: Der offizielle CLI-Client hat **keinen** Upstream-Idle-Timeout (belegt in issue #19), 30s ist also eine bewusste, dokumentierte Abweichung mit dem Risiko, lange Prefill-Stalls zu killen.
2c. **Kein Failover bei Timeouts.** `shouldFailover` schließt `context.DeadlineExceeded` bereits aus (`cc.go:263-265`) — das bleibt so und wird für die neuen Timeouts bewusst beibehalten; der Client-SDK übernimmt den Retry. Einfügen eines eigenen Fehlertyps, damit Timeout (Account-Belastung) von Client-Disconnect (keine Account-Belastung) unterscheidbar ist.
2d. **Transport- und Server-Timeouts anpassen:** `http.Client{Timeout: 600s}` (`cc.go:44`) auf `0` (bzw. großzügig) setzen, `WriteTimeout: 600s` (`server.go:211`) auf `0`, dafür `ReadHeaderTimeout: 10s` + `ReadTimeout: 0` (sonst brechen Base64-Bild-Uploads, die >30s brauchen, an `server.go:210` ab). **Nicht** wie früher geplant eine pauschale Write-Deadline pro `writeSSE` — die Referenz löst das über Backpressure: vor jedem Write auf `waitDrain(res)` warten und nur optional (Default **aus**) einen Stall-Timeout `CC_CLIENT_DRAIN_TIMEOUT_MS` setzen, weil ein Stall-Client von einem Client "blocked on tool execution" nicht unterscheidbar ist. Zusätzlich sendet die Referenz während stiller Phasen `: keepalive`-Frames — aber **nur nach** dem ersten echten Frame, damit das 429-Fenster aus 4b offen bleibt. Nebenbefund: `maxChatRequestBytes` gegen die 100-MB-Referenzgrenze prüfen (413 mit Drain, nicht Connection-Reset).
3. Consecutive-Timeout-Zähler, Schwelle 3, Reset bei jedem erfolgreichen Request (Stream **und** Non-Stream) — mit dem Referenztext "Response timeout - request timed out" bzw. "Response timeout - try reducing context length (summarize earlier messages)". **ENTSCHIEDEN (2026-09-12): prozess-global wie die Referenz** (ein Zähler für den ganzen Prozess, nicht pro Account) — der Hinweis meint die Kontextlänge des Clients, und im Account-Pool verteilen sich Timeouts auf verschiedene Accounts. Account-Health bleibt unverändert bei `authFailures`/`errors`.
4a. **Bedingung (Referenz):** Allein `outputTokens == 0` aus `finish`/`finish-step` löst den Guard aus — **ohne** "nichts emittiert"-Kriterium. Noch kein Frame gesendet ⇒ HTTP 429 `rate_limit_error` mit `retry_after: 10` ("Empty response from upstream (zero output tokens)"); bereits gesendet ⇒ SSE-Fehlerframe statt eines 200-Abschlusses. Zusätzlich nullt die Referenz in diesem Fall `inputTokens` und `cachedInputTokens` im **ausgelieferten** Usage (anti false billing). Unsere frühere Fassung (429 nur ohne Ausgabe, sonst 200 + `[WARN]`) war eine Abweichung. **ENTSCHIEDEN (2026-09-12): strikt wie die Referenz — kein Toleranzpfad.**
4b. **Stream-Fenster:** Das 429 ist nur zulässig, solange nichts geflusht wurde. `handleStreamWithOptions` setzt lediglich Header und schreibt erst im ersten `writeSSE` (`handler.go:412`) — bei einem Stream, der nur aus `finish` besteht, ist die Response also noch uncommitted. **Konsequenz:** im Stream-Pfad keinen vorzeitigen Flush/Heartbeat einbauen, sonst schließt sich das Fenster; nach dem ersten Frame ⇒ SSE-Fehlerframe wie in 4a/4c (ein 429 ist dann physisch unmöglich). Bei `stream:false` ist der Guard immer möglich, da `handleNonStream` erst nach dem vollständigen Drain schreibt.
4c. **Usage-Buchung:** Prompt- und Cache-Tokens (read/write) werden wie bisher verbucht, Completion bleibt 0 — aber **ohne** Erfolgszählung des Requests. Da `UsageTracker.Record`/`UsageCounters.add` heute **immer** `Requests` um 1 erhöhen (`usage.go:40`, `usage.go:70`), braucht es dafür eine kleine API-Erweiterung (z. B. ein Zähl-Flag oder eine getrennte Methode); der Fehler selbst wird über `Account.RecordFailure` mit eigenem Fehlertyp in `Account.Errors` (`accounts.go:27`/`73`) gezählt — kein neues Zählerfeld nötig. Das gilt bewusst abweichend vom bisherigen Verhalten, dass auch Fehlerpfade Usage buchen (`handler.go:274`, `handler.go:352`).
5. Upstream-Abort: `resp.Body.Close()` auf **allen** Pfaden (Non-Stream-Fehler, Parse-Fehler, Client-Abbruch, Idle-Watchdog, 90s-Idle-Drain); Stream-Schleife bricht bei `ctx.Err()` sofort ab — kein Weiterlesen, kein Failover, kein Replay; keine Goroutine-Leaks. Der Idle-Watchdog (2a) und der 90s-Idle-Watchdog (2b) canceln denselben ctx; ein Client-Disconnect (`r.Context()` abgebrochen) darf dabei **nicht** als Timeout gezählt werden (siehe 2c).
6. Fehlerantworten dürfen keine Upstream-Rohbodies durchreichen (nur normalisierter `code`/`message`), siehe AD-6.
7. **Backpressure + Drain (nachgetragen aus dem Abgleich):** Jeder Downstream-Write wartet auf Drain (`writeSSE`/`fmt.Fprint`-Fehler behandeln bzw. `http.NewResponseController`), damit ein nicht lesender Client den Upstream-Read pausiert statt Speicher aufzubauen; optionaler Stall-Timeout (Default **aus**, per Config/Env), der die Verbindung schließt und damit den Upstream abbricht. Body-Limit gegen die 100-MB-Referenz prüfen (`maxChatRequestBytes`): 413 **mit Drain** der Restbytes statt Connection-Reset, damit Keep-alive nutzbar bleibt.
8. **In-Flight-Cap (optional, Default aus):** globaler Zähler, über dem Limit 503 + `Retry-After: 5` + Type `server_busy`; `/health` (und `/`) sind ausgenommen, damit Liveness-Prüfungen nie 503 sehen.
9. **Status-Mapping an die Referenz angleichen:** 402 → 429 `rate_limit_error`, 403 → **401 `authentication_error`** (heute `permission_error`), 422 → 400, 500/502 → 502 `upstream_error` (heute `server_error`), 503 → 503 `temporarily_unavailable`; `retry_after` 30 (Upstream-429), 10 (Zero-Output), 5 (Timeout). Achtung: Das ändert bestehende Erwartungen in `cc_test.go`/`handler_test.go` — Tests bewusst mitziehen.

Akzeptanzkriterien:
- Upstream: table-driven `TestNormalizeAccountKey` — gültig `user_abc-1_2`, `"  user_x  "`, `"Bearer user_x"`, `"https://api.commandcode.ai/provider/v1/user_x"`, `"token_user_abc"` ⇒ jeweils `user_…` per **Match** (nicht per Anker am Anfang); ungültig `sk-abc`, `user_`, `foo`, leer ⇒ `Add`/`SetKey`/OAuth/WebUI lehnen mit klarer Meldung ab (kein Account angelegt).
- Ladepfad: `config.yaml` mit einem Nicht-`user_`-Key lädt weiterhin, Account bleibt `Enabled`, Log enthält eine `[WARN]`-Zeile, WebUI markiert den Account; danach greift die strenge Regel bei jeder Änderung.
- Client: `Authorization: Bearer ccgw-…` und `x-api-key: ccgw-…` sind beide gültig; `Bearer  ccgw-…/v1` wird normalisiert und matcht den Pool; `sk-…`, leer, unbekannt ⇒ 401; weder Key noch Fragment erscheinen in Response oder Log; CORS-Preflight erlaubt `x-api-key`. Fehlertyp-Frage: die Referenz liefert `auth_error`, unsere Middleware `authentication_error`/`invalid_api_key` — angleichen oder als Abweichung dokumentieren.
- Timeout-Tests mit injizierten Kurzwerten statt echtem Warten:
  - **Idle vor dem ersten Byte:** Mock schweigt ⇒ 429 `rate_limit_error` + `Retry-After`, Mock sieht `ctx.Done()`, und es findet **kein** zweiter Account-Aufruf statt (kein Failover).
  - **Idle mitten im Stream:** Mock sendet ein Delta, dann Stille ⇒ SSE-Fehler-Event, danach Verbindung schließen (wie die Referenz: `res.destroy()`, **kein** `[DONE]`), **kein** 429 (Header sind raus).
  - **Reset-Beweis:** Mock sendet alle 100ms ein Event (inkl. `:`-Keepalive) über das Testfenster hinaus ⇒ der Stream läuft über das Idle-Limit hinaus erfolgreich zu Ende.
  - **Non-streaming:** `stream:false` mit **schweigendem** Mock (keine Chunks) ⇒ nach dem 90s-Testwert 429 + `Retry-After: 5`, kein Body geschrieben. Gegenprobe: ein tröpfelnder Mock (Chunk alle 100ms) darf den Watchdog **nicht** auslösen — sonst wäre es ein Gesamtbudget.
- Client-Disconnect ist **kein** Timeout: Request mitten im Stream abbrechen ⇒ Timeout-Zähler des Accounts bleibt 0, kein Cooldown, kein Hinweis.
- 3 Timeouts in Folge ⇒ Hinweis vorhanden, **auch wenn sie auf verschiedene Accounts verteilt auftreten** (globaler Zähler); ein einziger erfolgreicher Request setzt ihn auf 0 zurück. Timeouts sind explizit **nicht** failover-berechtigt; Failover bleibt auf 401/403/429/5xx beschränkt (`TestShouldFailoverMatrix`).
- Konfigurations-Test: Client-Timeout 0, `WriteTimeout` 0, `ReadHeaderTimeout` 10s; **keine** Write-Deadline pro `writeSSE` (die Referenz regelt das über Backpressure/Drain, siehe 2d) — der Backpressure-Pfad wird mit einem langsam lesenden `httptest`-Reader geprüft.
- Zero-Output-Guard: `outputTokens == 0` löst ihn **immer** aus (Referenzverhalten), unabhängig davon, ob schon Deltas liefen.
  - **Noch kein Frame (Streaming):** Response nicht committed ⇒ echtes JSON-429 `rate_limit_error` + `Retry-After: 10`, kein `data:`-Frame, Mock sieht `ctx.Done()`.
  - **Nach dem ersten Frame (Streaming):** SSE-Fehlerframe mit derselben Meldung (429 ist physisch unmöglich), danach Verbindung schließen.
  - **Non-streaming:** 429 aus dem gepufferten Pfad mit `Retry-After: 10`.
  - **Ausgeliefertes Usage:** bei 0 Output sind `inputTokens` und `cachedInputTokens` genullt (anti false billing) — eigener Test darauf.
  - **Strikt (entschieden):** Auch wenn Text/Reasoning/Tool-Calls bereits ausgeliefert wurden, bleibt es beim Fehlerframe — **kein** 200-Toleranzpfad.
- Abort-Test: Client bricht eine laufende Streaming-Antwort ab (httptest + cancel) ⇒ Upstream-ctx canceled, Handler kehrt zurück, Upstream-Body geschlossen, keine hängende Goroutine (`go test -race`).
- Backpressure-Test: Client liest nicht (Reader mit kleinem Puffer) ⇒ Upstream-Read pausiert, Speicher wächst nicht unbegrenzt; mit aktivem Stall-Timeout wird die Verbindung geschlossen und der Upstream-ctx abgebrochen.
- 413-Test: Request über `maxChatRequestBytes` ⇒ 413, Restbytes werden gedraint (kein Verbindungsreset), Keep-alive bleibt nutzbar.
- In-Flight-Cap: Limit 1 ⇒ zweiter Request bekommt 503 + `Retry-After: 5` + `server_busy`; `GET /health` bleibt 200.
- Status-Mapping als Tabelle testen (402/403/422/500/502/503) inklusive `retry_after` 30/10/5; bestehende Mapping-Tests werden entsprechend angepasst.
- Bestehende 429-Tests bleiben grün (`TestCCClientSendParsesTopLevelRateLimitError`, `TestChatCompletionsReturnsNormalizedUpstreamRateLimit`, `TestCCClientAllAccountsRateLimited`).

### AD-6 – Privacy Logging (Phase 8)
Ist: **teilweise** — Admin maskiert Keys bereits (`MaskedKey`, Tests `admin_test.go:89/290`), aber bei `cfg.Debug` wird der komplette Request-Body geloggt (`handler.go:30`), rohe Upstream-SSE-Events inkl. `raw=` (`handler.go:231/296`), und Fehlerlogs (`handler.go:60/70`) können Upstream-Messages mit Body-Fragmenten enthalten.

Tasks:
1. Redaction-Helper in `internal/app/logging.go`: `redactKey`, `redactHeader`, `redactError` — Ausgabe als Präfix + letzte 4 Zeichen (z. B. `ccgw-…a1b2` bzw. `user_…a1b2`), nie vollständig; funktioniert für Client- **und** Account-Keys.
2. Systematische Audit-Liste aller `log.Printf`-Stellen (`handler.go`: 30, 60, 70, 82, 231, 262, 269, 296, 323, 332, 397, 415, 430; `cc.go`: 237; `admin.go`: 156, 285, 338, 564, 642, 651, 655, 661; `oauth.go`: 355, 376; `models.go`): keine `Authorization`/`x-api-key`-Werte, keine Key-Fragmente, keine Upstream-Roh-Bodies, keine Stacktraces (`%+v` auf Credential-Strukturen, `debug.Stack` verboten).
3. Debug-Body-Logging absichern: Header gar nicht loggen; sensible JSON-Keys (`api_key`, `key`, `token`, `authorization`, `password`) rekursiv maskieren; rohe SSE-Events auf maskierte Kurzform bzw. `event type` reduzieren.
4. Logging nur noch über den redigierenden Helper, damit die Regel zentral testbar bleibt.

Akzeptanzkriterien:
- Test `TestLogsNeverLeakAPIKey`: Debug an, Request mit `user_testkey_1234567890` plus Upstream-Fehlerbody, der den Key enthält ⇒ Log-Puffer enthält weder den vollen Key noch `sk-`-Muster noch den Key nach `Bearer `; nur maskierte Form.
- Test `TestDebugLoggingMasksSensitiveJSONKeys`: Body mit `api_key`/`password` ⇒ Werte im Log maskiert.
- Test, dass Fehlerlogs keine Stacktraces enthalten (kein `\.go:` + Zeilennummer im Log-Puffer).
- Admin-Masking-Tests (`admin_test.go:89/290`) bleiben unverändert grün.
- Grep-basierter Gate-Test: kein `log.*`-Aufruf im Paket gibt `Authorization`, rohe Body-Bytes oder `%+v` auf Credential-Strukturen aus.

## Phase 0 – Risiko- und Scope-Klärung

**Status 2026-09-13: Entscheidung dokumentiert, Restrisiko bleibt offen.**

- **Gegenstand:** Multi-Account-Pooling plus CLI-Header-Spoofing (Fingerprint, Lifecycle, Session, Version, Trace) gegenüber dem Command-Code-Upstream.
- **Bewertung:** Die Nutzungsbedingungen des Anbieters wurden **nicht** juristisch geprüft. Es ist ungeklärt, ob das Pooling mehrerer Accounts und das Nachbilden der CLI-Metadaten als Verstoß gewertet werden. Diese Frage kann nur der Betreiber verbindlich beantworten; sie ist keine Code-Entscheidung.
- **Entscheidung:** Die Umsetzung erfolgt wie in diesem Dokument beschrieben, weil die Aufgabe „Anti-Detection-Parität" ausdrücklich im Scope ist. Das Risiko liegt beim Betreiber; wer die Software einsetzt, muss die Vereinbarkeit vorher selbst klären.
- **Nicht nachgebildet / bewusst abweichend:** Persistente Fingerprint-/Session-Persistenz in `detection.json` statt reiner In-Process-Maps (behebt das Mehr-Instanz-Problem der Referenz); keine Key-Fragmente und keine Upstream-Rohbodies in Logs (AD-6); `x-project-slug` folgt dem Code der Referenz, nicht deren README-Default.
- **Offene Nebenwirkung:** Zusätzliche Fingerprint-/Lifecycle-Requests pro Key belasten Rate-Limits; sie sind nicht am Account-Cooling beteiligt und blockieren den Completion-Pfad nicht (eigene In-Flight-Sperre pro Key).

## Phase 1 – Ist-Zustand erfassen (Compatibility-Matrix)
Ziel: Belegte, reproduzierbare Vergleichstabelle statt Annahmen.
- Werkzeug: HTTP-Capture (z. B. mitmproxy) des offiziellen CLI-Clients vs. cmdcode2api-Ausgabe.
- Vergleichsdimensionen: HTTP-Header, Request-Body, Session-Verhalten, Account-Wechsel, CLI-Version, Lifecycle-Requests, Error-/Retry-Verhalten, **SSE-Stream-Protokoll-Lifecycle** (nicht HTTP-Session-Lifecycle!), Image Requests, Modell-Namen, OAuth.
- Ergebnis: Tabellarische Compatibility-Matrix (Feld | offizieller Client | cmdcode2api | Abweichung | Action-Item).
- Explizites Ergebnis dieser Phase: Klärung, ob Lifecycle-/Session-Endpunkte noch Teil des offiziellen Clients sind — nicht mehr als Grundsatzfrage (die Umsetzung ist mit AD-3 beschlossen), sondern als Grundlage für die Feld-/Endpunkt-Ausgestaltung.

## Phase 2 – CLI-Version dynamisch machen
Aktuell hardcodiert in `internal/app/cc.go`:
`httpReq.Header.Set("x-command-code-version", "0.24.1")`

Neue Komponente: `internal/app/cliversion.go`
- CLI-Version-Provider mit Startup-Ermittlung, lokalem Cache, periodischem Update, Fallback auf bekannte Version.
- Zugriff auf den Cache muss thread-safe sein (`sync.RWMutex` oder `atomic.Value`), da mehrere Accounts/Streams gleichzeitig zugreifen.
- Keine zusätzliche Anfrage pro Completion.
- Admin-WebUI zeigt aktuelle Version, optional manuelles Refresh.

## Phase 3 – Request Context einführen
```go
type ClientContext struct {
    AccountID  string
    SessionID  string  // Per-Key-Session (AD-3/v2); leer, bis v2 umgesetzt ist
    CLIVersion string
    CreatedAt  time.Time
}
```
- Context gehört zum Account, nicht global zum Gateway (ein `ClientContext` pro Account-Instanz).
- Diese Struktur wird gemeinsam mit den Health-/Quota-Feldern aus Phase 7 in einem einzigen Account-Refactoring eingeführt, um doppelte Migrationen zu vermeiden.

## Phase 4 – CLI-Metadaten kapseln
Statt verstreuter `Header.Set(...)`-Aufrufe:
```go
type CLIRequestMetadata struct {
    Version       string // aus cliversion.go (AD-1)
    Environment   string
    SessionID     string // x-session-id: Client-Header > prompt_cache_key > Per-Key-Session
    ProjectSlug   string // aus der Session-ID (AD-3)
    Traceparent   string // W3C Trace Context, pro Request neu
    CoFlag        bool   // x-co-flag: "false"
    TasteLearning bool   // x-taste-learning: "false"
    ZDREnabled    bool   // x-cmd-zdr: "1" (optional)
}

func (m CLIRequestMetadata) Apply(req *http.Request)
```
Die Handshake-Requests (Fingerprint/Lifecycle) nutzen eine **reduzierte** Teilmenge: Version + Environment + Authorization + optional ZDR, aber **kein** `traceparent`, `x-session-id` oder `x-project-slug` (Referenzverhalten).

Ziel: zentrale, testbare Erzeugung CLI-kompatibler Requests.

## Phase 5 – Lifecycle/Session-Modell
**Status:** Ursprünglich als blockiert markiert (unbestätigte Annahme). Durch das Ziel "Anti-Detection-Parität" wieder aktiviert: Per-Key-Session (12h + 1h Jitter) und `POST /alpha/lifecycle-events` sind ausdrücklich gefordert und müssen daher implementiert werden, sobald Phase 1 die Endpunkte bestätigt hat.

Historischer Stand (überholt): Phase 1 hatte **nicht** bestätigt, dass der Command-Code-Client Lifecycle-/Session-Endpunkte verwendet. Die Command-Code-API (`/alpha/generate`) ist **stateless**: jede Completion-Anfrage ist unabhängig, es gibt keine Session-Initialisierung, keine Session-Token, keinen Session-TTL und keinen Reconnect-Mechanismus.

Beispielsweise testet `protocol_lifecycle_test.go` den **SSE-Stream-Protokoll-Lifecycle** (text-delta → finish → [DONE], tool-call-Authorität, malformed-SSE-Ablehnung) — das ist **nicht** dasselbe wie HTTP-Session-Lifecycle.

**Entscheidung (2026-09-12):** Der frühere Vorschlag, diese Phase zu **streichen**, ist **aufgehoben** — die Anti-Detection-Parität verlangt Fingerprint-Aufzeichnung, `cli_session_exists` und eine Per-Key-Session (AD-3, v2). Offen ist ausschließlich die **Feld-/Endpunkt-Ausgestaltung** (Phase 1) sowie die Anforderung, dass die Zusatz-Requests den Completion-Pfad nicht blockieren.

Unverändert gültig:
- Die `ClientContext`-Struktur (Phase 3, **nicht** Phase 6) existiert unabhängig vom Session-State und wird bereits in v1 eingeführt.
- Die "Kein Replay nach Stream-Beginn"-Anforderung ist bereits im Code (`CCClient.Send` in cc.go:196) und getestet (`TestCCClientSendUsesRequestContext`, `TestCCClientNoFailoverOnInvalidRequest`).

Hinweis: Die frühere Ausnahme "künstliche Randomisierungen, deren einziger Zweck die Umgehung von Erkennungssystemen ist, sind ausgeschlossen" ist mit dem Ziel "Anti-Detection-Parität" aufgehoben. Randomisierte Fingerprints und Session-Jitter sind Teil des Scopes; die Vereinbarkeit mit den Nutzungsbedingungen wird in Phase 0 dokumentiert.

## Phase 6 – Request Builder
Statt `OpenAI Request → openAIToCC() → HTTP` einen zentralen Builder einführen:
`OpenAI Request → CC Request Builder (messages, model, config, session, CLI-Metadaten, capabilities) → HTTP Request`

`session` ist mit dem Ziel "Anti-Detection-Parität" **verbindlich** (AD-3/v2); offen ist nur die Feld-Ausgestaltung aus Phase 1.

Ziel: OpenAI- und später Anthropic-kompatible Eingänge nutzen denselben Upstream-Builder.

## Phase 7 – Account Pool erweitern
Bestehend und bestätigt vorhanden: Round-Robin (`AccountPool.Acquire` in accounts.go:177), Failover bei 401/403/429/5xx (`shouldFailover` in **cc.go:262**, nicht in accounts.go), Cooldown (`Account.rateLimitedUntil` in accounts.go:33), kein Replay nach Stream-Beginn (`CCClient.Send` in cc.go:196).

Bestehende Account-Gesundheitsfelder (Einzel-Felder, nicht konsolidiert): `Errors` (atomic counter), `lastError`, `lastErrorAt`, `lastUsedAt`, `rateLimitedUntil`, `authFailures`.

Nicht existierend, neu in diesem Refactoring: `ClientContext` (Phase 3), `session` + Fingerprint-State (**AD-3**, v2 — verbindlich), `health` (als konsolidierte Struktur), `quota`, in-flight Request-Zähler (aktive Requests).

Erweiterung (im selben Refactoring wie Phase 3):
```
AccountPool
 ├── Account
 │    ├── credentials (aktuell plaintext in config.yaml — Verschlüsselung at-rest ist Phase 8)
 │    ├── ClientContext      ← neu (Phase 3)
 │    ├── session            ← neu (AD-3/v2: Session-ID + Ablauf, persistiert in detection.json)
 │    ├── fingerprint        ← neu (AD-3/v2: Profil + SHA-256-Hash, persistiert in detection.json)
 │    ├── health             ← konsolidiert aus bestehenden Feldern + in-flight Counter
 │    └── quota              ← neu
 ├── selection
 ├── cooldown
 └── failover
```
Zusätzlich: Account Health State (letzte erfolgreiche Anfrage bestehend, letzte Fehlermeldung bestehend, Rate-Limit-Zeitpunkt bestehend, aktive Requests neu, optional Quota-Information neu).

## Phase 8 – Observability
Pro Account tracken: Requests, Tokens, Errors, 429, 401/403, durchschnittliche Latenz, letzter Erfolg/Fehler, Cooldown, Session-Status.

Bestehend (`internal/app/usage.go`):
- `UsageTracker` trackt Requests, Prompt-Tokens, Completion-Tokens, Cache-Read/Write-Tokens (global + pro Account-ID + pro ClientKey-ID).
- `Account` trackt Errors (total), lastError, lastErrorAt, lastUsedAt, rateLimitedUntil (`accounts.go`).

Neu in dieser Phase:
- 429/401/403 als separate Fehler-Zähler (bisher nur `authFailures` und generischer `Errors`-Counter).
- Durchschnittliche Latenz pro Account (Request-Dauer messen, bisher nicht erfasst).
- in-flight Request-Zähler (aktive Requests, bisher nicht vorhanden).
- Session-Status und Fingerprint-Zustand (**AD-3/v2** — werden erst dort eingeführt, hier erst relevant).
- Consecutive-Timeout-Zähler **prozess-global** (**AD-5.3**) — eigener Zähler, nicht mit Upstream-429 vermischen; Account-Health bleibt bei `authFailures`/`errors`.
- Zero-Output-Fehler (AD-5.4c) erscheinen **nicht** als Upstream-429-Zähler, sondern über den generischen `Errors`-Zähler mit eigenem Fehlertyp.

- Keine sensiblen Credential-/Token-Daten loggen.
- Credentials selbst (config/DB) verschlüsselt at-rest speichern, nicht nur aus Logs fernhalten (aktuell plaintext in config.yaml, `AccountConfig.APIKey`).

## Phase 9 – Migration & Abwärtskompatibilität
- Bestehende `config.yaml`-Dateien ohne Session-/ClientContext-Felder müssen mit sinnvollen Defaults weiterhin laden.
- `SessionID`-Feld in `ClientContext` bleibt leer, bis AD-3 umgesetzt ist; bis dahin enthalten weder `config.yaml` noch `detection.json` Session-Felder, und ein fehlendes `detection.json` ist der Normalzustand (Erststart).
- `detection.json` ist reiner Laufzeit-State, kein Konfigurations-Schema: kein Eintrag in `config.yaml`, keine Migration bei bestehenden Installationen; korrupte Datei ⇒ `[WARN]` + Neuaufbau (siehe AD-3.6a).
- Config-Schema-Version dokumentieren.

## Phase 10 – Tests
Bestehende Tests (nicht wiederholen):
- Account-Pool Round-Robin, Cooldown, Skip-Disabled/RateLimited: `accounts_test.go` (TestAccountPoolRoundRobin, TestAccountPoolSkipsDisabledAndRateLimited, TestAccountPoolAllLimitedReturnsNil)
- Failover (429 → anderer Account): `accounts_test.go` (TestCCClientFailoverOnRateLimit, TestCCClientAllAccountsRateLimited)
- Failover-Verweigerung bei 400/Intern: `accounts_test.go` (TestCCClientNoFailoverOnInvalidRequest, TestCCClientNoEnabledAccounts, TestShouldFailoverMatrix)
- Auth-Fehler-Zählung: `accounts_test.go` (TestAccountRecordFailureTracksAuthFailures)
- 429 Retry-After-Parsing + Fehlercode-Preservation: `cc_test.go` (TestCCClientSendParsesTopLevelRateLimitError, TestRetryAfterFromRateLimitMessage, TestCCClientSendPreservesNestedUpstreamErrorCode)
- Stream-Anfrage-Kontext (kein Replay): `cc_test.go` (TestCCClientSendUsesRequestContext)
- Request Builder (`openAIToCC`, `ContentToCC`, `SystemContentPartsArePreserved`, etc.): `cc_test.go`, `budget_test.go`
- SSE-Stream-Protokoll-Lifecycle (text-delta → finish → [DONE], tool-call-Authorität, malformed-Ablehnung): `protocol_lifecycle_test.go` (TestHandleStreamSurfacesUpstreamError, TestHandleStreamRejectsDoneWithoutFinish, TestParseStreamEventsCombinesMultilineData, uvm.)
- SSE-Stream-Protokoll-Lifecycle (weitere, in handler_test.go): (TestHandleStreamEmitsDoneOnceWithFinishStep, TestHandleStreamRejectsWhenFinishNeverArrives, TestHandleStreamRejectsToolCallWhenUpstreamAborts, uvm.)
- HTTP 429 Response-Normalisierung: `handler_test.go` (TestChatCompletionsReturnsNormalizedUpstreamRateLimit)
- Tool-Call-Authorität (provisional vs. authoritative): `authoritative_test.go` (TestAuthoritativeToolCallSupersedesProvisional, TestMalformedProvisionalCanBeSupersededByAuthoritative, uvm.)
- Usage-Tracking: `accounts_test.go` (TestUsageForAccountRecordsSeparately, TestUsageSnapshotPersistsAccounts), `clientkeys_test.go` (TestUsageRecorderClientKeyDimension, TestUsageSnapshotPersistsClientKeys)
- Config-Migration: `accounts_test.go` (TestLoadConfigMigratesLegacySingleKey, TestSaveConfigClearsLegacyKeyWhenAccountsExist)
- Client-Key-Auth: `clientkeys_test.go` (TestClientKeyPoolBasics, TestAuthMiddlewareUsesClientKeyPool, TestAuthMiddlewareLegacyFallback)
- IP-Rate-Limiting: `ratelimit_test.go` (TestIPRateLimiterLockoutWindow, TestAdminAuthRateLimitsBruteForce)

Neue Tests benötigt: CLI-Version (cliversion.go) → AD-1, Header-Generierung (CLIRequestMetadata.Apply) → AD-2, Session-Lifecycle/Fingerprint inkl. `detection.json`-Persistenz → AD-3 (Umsetzung beschlossen; PENDING ist nur die Feld-/Endpunkt-Ausgestaltung aus Phase 1, siehe Phase 5), Envelope/`reasoning_effort` → AD-4, Key-Validierung/Timeouts/Zero-Output/Abort → AD-5, Privacy-Logging → AD-6, Account-Context Integration (ClientContext Zuordnung). Die konkreten Akzeptanzkriterien je ID stehen im Abschnitt "Anti-Detection: Tasks & Akzeptanzkriterien".

Integration Tests (Mock Command-Code API): 200, 401, 403, 429, 500, Stream-Disconnect, malformed SSE, slow response.

Besonders wichtig, mit Status der bestehenden Abdeckung:
- Account A → 429, Account B → 200 (Failover funktioniert) — **abgedeckt**: `TestCCClientFailoverOnRateLimit`
- Account A → Stream beginnt → Fehler → KEIN Replay auf Account B — **bedingt abgedeckt**: `TestCCClientNoFailoverOnInvalidRequest` + `protocol_lifecycle_test.go` / `authoritative_test.go` (TestHandleStreamRejectsToolCallWhenUpstreamAborts, TestProvisionalInputsNeverBecomeExecutableCalls, TestBufferedCallNotReleasedOnAbort)
- Account A → 429 mit Retry-After → Cooldown beachtet — **abgedeckt**: `TestCCClientSendParsesTopLevelRateLimitError` + `TestRetryAfterFromRateLimitMessage`
- Alle Accounts rate-limited → 429 an Client — **abgedeckt**: `TestCCClientAllAccountsRateLimited`
- 401/403 → Account deaktiviert, nicht mehr ausgewählt — **abgedeckt**: `TestAccountRecordFailureTracksAuthFailures` + `TestAccountPoolSkipsDisabledAndRateLimited`

## Phase 11 – Gateway-Robustheit (neu)
Edge-Härtung, die **nicht** Teil der CLI-Simulation ist: Upstream-Key-Hygiene (`user_…`) plus Client-Syntax (`x-api-key`), Idle-Watchdogs 30s (Streaming) und 90s (`stream:false`), beide mit Reset pro Chunk, Consecutive-Timeout-Hinweis nach 3 Timeouts, Zero-Output-Guard, Upstream-Abort und Abbau der beiden 600s-Wände. Tasks und Akzeptanzkriterien: **AD-5** (Release v3).

## Priorisierung (Releases)
- **v1 — Compatibility Foundation** (AD-1, AD-2, AD-4): Phase 0, Phase 1 (Compatibility-Matrix), dynamische CLI-Version, CLIRequestMetadata, ClientContext (ohne Session-State), Account-Refactoring (Context + Health/Quota gemeinsam — Health-Felder bereits vorhanden als Einzel-Felder in `Account`, `UsageTracker` bereits in `usage.go`), Request Builder (bestehende `openAIToCC` erweitern), Tests (neue Tests für CLI-Version, Header-Generierung, Account-Context)
- **v2 — Session/Protocol** (AD-3): Session Management, Per-Key-Session (12h + 1h Jitter), `POST /alpha/lifecycle-events` und `POST /alpha/fingerprint/record` (Ziel "Anti-Detection-Parität"); verbleibend **PENDING Phase 1-Ergebnis** ist nur noch die genaue Ausgestaltung der Endpunkte/Felder, nicht mehr die Frage ob Session-State existiert. Context Persistence, sauberes Reconnect-Verhalten, SSE-Protokoll-Tests (`protocol_lifecycle_test.go` bereits vorhanden)
- **v3 — Gateway** (AD-5, AD-6): Account Health, bessere Quota-Auswahl, Metrics, WebUI, Debugging/Diagnostics, Config-Migration (Phase 9), Gateway-Robustheit aus dem Anti-Detection-Ziel (Upstream-Key-Regex + Client-Syntax-Härtung, Idle-Watchdogs 30s/90s mit `Retry-After: 5`, globaler Consecutive-Timeout-Hinweis nach 3 Timeouts, strikter Zero-Output-Guard → 429, Upstream-Abort bei Client-Disconnect, Abbau der 600s-Wände), zusätzlich nachgezogen: Backpressure/Drain mit optionalem Stall-Timeout, In-Flight-Cap (503 `server_busy`), 413 mit Drain, Status-Mapping-Tabelle
- **v4 — API Compatibility**: OpenAI Responses API, Anthropic Messages API, bessere Tool Calls, Reasoning (reasoning_effort-Pass-through aus AD-4), Vision

## Zielarchitektur
```
                         ┌──────────────────────┐
                         │      WebUI/Admin      │
                         └──────────┬───────────┘
                                    │
                         ┌──────────▼───────────┐
                         │     Account Pool      │
                         └──────────┬───────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
         Account A             Account B             Account C
              │                     │                     │
        ClientContext          ClientContext          ClientContext
              │                     │                     │
     Session + Fingerprint  Session + Fingerprint  Session + Fingerprint
          [AD-3, v2]             [AD-3, v2]             [AD-3, v2]
              │                     │                     │
              └─────────────────────┼─────────────────────┘
                                    ▼
                           ┌──────────────────┐
                           │ Request Builder  │
                           └────────┬─────────┘
                                    │
                           CLI-compatible
                           request metadata
                                    │
                                    ▼
                         Command Code upstream
```