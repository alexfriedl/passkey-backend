# PasskeyGuard Hardware-Bound Passkey Testing

## Übersicht

Diese Anleitung erklärt, wie du die Integration zwischen dem Backend und der PasskeyGuard iOS App testen kannst.

## Was wurde implementiert

### Backend Änderungen
- ✅ `register.html`: Deeplink-Support hinzugefügt (`passkeyguard://webauthn-completion`)
- ✅ `demo-rp.html`: Demo RP-Website für Hardware-bound Registrierung
- ✅ Auto-Start der Registrierung wenn von App geöffnet

### iOS App Änderungen
- ✅ SFSafariViewController Integration
- ✅ Deeplink Support (`passkeyguard://` und `passkeyguard://`)
- ✅ Passkey-Generierung im Main App Context
- ✅ DCAppAttest Hardware-Integrity Proof

## Testing Flow

### 1. Standard Registrierung (Baseline)
```
Browser → http://localhost:3000/register.html
```
- Normale WebAuthn Registrierung ohne PasskeyGuard App

### 2. Demo RP Website
```
Browser → http://localhost:3000/demo-rp.html
```
- Zeigt beide Registrierungsarten
- Erklärt den Hardware-bound Flow

### 3. Hardware-Bound Registrierung (Main Flow)

#### Schritt 1: RP Website generiert Deeplink
```javascript
const deeplink = `passkeyguard://?origin=${encodeURIComponent(registerUrl)}`;
window.location.href = deeplink;
```

#### Schritt 2: PasskeyGuard App öffnet sich
- App parst den `origin` Parameter
- Öffnet RP Website in SFSafariViewController

#### Schritt 3: WebAuthn läuft im Main App Context
- Registrierung erfolgt im Main App (nicht Extension)
- DCAppAttest Key wird generiert
- Hardware-Integrity wird bewiesen

#### Schritt 4: Zurück zur App
```javascript
const deeplink = `passkeyguard://webauthn-completion?status=success&token=${token}&username=${username}`;
window.location.href = deeplink;
```

## URL Schemes

### iOS App registriert:
1. `passkeyguard://` - Basis App Scheme
2. `passkeyguard://` - WebAuthn Initiierung

### Verwendete Deeplinks:

#### 1. RP → App (Start WebAuthn)
```
passkeyguard://?origin=https://example.com/register.html?username=testuser&hw=true
```

#### 2. App → App (Completion)
```
passkeyguard://webauthn-completion?status=success&token=abc123&username=testuser
```

## Testing Schritte

### Voraussetzungen
1. Backend läuft auf `localhost:3000`
2. PasskeyGuard iOS App ist installiert
3. iOS Simulator oder physisches Device

### Test 1: Demo RP
1. Öffne `http://localhost:3000/demo-rp.html`
2. Gib Username ein
3. Klicke "🔒 Hardware-bound Registrierung"
4. App sollte sich öffnen

### Test 2: Vollständiger Flow
1. RP Website → Deeplink → App öffnet sich
2. App → SFSafariViewController mit RP Website
3. WebAuthn Registrierung im Main App Context
4. DCAppAttest Generierung
5. Erfolg-Deeplink zurück zur App

## Debugging

### Backend Logs
```bash
# In passkey-backend Verzeichnis
npm start
# oder
yarn start
```

### iOS App Logs
- Xcode Console für detaillierte Logs
- Alle Deeplink-Aktionen werden geloggt

### Browser Developer Tools
- Netzwerk-Tab für API Calls
- Console für JavaScript Errors

## Erwartete Ergebnisse

### Erfolgreicher Hardware-Bound Flow:
1. ✅ Deeplink öffnet PasskeyGuard App
2. ✅ SFSafariViewController zeigt RP Website
3. ✅ WebAuthn Registrierung startet automatisch
4. ✅ DCAppAttest Key wird generiert
5. ✅ Passkey wird im Main App Context erstellt
6. ✅ Completion-Deeplink führt zurück zur App
7. ✅ Safari View wird geschlossen

### Unterschied zu Standard Flow:
- **Standard**: Passkey in Autofill Extension (Cloud-sync möglich)
- **Hardware-bound**: Passkey in Main App + DCAppAttest Proof

## Troubleshooting

### App öffnet sich nicht
- URL Scheme in Info.plist prüfen
- App installiert und auf dem Device verfügbar?

### Safari View öffnet sich nicht
- SFSafariViewController Import fehlt?
- presentSafari State korrekt?

### Deeplink-Parameter fehlen
- URL-Encoding korrekt?
- Query Parameter Format prüfen

### DCAppAttest Fehler
- iOS 14+ erforderlich
- App entitlements korrekt?
- Development vs Production Environment

## Logs zu beachten

### iOS App:
```
MAIN APP: Handling URL scheme: passkeyguard://...
MAIN APP: WebAuthn request received: ...
MAIN APP: Opening WebAuthn flow in Safari View for RP: ...
MAIN APP: DCAppAttest key generated: ...
MAIN APP: WebAuthn completion received: ...
```

### Backend:
```
Registrierung gestartet für: testuser (Hardware-bound: true)
Empfangene Optionen: {...}
Credential erfolgreich erstellt: {...}
Registrierung erfolgreich – starte Deeplink zurück zur App.
```