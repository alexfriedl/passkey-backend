# Apple App Attest Integration

Diese Dokumentation beschreibt die Integration von Apple App Attest mit lokalem Challenge-Hash in das Passkey-Backend.

## Übersicht

Das System unterstützt jetzt zwei parallele Authentifizierungsmethoden:
1. **WebAuthn/Passkeys** - für Benutzer-Authentifizierung
2. **Apple App Attest** - für App-/Geräte-Integrität mit lokaler Challenge

## Besonderheit: Lokale Challenge-Generierung

Im Gegensatz zum Standard-Flow wird die Challenge nicht vom Server generiert, sondern lokal in der iOS-App aus Formulardaten erstellt:

```
Formulardaten → SHA256 Hash → clientDataHash → attestKey()
```

## Endpoints

### POST `/api/appattest/attest`
Verifiziert eine Apple App Attest Attestation mit lokaler Challenge.

**Request Body:**
```json
{
  "username": "alice",
  "keyId": "<Base64URL encoded keyId>",
  "attestationObject": "<Base64URL encoded attestation object>",
  "localChallenge": "<Base64URL encoded SHA256 hash der Formulardaten>"
}
```

**Response:**
```json
{
  "verified": true,
  "keyId": "...",
  "publicKey": "...",
  "counter": 0,
  "appId": "TEAMID.com.example.app",
  "formats": {
    "fido2Wrapper": {
      "type": "wrapped-attestation",
      "original": {...},
      "credential": {...}
    }
  }
}
```

### GET `/api/appattest/challenge` (Optional)
Für hybriden Ansatz mit Server-Nonce.

## iOS Integration

### 1. Formulardaten hashen

```swift
// Formulardaten normalisieren
let formData: [String: Any] = [
    "action": "transfer",
    "amount": 100,
    "to": "bob",
    "timestamp": ISO8601DateFormatter().string(from: Date())
]

// Deterministisches JSON erstellen
let sortedKeys = formData.keys.sorted()
let jsonData = try JSONSerialization.data(withJSONObject: formData)

// Hash berechnen
let clientDataHash = Data(SHA256.hash(data: jsonData))
```

### 2. App Attest durchführen

```swift
import DeviceCheck

let service = DCAppAttestService.shared

// Key generieren (einmalig pro Installation)
let keyId = try await service.generateKey()

// Attestation mit lokalem Hash
let attestationObject = try await service.attestKey(
    keyId, 
    clientDataHash: clientDataHash
)

// An Server senden
let request = AttestationRequest(
    username: "alice",
    keyId: keyId.base64EncodedString(),
    attestationObject: attestationObject.base64EncodedString(),
    localChallenge: clientDataHash.base64EncodedString()
)
```

## Format-Konvertierung

Da eine direkte Konvertierung von `apple-appattest` zu `packed` kryptografisch nicht möglich ist, bietet das System drei Alternativen:

### 1. FIDO2 Wrapper (Empfohlen)
Kapselt die App Attest Daten in einem FIDO2-kompatiblen Format.

### 2. Server-Attestation
Der Server erstellt ein eigenes signiertes Token basierend auf der verifizierten App Attest.

### 3. Packed-Like Format (Nur für Tests!)
Eine strukturell ähnliche Darstellung, die aber keine gültige packed-Attestation ist.

## Sicherheitshinweise

1. **Lokale Challenge**: Da die Challenge lokal generiert wird, muss der Server zusätzliche Maßnahmen ergreifen:
   - Zeitstempel in den Formulardaten einbeziehen
   - Session-Binding
   - Replay-Schutz durch Speichern verwendeter Attestations

2. **Format-Konvertierung**: Die konvertierten Formate sind keine echten FIDO2-Attestationen und sollten nur in kontrollierten Umgebungen verwendet werden.

3. **App ID Verifikation**: Immer die App ID (TeamID.BundleID) aus dem Zertifikat gegen die erwartete App ID prüfen.

## Datenbank-Schema

App Attest Keys werden in MongoDB gespeichert:

```typescript
{
  username: string;
  keyId: string;       // Base64URL
  publicKey: string;   // Base64URL
  counter: number;
  appId: string;       // TeamID.BundleID
  createdAt: Date;
  lastUsed: Date;
}
```

## Demo-Seite

Unter `/appattest-demo.html` ist eine interaktive Demo verfügbar, die den lokalen Challenge-Flow demonstriert.

## Nächste Schritte

1. Vollständige Zertifikatsketten-Validierung implementieren
2. Nonce-Extraktion aus Zertifikat-Extensions vervollständigen
3. Server-Key-Paar für Server-Attestation einrichten
4. Assertion-Flow für nachfolgende Requests implementieren