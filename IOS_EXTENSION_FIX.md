# iOS Extension Fix Guide

## Probleme identifiziert

### 1. Backend: ✅ GELÖST
- clientDataJSON wird jetzt als base64url encoded string gesendet
- Synthetisches clientDataJSON für iOS Extensions implementiert

### 2. iOS Extension: ❌ ZU LÖSEN

#### Problem A: App Attest in Extensions
```
DCAppAttestService.isSupported: false
❌ App Attest NOT SUPPORTED on this device!
```
**Das ist normal!** Extensions unterstützen kein App Attest.

#### Problem B: Keine pre-generierten Attestations
```
❌ No pre-generated attestations available!
```
Die Extension findet keine Attestations im Shared Container.

## Lösungsschritte

### 1. Verifiziere Hauptapp Generierung
Starte die Hauptapp und prüfe die Logs:
- Sollte zeigen: "🔑 Generating X App Attest keys..."
- Sollte zeigen: "✅ Pre-generation complete!"

### 2. Debug Shared Container
In der Extension, füge Debug-Code hinzu:
```swift
// In Registration+Combined.swift
private func debugSharedContainer() {
    let defaults = UserDefaults(suiteName: "group.com.merckgroup.passkeyguard.dev")
    let key = "com.merckgroup.passkeyguard.pregeneratedattestations"
    
    if let data = defaults?.data(forKey: key) {
        print("✅ Found attestation data: \(data.count) bytes")
        if let attestations = try? JSONDecoder().decode([PreGeneratedAttestation].self, from: data) {
            print("✅ Decoded \(attestations.count) attestations")
            print("📊 Unused: \(attestations.filter { !$0.used }.count)")
        }
    } else {
        print("❌ No attestation data in shared container")
    }
}
```

### 3. Bundle ID Mismatch
Prüfe ob die Bundle IDs übereinstimmen:
- Hauptapp: `com.merckgroup.passkeyguard.dev`
- Extension: `com.merckgroup.passkeyguard.dev.autofill`
- AppAttestPreGenerator verwendet: `com.merckgroup.passkeyguard` (FALSCH!)

### 4. Extension Code anpassen
Die Extension sollte NIEMALS selbst generieren:
```swift
// ENTFERNEN aus Extension:
AppAttestInitializer.shared.setupInitialKeyGeneration()  

// NUR in Hauptapp!
```

## Quick Fix Checkliste

1. [ ] Backend deployen mit clientDataJSON Fix
2. [ ] Hauptapp starten und Attestation-Generierung verifizieren
3. [ ] Debug-Code in Extension hinzufügen
4. [ ] Bundle ID in AppAttestPreGenerator korrigieren
5. [ ] Extension Code bereinigen (keine eigene Generierung)

## Test-Flow

1. App löschen und neu installieren
2. Hauptapp starten und 10 Sekunden warten
3. Safari öffnen und Registrierung versuchen
4. Logs prüfen für "Retrieved attestation"