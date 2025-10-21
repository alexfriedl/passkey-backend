# App Attest Architecture für PasskeyGuard

## Problem

iOS Extensions (wie Credential Provider Extensions) unterstützen KEIN App Attest! Dies ist eine fundamentale iOS-Limitation:

- ❌ `DCAppAttestService.isSupported` gibt in Extensions immer `false` zurück
- ❌ Selbst auf physischen Geräten mit korrektem Bundle ID
- ✅ App Attest funktioniert NUR in der Hauptapp

## Lösung: Hauptapp als App Attest Provider

### Architektur

```
┌─────────────────────┐     ┌──────────────────────┐
│   Hauptapp (iOS)    │────▶│  Shared Container    │
│                     │     │                      │
│ - App Attest init   │     │ - Key Pool (10 Keys) │
│ - Key generation    │     │ - Attestations       │
│ - Attestation       │     │ - Metadata           │
└─────────────────────┘     └──────────────────────┘
                                       ▲
                                       │
                            ┌──────────────────────┐
                            │ Extension (Safari)   │
                            │                      │
                            │ - Read Keys only     │
                            │ - Use pre-generated  │
                            │   attestations       │
                            └──────────────────────┘
```

### Implementierungsschritte

1. **Hauptapp beim Start**:
   - Prüft Key Pool im Shared Container
   - Generiert fehlende Keys (bis zu 10)
   - Erstellt Attestations für jeden Key
   - Speichert alles im Shared Container

2. **Extension bei Registrierung**:
   - Liest pre-generated Attestation aus Pool
   - Verwendet sie für Combined Registration
   - Markiert Key als "verwendet"

3. **Hauptapp Background Task**:
   - Überwacht Pool-Größe
   - Füllt Pool bei Bedarf auf
   - Cleanup alter/ungenutzter Keys

### Code-Beispiel

```swift
// In Hauptapp AppDelegate
func application(_ application: UIApplication, 
                didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
    
    // App Attest Key Pool initialisieren
    Task {
        await AppAttestKeyPoolManager.shared.initializePool()
    }
    
    return true
}

// Key Pool Manager
class AppAttestKeyPoolManager {
    static let shared = AppAttestKeyPoolManager()
    private let targetPoolSize = 10
    
    func initializePool() async {
        guard DCAppAttestService.shared.isSupported else {
            print("❌ App Attest not supported")
            return
        }
        
        let currentPoolSize = getCurrentPoolSize()
        let keysNeeded = targetPoolSize - currentPoolSize
        
        if keysNeeded > 0 {
            print("🔑 Generating \(keysNeeded) App Attest keys...")
            await generateKeys(count: keysNeeded)
        }
    }
}
```

### Shared Container Struktur

```
group.com.company.app/
├── AppAttest/
│   ├── KeyPool/
│   │   ├── key1/
│   │   │   ├── keyId.txt
│   │   │   ├── attestation.dat
│   │   │   ├── challenge.txt
│   │   │   └── metadata.json
│   │   └── key2/...
│   └── pool_status.json
```

### Sicherheitsüberlegungen

1. **Pre-generation ist sicher**: Attestations beinhalten Challenge, die bei Verwendung validiert wird
2. **Pool-Größe**: 10 Keys reichen für normale Nutzung
3. **Cleanup**: Ungenutzte Keys nach 30 Tagen löschen
4. **Monitoring**: Hauptapp loggt Pool-Status

### Debugging

```swift
// In Extension
if !DCAppAttestService.shared.isSupported {
    print("❌ App Attest not supported in Extension - using pre-generated keys")
    let attestation = AppAttestKeyPoolManager.shared.getNextAvailableAttestation()
    // Use attestation...
}
```

## Zusammenfassung

- Extensions können kein App Attest generieren
- Hauptapp generiert Key Pool beim Start
- Extensions verwenden pre-generated Keys
- Shared Container für Kommunikation
- Backend akzeptiert beide Flows