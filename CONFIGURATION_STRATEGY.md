# Konfigurationsstrategie für Dual-Mode Passkey System

## Use Cases

1. **Standard Mode** (für alle Kunden außer Merck)
   - Nur Passkey-Registrierung
   - Nutzt `/api/register` und `/api/register/verify`
   - Keine App Attest Anforderung
   - Standard WebAuthn Flow

2. **Enhanced Mode** (nur für Merck)
   - Combined Registration: Passkey + App Attest
   - Nutzt `/api/register/combined`
   - Erfordert iOS App mit App Attest
   - Zusätzliche Sicherheitsebene

## Backend Konfiguration

### Option 1: Environment Variables
```env
# .env file
ENABLE_APP_ATTEST=true
APP_ATTEST_REQUIRED=false  # wenn true, MUSS App Attest vorhanden sein
APP_ATTEST_DOMAINS=merck.com,merckgroup.com
```

### Option 2: Domain-basierte Erkennung
```javascript
// config/security.js
const ENHANCED_SECURITY_DOMAINS = [
  'merck.com',
  'merckgroup.com',
  'emdgroup.com'
];

function requiresAppAttest(email) {
  const domain = email.split('@')[1];
  return ENHANCED_SECURITY_DOMAINS.includes(domain);
}
```

### Option 3: Tenant-basierte Konfiguration
```javascript
// config/tenants.js
const TENANT_CONFIG = {
  'merck': {
    requireAppAttest: true,
    allowStandardRegistration: false
  },
  'default': {
    requireAppAttest: false,
    allowStandardRegistration: true
  }
};
```

## iOS App Konfiguration

### Build Configurations
```swift
// BuildConfiguration.swift
struct BuildConfiguration {
    static let isAppAttestEnabled = {
        #if MERCK_BUILD
        return true
        #else
        return false
        #endif
    }()
    
    static let backendMode: BackendMode = {
        #if MERCK_BUILD
        return .enhanced
        #else
        return .standard
        #endif
    }()
}

enum BackendMode {
    case standard    // nur Passkey
    case enhanced   // Passkey + App Attest
}
```

### Dynamic Configuration
```swift
// ConfigurationService.swift
class ConfigurationService {
    static let shared = ConfigurationService()
    
    func getRegistrationMode(for domain: String) -> RegistrationMode {
        // Könnte von einem Config-Endpoint kommen
        let enhancedDomains = ["merck.com", "merckgroup.com"]
        
        if enhancedDomains.contains(domain) {
            return .combined
        }
        return .standard
    }
}

enum RegistrationMode {
    case standard
    case combined
}
```

## Backend Implementation

### 1. Flexible Endpoint
```javascript
// server.ts
app.post("/api/register/verify", async (req, res) => {
  const { username, credential, appAttest } = req.body;
  
  // Check if this user/domain requires App Attest
  const requiresAppAttest = await checkAppAttestRequirement(username);
  
  if (requiresAppAttest && !appAttest) {
    return res.status(400).json({
      error: "App Attest required for this account"
    });
  }
  
  // Regular passkey verification
  const passkeyResult = await verifyPasskey(credential, username);
  
  // Optional App Attest verification
  if (appAttest) {
    const attestResult = await verifyAppAttest(appAttest);
    // Store both credentials
  }
  
  res.json({ success: true });
});
```

### 2. Feature Flags
```javascript
// featureFlags.js
const FLAGS = {
  APP_ATTEST_ENABLED: process.env.APP_ATTEST_ENABLED === 'true',
  APP_ATTEST_REQUIRED_DOMAINS: process.env.APP_ATTEST_DOMAINS?.split(',') || [],
  ALLOW_STANDARD_REGISTRATION: process.env.ALLOW_STANDARD_REG !== 'false'
};

function isAppAttestRequired(email) {
  if (!FLAGS.APP_ATTEST_ENABLED) return false;
  
  const domain = email.split('@')[1];
  return FLAGS.APP_ATTEST_REQUIRED_DOMAINS.includes(domain);
}
```

## iOS Extension Flow

```swift
// Registration+Combined.swift
extension RegistrationCoordinator {
    
    func performRegistration(for identity: ASPasskeyCredentialIdentity) async throws {
        // Check configuration
        let mode = ConfigurationService.shared.getRegistrationMode(for: identity.relyingPartyIdentifier)
        
        switch mode {
        case .standard:
            // Standard flow: register -> verify
            let credential = try await registerPasskey(identity: identity)
            try await verifyRegistration(credential: credential)
            
        case .combined:
            // Enhanced flow: combined registration
            try await performCombinedRegistration(for: identity)
        }
    }
}
```

## Empfohlene Lösung

**Kombination aus Option 2 + Feature Flags:**

1. **Backend erkennt automatisch** anhand der Email-Domain
2. **iOS App prüft** beim Start die Konfiguration
3. **Graceful Degradation**: Wenn App Attest nicht verfügbar, fällt zurück auf Standard

```javascript
// Backend
const registrationConfig = {
  isAppAttestAvailable: (req) => req.body.platform === 'ios-extension',
  isAppAttestRequired: (email) => email.endsWith('@merck.com'),
  allowStandardFallback: true
};

// Entscheidungslogik
if (config.isAppAttestRequired(email)) {
  if (config.isAppAttestAvailable(req)) {
    // Use combined registration
    return handleCombinedRegistration(req, res);
  } else if (config.allowStandardFallback) {
    // Fallback to standard
    return handleStandardRegistration(req, res);
  } else {
    // Reject
    return res.status(400).json({ error: "Enhanced security required" });
  }
}
```

## Migration Strategy

1. **Phase 1**: Beide Modi parallel (current state)
2. **Phase 2**: Merck-Domains auf Enhanced Mode umstellen
3. **Phase 3**: Monitoring und Optimierung
4. **Phase 4**: Ggf. weitere Enterprise-Kunden auf Enhanced Mode

## Testing

```bash
# Test Standard Mode
EMAIL=user@example.com npm test

# Test Enhanced Mode  
EMAIL=user@merck.com npm test

# Test Fallback
APP_ATTEST_ENABLED=false EMAIL=user@merck.com npm test
```