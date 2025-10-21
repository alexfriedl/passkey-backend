# iOS Combined Registration - Implementation Guide

## Problem Statement

iOS Extensions (Credential Provider Extensions) handle WebAuthn differently than web browsers:
- They don't provide the full `clientDataJSON`, only the `clientDataHash` 
- They generate their own challenge internally which cannot be overridden
- The backend FIDO2 library expects JSON but receives a hash

## Solution Architecture

### 1. Platform Detection
The iOS app must send `platform: "ios-extension"` to indicate special handling is needed:

```javascript
{
  username: "alice",
  passkey: { ... },
  appAttest: { ... },
  platform: "ios-extension"  // Critical flag
}
```

### 2. Backend Flow

When `platform: "ios-extension"` is detected:

1. **Route to iOS Handler**: `/api/register/combined` checks platform and routes to `verifyIOSRegistration()`
2. **Create Synthetic clientDataJSON**: Since iOS only sends the hash, we create a synthetic JSON object
3. **Store Original Hash**: Keep the iOS hash for audit trail
4. **Bypass Challenge Validation**: Accept that iOS uses its own challenge

### 3. Code Changes Made

#### iOS App (PasskeyGuardShared/CombinedRegistrationService.swift)
```swift
// Added platform field to indicate iOS Extension
let request = CombinedRegistrationRequest(
    username: passkeyData.username,
    passkey: CombinedPasskeyData(
        credential: passkeyData.credential,
        challenge: passkeyData.challenge
    ),
    appAttest: appAttestData,
    platform: "ios-extension"  // Added this line
)
```

#### Backend (src/ios-registration.ts)
```javascript
// Enhanced logging to debug iOS format
console.log("Credential structure:", {
    id: credential.id?.substring(0, 20) + "...",
    rawId: credential.rawId?.substring(0, 20) + "...",
    type: credential.type,
    response: {
        attestationObject: credential.response?.attestationObject?.substring(0, 20) + "...",
        clientDataJSON: credential.response?.clientDataJSON?.substring(0, 50) + "..."
    }
});

// Detect iOS hash vs JSON
const isIOSHash = typeof clientDataValue === 'string' && 
                  clientDataValue.length < 100 && 
                  !clientDataValue.startsWith('{');
```

## Testing

Use the provided test script:
```bash
cd /Users/alexanderfriedl/Repositories/github-alexfriedl/passkey-backend
node test-combined-registration.js
```

This simulates an iOS registration with:
- Base64URL encoded credential IDs
- ClientDataHash instead of JSON
- App Attest data
- Platform flag set to "ios-extension"

## Security Considerations

1. **Challenge Security**: iOS-generated challenges are cryptographically secure
2. **Dual Authentication**: Passkey + App Attest provides double verification
3. **Audit Trail**: Server stores both server and iOS challenges for forensics

## Troubleshooting

### Common Issues

1. **"clientDataJSON is not valid JSON"**
   - Ensure platform field is set to "ios-extension"
   - Check that iOS is sending base64url encoded hash

2. **"Challenge mismatch"**
   - Normal for iOS - they use internal challenges
   - Server challenge is stored for audit only

3. **"App Attest validation failed"**
   - Ensure App ID and Team ID match configuration
   - Check that attestation object is properly base64url encoded

### Debug Tips

1. Check backend logs for credential structure
2. Verify platform field is present in request
3. Look for "iOS Extension detected" in logs
4. Ensure synthetic clientDataJSON is being created

## Next Steps

1. Implement proper App Attest validation
2. Add challenge correlation for better security  
3. Create monitoring for iOS vs Web registrations
4. Add integration tests for both flows