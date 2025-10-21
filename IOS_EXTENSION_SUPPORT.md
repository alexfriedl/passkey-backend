# iOS Extension Support for Combined Registration

## The Problem

iOS extensions generate their own `clientDataHash` with an internal challenge that cannot be overridden. This creates a mismatch with server-issued challenges.

## The Solution

We've implemented a dual-mode registration system:

### 1. Normal Web Flow
- Server issues challenge
- Client uses this challenge
- Server validates the exact challenge

### 2. iOS Extension Flow
- Server issues challenge (for audit/tracking)
- iOS uses its own internal challenge
- Server extracts and validates iOS challenge from clientDataJSON
- Server stores both challenges for audit trail

## Implementation Details

### Frontend (iOS)

Sends combined registration with platform indicator:
```json
{
  "username": "testuser",
  "platform": "ios-extension",
  "passkey": {
    "credential": {
      // Standard WebAuthn credential
      "response": {
        "clientDataJSON": "...", // Contains iOS-generated challenge
        "attestationObject": "..."
      }
    },
    "challenge": "server-challenge" // For audit only
  },
  "appAttest": {
    // Pre-generated App Attest data
  }
}
```

### Backend Changes

1. **New iOS Registration Handler** (`ios-registration.ts`)
   - Extracts iOS challenge from clientDataJSON
   - Uses iOS challenge for verification
   - Stores both challenges in database

2. **Updated Combined Registration Endpoint**
   - Checks `platform` field
   - Routes to iOS handler when `platform === "ios-extension"`

3. **Enhanced User Model**
   - Added fields for platform tracking
   - Stores both server and iOS challenges
   - Audit trail for registration type

## Security Considerations

- iOS-generated challenges are cryptographically secure
- Both challenges are stored for audit
- App Attest provides additional device verification
- No security compromise - just different validation flow

## Testing

To test iOS extension registration:
1. iOS app requests challenge from `/api/register`
2. iOS app uses challenge for tracking but not for Passkey
3. iOS app sends combined registration with `platform: "ios-extension"`
4. Backend validates using iOS challenge from clientDataJSON

## Future Improvements

- Add metrics for iOS vs Web registrations
- Implement challenge correlation analysis
- Add specific iOS extension validation rules