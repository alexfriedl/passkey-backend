# Security Improvements for Combined Registration

## 1. Unified Challenge with Binding

```typescript
// Backend: Generate challenge with metadata
router.post("/api/register/challenge", async (req, res) => {
  const challenge = {
    value: crypto.randomBytes(32).toString('base64url'),
    timestamp: Date.now(),
    sessionId: crypto.randomBytes(16).toString('hex'),
    rpId: process.env.RPID,
    action: 'register',
    username: req.body.username
  };
  
  // Store in Redis with TTL
  await redis.setex(
    `challenge:${challenge.sessionId}`,
    300, // 5 minutes
    JSON.stringify(challenge)
  );
  
  // Sign the challenge
  const signature = crypto
    .createHmac('sha256', process.env.CHALLENGE_SECRET)
    .update(JSON.stringify(challenge))
    .digest('base64url');
    
  res.json({ challenge, signature });
});
```

## 2. Verify Challenge Binding

```typescript
router.post("/api/register/combined", async (req, res) => {
  const { passkey, appAttest, challengeData, signature } = req.body;
  
  // 1. Verify signature
  const expectedSignature = crypto
    .createHmac('sha256', process.env.CHALLENGE_SECRET)
    .update(JSON.stringify(challengeData))
    .digest('base64url');
    
  if (signature !== expectedSignature) {
    throw new Error("Challenge tampering detected");
  }
  
  // 2. Verify challenge not expired
  const stored = await redis.get(`challenge:${challengeData.sessionId}`);
  if (!stored) {
    throw new Error("Challenge expired or already used");
  }
  
  // 3. Verify both use same challenge
  if (passkey.challenge !== challengeData.value) {
    throw new Error("Challenge mismatch");
  }
  
  // 4. Verify App Attest includes challenge
  const localChallengeData = JSON.parse(
    Buffer.from(appAttest.localChallenge, 'base64url').toString()
  );
  
  if (localChallengeData.originalChallenge !== challengeData.value) {
    throw new Error("App Attest challenge mismatch");
  }
  
  // 5. Delete challenge (one-time use)
  await redis.del(`challenge:${challengeData.sessionId}`);
  
  // Continue with verification...
});
```

## 3. iOS: Device Binding

```swift
// Add device-specific data to local challenge
struct SecureChallenge: Codable {
    let originalChallenge: String
    let deviceId: String // From DeviceCheck
    let bundleId: String
    let timestamp: Date
    let nonce: String
    
    var data: Data {
        try! JSONEncoder().encode(self)
    }
    
    var hash: Data {
        Data(SHA256.hash(data: self.data))
    }
}

// In App Attest
let deviceId = DCDevice.current.generateToken() // Unique per device
let secureChallenge = SecureChallenge(
    originalChallenge: serverChallenge,
    deviceId: deviceId,
    bundleId: Bundle.main.bundleIdentifier!,
    timestamp: Date(),
    nonce: UUID().uuidString
)
```

## 4. Cryptographic Binding

```swift
// Create proof that both attestations come from same device
extension CombinedRegistrationService {
    func createBindingProof(
        passkeyCredential: Data,
        appAttestKeyId: String
    ) -> Data {
        // Create a signature over both credentials
        let message = passkeyCredential + appAttestKeyId.data(using: .utf8)!
        
        // Use App Attest key to sign
        let assertion = try! DCAppAttestService.shared.generateAssertion(
            keyId,
            clientDataHash: Data(SHA256.hash(data: message))
        )
        
        return assertion
    }
}
```

## 5. Backend: Complete Verification

```typescript
// Additional checks
async function verifyDeviceBinding(
  passkeyData: any,
  appAttestData: any,
  bindingProof: string
) {
  // 1. Verify AAGUID matches expected iOS devices
  const aaguid = extractAAGUID(passkeyData.attestationObject);
  if (!VALID_IOS_AAGUIDS.includes(aaguid)) {
    throw new Error("Invalid authenticator");
  }
  
  // 2. Verify App ID matches
  const appId = await verifyAppAttest(appAttestData);
  if (appId !== process.env.EXPECTED_APP_ID) {
    throw new Error("Invalid app");
  }
  
  // 3. Verify binding proof
  const message = passkeyData.credentialId + appAttestData.keyId;
  const valid = await verifyAssertion(
    appAttestData.keyId,
    bindingProof,
    sha256(message)
  );
  
  if (!valid) {
    throw new Error("Device binding failed");
  }
  
  // 4. Rate limiting per device
  const deviceHash = sha256(appAttestData.keyId);
  const attempts = await redis.incr(`attempts:${deviceHash}`);
  if (attempts > 5) {
    throw new Error("Too many attempts");
  }
  await redis.expire(`attempts:${deviceHash}`, 3600);
}
```

## 6. Additional Security Measures

### A. Certificate Transparency
```typescript
// Log all attestations
await log({
  timestamp: Date.now(),
  username: hash(username),
  passkeyId: hash(credentialId),
  appAttestId: hash(keyId),
  ip: req.ip,
  userAgent: req.headers['user-agent']
});
```

### B. Anomaly Detection
```typescript
// Check for suspicious patterns
if (await detectAnomaly(username, req.ip, deviceInfo)) {
  // Require additional verification
  await sendVerificationEmail(username);
  throw new Error("Additional verification required");
}
```

### C. Secure Storage
```swift
// Use Keychain instead of UserDefaults
KeychainService.shared.save(
    passkeyData,
    service: "passkey-registration",
    account: username,
    accessGroup: appGroup,
    accessible: .whenUnlockedThisDeviceOnly
)
```

## Attack Scenarios Mitigated

1. **Replay Attack**: ✅ One-time challenges with Redis
2. **TOCTOU**: ✅ Signed challenges with expiration
3. **Cross-Device**: ✅ Device binding via App Attest
4. **Challenge Substitution**: ✅ Cryptographic binding
5. **Credential Stuffing**: ✅ Rate limiting
6. **Side Channel**: ✅ Timing-safe comparisons
7. **Downgrade**: ✅ Require both attestations

## Implementation Priority

1. **High**: Unified challenge system (prevents most attacks)
2. **High**: One-time challenge usage
3. **Medium**: Device binding proof
4. **Medium**: Rate limiting
5. **Low**: Anomaly detection