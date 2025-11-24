# Debugging Improvements Summary

## Changes Made to server.ts

### 1. Added Helper Functions for Better Buffer Logging

- **formatBuffer()**: Formats Buffer data as hex string with truncation
  - Shows first 50 bytes by default (configurable)
  - Displays total size if truncated
  - Example: `a5646374666d74646e6f6e65675... (450 more bytes)`

- **formatObjectWithBuffers()**: Recursively formats objects containing Buffers
  - Buffers shown as: `Buffer(123 bytes) [hex preview]`
  - Nested objects properly indented
  - Arrays shown with item count

### 2. Improved Attestation Object Logging

#### Before:
- One line per byte for Buffer data
- Verbose output with repetitive information
- Hard to see the structure

#### After:
- Concise hex preview for Buffers
- Structured output with proper indentation
- Clear indication of data types and sizes

### 3. Enhanced dcAppAttest Logging

- Special handling for dcAppAttest field detection
- Shows size and preview of dcAppAttest data
- Attempts to decode CBOR if applicable
- Clear success/failure indicators

### 4. Updated Attestation Format Checks

- Now properly checks for 'none' format (expected for passkey with embedded App Attest)
- Also checks for 'apple-appattest' format
- Clear warning for unexpected formats

### 5. Response Logging Improvements

- Shows response data sizes instead of full content
- Prevents flooding console with base64 data
- Summary format for easier reading

## Example Output

```
🔍 DEBUG: AttestationObject buffer size: 500
🔍 DEBUG: AttestationObject hex preview: a5646374666d74646e6f6e65675... (450 more bytes)

🔍 DEBUG: Decoded attestation object:
  fmt (attestation format): none
  authData: Buffer(123 bytes)

🔍 DEBUG: attStmt (attestation statement):
  dcAppAttest: Buffer(256 bytes) [3082010ca003020102020900abcd...]

✅ dcAppAttest field found in attStmt!
  Size: 256 bytes
  Preview: 3082010ca003020102020900abcd...

✅ Attestation format is 'none' (expected for passkey with embedded App Attest)
```

## Benefits

1. **Reduced Log Verbosity**: No more one-line-per-byte Buffer logging
2. **Better Structure**: Clear hierarchy and indentation
3. **Useful Previews**: Hex previews for debugging without flooding console
4. **Clear Status**: Success/failure indicators for important checks
5. **Performance**: Truncated output prevents browser console slowdowns