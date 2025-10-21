import * as cbor from 'cbor';
import * as crypto from 'crypto';

interface IOSRegistrationRequest {
  credential: {
    id: string;
    rawId: string;
    type: string;
    response: {
      clientDataHash: string;  // Base64URL encoded
      attestationObject: string;  // Base64URL encoded
    };
  };
  username: string;
  challenge: string;
}

interface ParsedAuthenticatorData {
  rpIdHash: Buffer;
  flags: number;
  signCount: number;
  aaguid: Buffer;
  credentialIdLength: number;
  credentialId: Buffer;
  credentialPublicKey: any;
}

// Simple in-memory storage for demo purposes
const users = new Map<string, any>();

/**
 * Parse authenticator data according to WebAuthn spec
 */
function parseAuthenticatorData(authData: Buffer): ParsedAuthenticatorData {
  let offset = 0;

  // RP ID hash (32 bytes)
  const rpIdHash = authData.slice(0, 32);
  offset += 32;

  // Flags (1 byte)
  const flags = authData[offset];
  offset += 1;

  // Sign count (4 bytes, big-endian)
  const signCount = authData.readUInt32BE(offset);
  offset += 4;

  // Check if attested credential data is present (bit 6 of flags)
  if (!(flags & 0x40)) {
    throw new Error('No attested credential data present');
  }

  // AAGUID (16 bytes)
  const aaguid = authData.slice(offset, offset + 16);
  offset += 16;

  // Credential ID length (2 bytes, big-endian)
  const credentialIdLength = authData.readUInt16BE(offset);
  offset += 2;

  // Credential ID
  const credentialId = authData.slice(offset, offset + credentialIdLength);
  offset += credentialIdLength;

  // Credential public key (CBOR encoded)
  const credentialPublicKeyBytes = authData.slice(offset);
  const credentialPublicKey = cbor.decodeFirstSync(credentialPublicKeyBytes);

  return {
    rpIdHash,
    flags,
    signCount,
    aaguid,
    credentialIdLength,
    credentialId,
    credentialPublicKey
  };
}

/**
 * Convert COSE key to PEM format for storage
 */
function coseKeyToPEM(coseKey: any): string {
  // For ES256 (alg: -7), kty: 2 (EC), crv: 1 (P-256)
  if (coseKey.get(3) !== -7 || coseKey.get(1) !== 2) {
    throw new Error('Unsupported key type or algorithm');
  }

  // Extract x and y coordinates
  const x = coseKey.get(-2);
  const y = coseKey.get(-3);

  if (!x || !y || x.length !== 32 || y.length !== 32) {
    throw new Error('Invalid key coordinates');
  }

  // Create public key from x,y coordinates
  const publicKeyBuffer = Buffer.concat([
    Buffer.from([0x04]), // Uncompressed point indicator
    x,
    y
  ]);

  // Create EC public key
  const keyObject = crypto.createPublicKey({
    key: publicKeyBuffer,
    format: 'der',
    type: 'spki',
    encoding: 'buffer'
  });

  // Export as PEM
  return keyObject.export({
    type: 'spki',
    format: 'pem'
  }).toString();
}

/**
 * Base64URL decode helper
 */
function base64urlDecode(str: string): Buffer {
  // Add padding if necessary
  str += '='.repeat((4 - (str.length % 4)) % 4);
  // Convert base64url to base64
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(str, 'base64');
}

/**
 * Simplified iOS registration handler
 */
export async function registerIOSSimple(request: IOSRegistrationRequest): Promise<any> {
  try {
    console.log('Starting iOS simple registration for user:', request.username);

    // Decode the attestation object
    const attestationObjectBuffer = base64urlDecode(request.credential.response.attestationObject);
    
    // Parse CBOR attestation object
    const attestationObject = cbor.decodeFirstSync(attestationObjectBuffer);
    
    // Extract components
    const authData = attestationObject.authData;
    const fmt = attestationObject.fmt;
    const attStmt = attestationObject.attStmt;

    console.log('Attestation format:', fmt);

    // Parse authenticator data
    const parsedAuthData = parseAuthenticatorData(authData);
    
    console.log('Parsed authenticator data:', {
      credentialIdLength: parsedAuthData.credentialIdLength,
      flags: parsedAuthData.flags.toString(2),
      signCount: parsedAuthData.signCount,
      aaguid: parsedAuthData.aaguid.toString('hex')
    });

    // Convert credential ID to base64url for storage
    const credentialId = parsedAuthData.credentialId.toString('base64url');

    // Extract and convert public key
    let publicKeyPEM: string;
    try {
      publicKeyPEM = coseKeyToPEM(parsedAuthData.credentialPublicKey);
      console.log('Successfully converted public key to PEM format');
    } catch (error) {
      console.error('Error converting public key:', error);
      // For iOS, we might get the key in a different format
      // Store the raw COSE key as fallback
      publicKeyPEM = JSON.stringify(parsedAuthData.credentialPublicKey);
    }

    // Create user object
    const user = {
      id: crypto.randomUUID(),
      username: request.username,
      credentials: [{
        credentialId: credentialId,
        publicKey: publicKeyPEM,
        signCount: parsedAuthData.signCount,
        aaguid: parsedAuthData.aaguid.toString('hex'),
        fmt: fmt,
        registeredAt: new Date().toISOString(),
        lastUsed: null
      }]
    };

    // Store user
    users.set(request.username, user);
    console.log('User registered successfully:', request.username);

    return {
      success: true,
      user: {
        id: user.id,
        username: user.username,
        credentialId: credentialId
      }
    };

  } catch (error) {
    console.error('Registration error:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Registration failed'
    };
  }
}

/**
 * Get user by username (for testing/debugging)
 */
export function getUser(username: string): any {
  return users.get(username);
}

/**
 * List all users (for testing/debugging)
 */
export function listUsers(): any[] {
  return Array.from(users.values());
}