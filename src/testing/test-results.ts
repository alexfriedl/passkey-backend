import { TestConfiguration } from './test-controller';

// ============================================================================
// Test Result Types
// ============================================================================

export interface TestResult {
  // Test identification
  testId: string;
  timestamp: Date;
  operation: 'registration' | 'authentication';

  // Configuration used for this test
  parameters: TestConfiguration;

  // Outcome
  success: boolean;
  errorType?: string;           // NotAllowedError, InvalidStateError, etc.
  errorMessage?: string;

  // Authenticator Data analysis
  authenticatorData?: AuthenticatorDataAnalysis;

  // Attestation analysis (registration only)
  attestation?: AttestationAnalysis;

  // Credential info
  credential?: CredentialInfo;

  // Raw data for debugging
  rawRequest?: any;
  rawResponse?: any;
}

export interface AuthenticatorDataAnalysis {
  rpIdHash: string;
  flags: number;
  flagsDecoded: {
    UP: boolean;    // User Present (bit 0)
    UV: boolean;    // User Verified (bit 2)
    BE: boolean;    // Backup Eligible (bit 3)
    BS: boolean;    // Backup State (bit 4)
    AT: boolean;    // Attested Credential Data (bit 6)
    ED: boolean;    // Extension Data (bit 7)
  };
  signCount: number;
  aaguid?: string;
  credentialIdLength?: number;
}

export interface AttestationAnalysis {
  format: string;             // none, packed, apple, tpm, etc.
  hasX5c: boolean;
  x5cCount?: number;
  hasSig: boolean;
  algorithm?: number;
}

export interface CredentialInfo {
  id: string;
  rawId: string;
  type: string;
  algorithm?: number;
  publicKeyPem?: string;
  transports?: string[];
}

// ============================================================================
// Test Result Store (In-Memory)
// ============================================================================

class TestResultStore {
  private results: TestResult[] = [];
  private maxResults: number = 100;

  /**
   * Store a new test result
   */
  addResult(result: TestResult): void {
    console.log('\n========== STORING TEST RESULT ==========');
    console.log('Test ID:', result.testId);
    console.log('Operation:', result.operation);
    console.log('Success:', result.success);
    if (result.errorType) {
      console.log('Error Type:', result.errorType);
    }
    if (result.authenticatorData) {
      console.log('Flags:', result.authenticatorData.flagsDecoded);
    }
    console.log('========== TEST RESULT STORED ==========\n');

    this.results.push(result);

    // Keep only the last N results
    if (this.results.length > this.maxResults) {
      this.results = this.results.slice(-this.maxResults);
    }
  }

  /**
   * Get the most recent result
   */
  getLastResult(): TestResult | null {
    return this.results.length > 0 ? this.results[this.results.length - 1] : null;
  }

  /**
   * Get all stored results
   */
  getAllResults(): TestResult[] {
    return [...this.results];
  }

  /**
   * Get results by test ID
   */
  getResultsByTestId(testId: string): TestResult[] {
    return this.results.filter(r => r.testId === testId);
  }

  /**
   * Get results by operation type
   */
  getResultsByOperation(operation: 'registration' | 'authentication'): TestResult[] {
    return this.results.filter(r => r.operation === operation);
  }

  /**
   * Clear all results
   */
  clear(): void {
    this.results = [];
  }

  /**
   * Get summary statistics
   */
  getSummary(): {
    total: number;
    passed: number;
    failed: number;
    registrations: number;
    authentications: number;
  } {
    return {
      total: this.results.length,
      passed: this.results.filter(r => r.success).length,
      failed: this.results.filter(r => !r.success).length,
      registrations: this.results.filter(r => r.operation === 'registration').length,
      authentications: this.results.filter(r => r.operation === 'authentication').length,
    };
  }
}

// Singleton instance
export const testResultStore = new TestResultStore();

// ============================================================================
// Helper Functions for Parsing Authenticator Data
// ============================================================================

/**
 * Parse authenticator data buffer and extract all fields
 */
export function parseAuthenticatorData(authData: Buffer): AuthenticatorDataAnalysis {
  // Authenticator data structure:
  // - rpIdHash: 32 bytes
  // - flags: 1 byte
  // - signCount: 4 bytes (big-endian)
  // - (optional) attestedCredentialData
  // - (optional) extensions

  const rpIdHash = authData.slice(0, 32).toString('hex');
  const flags = authData[32];
  const signCount = authData.readUInt32BE(33);

  // Decode flags
  const flagsDecoded = {
    UP: (flags & 0x01) !== 0,    // Bit 0
    UV: (flags & 0x04) !== 0,    // Bit 2
    BE: (flags & 0x08) !== 0,    // Bit 3
    BS: (flags & 0x10) !== 0,    // Bit 4
    AT: (flags & 0x40) !== 0,    // Bit 6
    ED: (flags & 0x80) !== 0,    // Bit 7
  };

  const result: AuthenticatorDataAnalysis = {
    rpIdHash,
    flags,
    flagsDecoded,
    signCount,
  };

  // If AT flag is set, parse attested credential data
  if (flagsDecoded.AT && authData.length > 37) {
    // AAGUID: 16 bytes starting at offset 37
    result.aaguid = authData.slice(37, 53).toString('hex');
    // Credential ID length: 2 bytes at offset 53
    result.credentialIdLength = authData.readUInt16BE(53);
  }

  return result;
}

/**
 * Parse attestation statement and extract format info
 */
export function parseAttestationStatement(attStmt: any, fmt: string): AttestationAnalysis {
  return {
    format: fmt,
    hasX5c: Array.isArray(attStmt?.x5c) && attStmt.x5c.length > 0,
    x5cCount: Array.isArray(attStmt?.x5c) ? attStmt.x5c.length : 0,
    hasSig: !!attStmt?.sig,
    algorithm: attStmt?.alg,
  };
}

/**
 * Create a test result from a registration operation
 */
export function createRegistrationResult(
  testId: string,
  parameters: TestConfiguration,
  success: boolean,
  options: {
    errorType?: string;
    errorMessage?: string;
    authenticatorData?: Buffer;
    attestationObject?: any;
    credential?: any;
    rawRequest?: any;
    rawResponse?: any;
  }
): TestResult {
  const result: TestResult = {
    testId,
    timestamp: new Date(),
    operation: 'registration',
    parameters,
    success,
  };

  if (options.errorType) {
    result.errorType = options.errorType;
    result.errorMessage = options.errorMessage;
  }

  if (options.authenticatorData) {
    result.authenticatorData = parseAuthenticatorData(options.authenticatorData);
  }

  if (options.attestationObject) {
    result.attestation = parseAttestationStatement(
      options.attestationObject.attStmt,
      options.attestationObject.fmt
    );
  }

  if (options.credential) {
    result.credential = {
      id: options.credential.id,
      rawId: options.credential.rawId,
      type: options.credential.type || 'public-key',
    };
  }

  if (options.rawRequest) {
    result.rawRequest = options.rawRequest;
  }

  if (options.rawResponse) {
    result.rawResponse = options.rawResponse;
  }

  return result;
}

/**
 * Create a test result from an authentication operation
 */
export function createAuthenticationResult(
  testId: string,
  parameters: TestConfiguration,
  success: boolean,
  options: {
    errorType?: string;
    errorMessage?: string;
    authenticatorData?: Buffer;
    credential?: any;
    rawRequest?: any;
    rawResponse?: any;
  }
): TestResult {
  const result: TestResult = {
    testId,
    timestamp: new Date(),
    operation: 'authentication',
    parameters,
    success,
  };

  if (options.errorType) {
    result.errorType = options.errorType;
    result.errorMessage = options.errorMessage;
  }

  if (options.authenticatorData) {
    result.authenticatorData = parseAuthenticatorData(options.authenticatorData);
  }

  if (options.credential) {
    result.credential = {
      id: options.credential.id,
      rawId: options.credential.rawId,
      type: options.credential.type || 'public-key',
    };
  }

  if (options.rawRequest) {
    result.rawRequest = options.rawRequest;
  }

  if (options.rawResponse) {
    result.rawResponse = options.rawResponse;
  }

  return result;
}
