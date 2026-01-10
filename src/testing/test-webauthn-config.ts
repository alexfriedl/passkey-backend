import { Fido2Lib } from "fido2-lib";

// ============================================================================
// Test Configuration for WebAuthn
// ============================================================================

export interface TestConfig {
  userVerification: 'required' | 'preferred' | 'discouraged';
  residentKey: 'required' | 'preferred' | 'discouraged';
  attestation: 'none' | 'direct' | 'indirect' | 'enterprise';
  pubKeyCredParams: number[];
  excludeCredentials: Array<{ id: string; transports?: string[] }>;
  allowCredentials: Array<{ id: string; transports?: string[] }>;
  testId?: string;
}

// Current test configuration (null = use defaults)
let currentTestConfig: TestConfig | null = null;

/**
 * Set test configuration
 */
export function setTestConfig(config: TestConfig | null): void {
  currentTestConfig = config;
  if (config) {
    console.log("\n🧪 TEST CONFIG SET:");
    console.log("  userVerification:", config.userVerification);
    console.log("  residentKey:", config.residentKey);
    console.log("  attestation:", config.attestation);
    console.log("  pubKeyCredParams:", config.pubKeyCredParams);
    if (config.testId) {
      console.log("  testId:", config.testId);
    }
  } else {
    console.log("🧪 Test config cleared - using defaults");
  }
}

/**
 * Get current test configuration
 */
export function getTestConfig(): TestConfig | null {
  return currentTestConfig;
}

/**
 * Check if test mode is active
 */
export function isTestMode(): boolean {
  return currentTestConfig !== null;
}

/**
 * Get default configuration
 */
export function getDefaultConfig(): TestConfig {
  return {
    userVerification: 'required',
    residentKey: 'required',
    attestation: 'none',
    pubKeyCredParams: [-7], // ES256
    excludeCredentials: [],
    allowCredentials: [],
  };
}

/**
 * Create a Fido2Lib instance with the given configuration
 */
export function createFido2WithConfig(
  rpId: string,
  config: TestConfig
): Fido2Lib {
  console.log("\n🧪 Creating Fido2Lib with test config:");
  console.log("  rpId:", rpId);
  console.log("  userVerification:", config.userVerification);
  console.log("  requireResidentKey:", config.residentKey === 'required');
  console.log("  attestation:", config.attestation);
  console.log("  cryptoParams:", config.pubKeyCredParams);

  return new Fido2Lib({
    timeout: 60000,
    rpId: rpId,
    rpName: "LocalKeyApp",
    challengeSize: 32,
    authenticatorAttachment: "platform",
    authenticatorRequireResidentKey: config.residentKey === 'required',
    authenticatorUserVerification: config.userVerification,
    attestation: config.attestation,
    cryptoParams: config.pubKeyCredParams,
  });
}

/**
 * Build registration options with test config applied
 */
export function applyTestConfigToRegistrationOptions(
  options: any,
  config: TestConfig
): any {
  return {
    ...options,
    authenticatorSelection: {
      ...options.authenticatorSelection,
      authenticatorAttachment: "platform",
      requireResidentKey: config.residentKey === 'required',
      residentKey: config.residentKey,
      userVerification: config.userVerification,
    },
    attestation: config.attestation,
    pubKeyCredParams: config.pubKeyCredParams.map(alg => ({
      type: "public-key",
      alg: alg,
    })),
    excludeCredentials: config.excludeCredentials.map(cred => ({
      type: "public-key",
      id: cred.id,
      transports: cred.transports || ["internal"],
    })),
  };
}

/**
 * Build authentication options with test config applied
 */
export function applyTestConfigToAuthenticationOptions(
  options: any,
  config: TestConfig
): any {
  // If allowCredentials is empty, it's a discoverable flow
  const allowCredentials = config.allowCredentials.length > 0
    ? config.allowCredentials.map(cred => ({
        type: "public-key",
        id: cred.id,
        transports: cred.transports || ["internal"],
      }))
    : []; // Empty = discoverable flow

  return {
    ...options,
    userVerification: config.userVerification,
    allowCredentials: allowCredentials,
  };
}
