/**
 * FIDO E2E Testing Module
 *
 * This module provides test infrastructure for E2E testing of FIDO/WebAuthn
 * parameter combinations against the PasskeyGuard iOS app.
 *
 * API Endpoints (registered at /api/test/*):
 *   POST /api/test/configure  - Set FIDO parameters for next operation
 *   POST /api/test/reset      - Reset to default configuration
 *   GET  /api/test/results    - Get last operation result
 *   GET  /api/test/results/all - Get all stored results
 *   GET  /api/test/matrix     - Get test case definitions
 *   GET  /api/test/status     - Get current config and status
 *   GET  /api/test/config     - Get current configuration
 *
 * Files:
 *   - test-controller.ts      - Express router with API endpoints
 *   - test-results.ts         - Result storage and authenticator data parsing
 *   - test-webauthn-config.ts - Dynamic FIDO configuration
 *   - test-matrix.json        - P0 test case definitions (synced with TESTCASES.csv)
 */

export { default as testRouter } from './test-controller';
export { getCurrentTestConfig, isTestModeActive, getConfigByTestId } from './test-controller';
export {
  testResultStore,
  createRegistrationResult,
  createAuthenticationResult,
  parseAuthenticatorData,
  parseAttestationStatement,
  type TestResult,
  type AuthenticatorDataAnalysis,
  type AttestationAnalysis,
} from './test-results';
export {
  setTestConfig,
  getTestConfig,
  isTestMode,
  getDefaultConfig,
  createFido2WithConfig,
  applyTestConfigToRegistrationOptions,
  applyTestConfigToAuthenticationOptions,
  type TestConfig,
} from './test-webauthn-config';
