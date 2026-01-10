import { Router, Request, Response } from 'express';
import { testResultStore } from './test-results';
import { setTestConfig, isTestMode, getDefaultConfig, TestConfig } from './test-webauthn-config';
import testMatrix from './test-matrix.json';

const router = Router();

// ============================================================================
// Test Configuration State
// ============================================================================

export interface TestConfiguration {
  // Registration parameters
  userVerification: 'required' | 'preferred' | 'discouraged';
  residentKey: 'required' | 'preferred' | 'discouraged';
  attestation: 'none' | 'direct' | 'indirect' | 'enterprise';
  excludeCredentials: ExcludeCredentialConfig[];
  pubKeyCredParams: number[];

  // Authentication parameters
  allowCredentials: AllowCredentialConfig[];

  // Test metadata
  testId?: string;
  description?: string;
}

export interface ExcludeCredentialConfig {
  id: string;
  transports?: string[];
}

export interface AllowCredentialConfig {
  id: string;
  transports?: string[];
}

// Current active configuration (in-memory, resets on server restart)
let currentConfig: TestConfiguration = {
  ...getDefaultConfig(),
  testId: undefined,
  description: undefined,
};

// ============================================================================
// API Endpoints
// ============================================================================

/**
 * POST /api/test/configure
 * Set FIDO parameters for the next registration/authentication operation
 */
router.post('/configure', (req: Request, res: Response): void => {
  try {
    const config = req.body as Partial<TestConfiguration>;

    console.log('\n========== TEST CONFIGURE ==========');
    console.log('Received configuration:', JSON.stringify(config, null, 2));

    // Merge with current config (partial updates allowed)
    currentConfig = {
      ...currentConfig,
      ...config,
    };

    // Validate configuration
    const validationErrors = validateConfig(currentConfig);

    // Apply to WebAuthn module
    setTestConfig(currentConfig as TestConfig);
    if (validationErrors.length > 0) {
      console.error('Configuration validation errors:', validationErrors);
      res.status(400).json({
        success: false,
        errors: validationErrors,
      });
      return;
    }

    console.log('Active configuration:', JSON.stringify(currentConfig, null, 2));
    console.log('========== TEST CONFIGURE END ==========\n');

    res.json({
      success: true,
      config: currentConfig,
    });
  } catch (error) {
    console.error('Error configuring test:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * POST /api/test/reset
 * Reset configuration to defaults and clear last result
 */
router.post('/reset', (_req: Request, res: Response) => {
  try {
    console.log('\n========== TEST RESET ==========');

    currentConfig = {
      ...getDefaultConfig(),
      testId: undefined,
      description: undefined,
    };
    setTestConfig(null); // Clear test mode
    testResultStore.clear();

    console.log('Configuration reset to defaults');
    console.log('Test results cleared');
    console.log('========== TEST RESET END ==========\n');

    res.json({
      success: true,
      config: currentConfig,
    });
  } catch (error) {
    console.error('Error resetting test:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * GET /api/test/results
 * Get the last operation result with full details
 */
router.get('/results', (_req: Request, res: Response): void => {
  try {
    const lastResult = testResultStore.getLastResult();

    if (!lastResult) {
      res.status(404).json({
        success: false,
        error: 'No test results available',
      });
      return;
    }

    res.json({
      success: true,
      result: lastResult,
    });
  } catch (error) {
    console.error('Error getting test results:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * GET /api/test/results/all
 * Get all stored results (for test reports)
 */
router.get('/results/all', (_req: Request, res: Response) => {
  try {
    const allResults = testResultStore.getAllResults();

    res.json({
      success: true,
      count: allResults.length,
      results: allResults,
    });
  } catch (error) {
    console.error('Error getting all test results:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * GET /api/test/matrix
 * Get the complete test matrix definition
 */
router.get('/matrix', (_req: Request, res: Response) => {
  try {
    res.json({
      success: true,
      matrix: testMatrix,
    });
  } catch (error) {
    console.error('Error getting test matrix:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * GET /api/test/status
 * Get current configuration and server status
 */
router.get('/status', (_req: Request, res: Response) => {
  try {
    const lastResult = testResultStore.getLastResult();

    res.json({
      success: true,
      status: 'ready',
      currentConfig: currentConfig,
      lastResultId: lastResult?.testId || null,
      lastResultTimestamp: lastResult?.timestamp || null,
      totalResults: testResultStore.getAllResults().length,
    });
  } catch (error) {
    console.error('Error getting test status:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * GET /api/test/config
 * Get current active configuration
 */
router.get('/config', (_req: Request, res: Response) => {
  res.json({
    success: true,
    config: currentConfig,
  });
});

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Get the current test configuration
 * Used by webauthn.ts to apply test parameters
 */
export function getCurrentTestConfig(): TestConfiguration {
  return { ...currentConfig };
}

/**
 * Check if test mode is active
 */
export function isTestModeActive(): boolean {
  return isTestMode();
}

/**
 * Validate configuration values
 */
function validateConfig(config: TestConfiguration): string[] {
  const errors: string[] = [];

  const validUserVerification = ['required', 'preferred', 'discouraged'];
  if (!validUserVerification.includes(config.userVerification)) {
    errors.push(`Invalid userVerification: ${config.userVerification}`);
  }

  const validResidentKey = ['required', 'preferred', 'discouraged'];
  if (!validResidentKey.includes(config.residentKey)) {
    errors.push(`Invalid residentKey: ${config.residentKey}`);
  }

  const validAttestation = ['none', 'direct', 'indirect', 'enterprise'];
  if (!validAttestation.includes(config.attestation)) {
    errors.push(`Invalid attestation: ${config.attestation}`);
  }

  // Validate pubKeyCredParams (must be valid COSE algorithm identifiers)
  const validAlgorithms = [-7, -35, -36, -37, -38, -39, -257, -258, -259];
  for (const alg of config.pubKeyCredParams) {
    if (!validAlgorithms.includes(alg)) {
      errors.push(`Invalid algorithm in pubKeyCredParams: ${alg}`);
    }
  }

  return errors;
}

export default router;
