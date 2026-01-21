import { Router, Request, Response } from 'express';
import { testResultStore } from './test-results';
import { setTestConfig, isTestMode, getDefaultConfig, TestConfig } from './test-webauthn-config';
import testMatrix from './test-matrix.json';
import User from '../models/User';

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

// Map to store configurations by testId (for parallel test support)
const configStore = new Map<string, TestConfiguration>();

/**
 * Generate a unique testId
 */
function generateTestId(): string {
  return `test_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
}

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

    // Generate testId if not provided
    const testId = config.testId || generateTestId();

    // Create new config with testId
    const newConfig: TestConfiguration = {
      ...getDefaultConfig(),
      ...config,
      testId,
    };

    // Validate configuration
    const validationErrors = validateConfig(newConfig);

    if (validationErrors.length > 0) {
      console.error('Configuration validation errors:', validationErrors);
      res.status(400).json({
        success: false,
        errors: validationErrors,
      });
      return;
    }

    // Store in configStore Map (for parallel test support)
    configStore.set(testId, newConfig);
    console.log(`📦 Config stored with testId: ${testId}`);
    console.log(`📦 Total configs in store: ${configStore.size}`);

    // Also update currentConfig for backwards compatibility
    currentConfig = newConfig;

    // Apply to WebAuthn module
    setTestConfig(newConfig as TestConfig);

    console.log('Active configuration:', JSON.stringify(newConfig, null, 2));
    console.log('========== TEST CONFIGURE END ==========\n');

    // Return config without testId (it's already a top-level field)
    const { testId: _excludeTestId, ...configWithoutTestId } = newConfig;

    res.json({
      success: true,
      testId,
      config: configWithoutTestId,
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

/**
 * DELETE /api/test/config/:testId
 * Delete configuration for a specific testId
 */
router.delete('/config/:testId', (req: Request, res: Response): void => {
  try {
    const { testId } = req.params;

    console.log(`🗑️ Deleting config for testId: ${testId}`);

    const existed = configStore.has(testId);
    configStore.delete(testId);

    if (existed) {
      console.log(`✅ Config deleted for testId: ${testId}`);
      res.json({
        success: true,
        deleted: true,
        testId,
      });
    } else {
      console.log(`⚠️ Config not found for testId: ${testId}`);
      res.json({
        success: true,
        deleted: false,
        testId,
        message: 'Config not found',
      });
    }
  } catch (error) {
    console.error('Error deleting config:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * GET /api/test/config/:testId
 * Get configuration for a specific testId (for parallel test support)
 */
router.get('/config/:testId', (req: Request, res: Response): void => {
  try {
    const { testId } = req.params;

    console.log(`📦 Fetching config for testId: ${testId}`);

    const config = configStore.get(testId);

    if (!config) {
      console.log(`❌ Config not found for testId: ${testId}`);
      res.status(404).json({
        success: false,
        error: `Configuration not found for testId: ${testId}`,
      });
      return;
    }

    console.log(`✅ Config found for testId: ${testId}`);

    res.json({
      success: true,
      testId,
      config,
    });
  } catch (error) {
    console.error('Error getting config by testId:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * POST /api/test/error
 * Record a client-side WebAuthn error for E2E testing
 * Used when navigator.credentials.create/get fails on the client
 */
router.post('/error', (req: Request, res: Response): void => {
  try {
    const { errorType, errorMessage, operation, testId } = req.body;

    // Use testId from request body if provided, otherwise fall back to currentConfig
    const effectiveTestId = testId || currentConfig.testId;
    const effectiveConfig = testId ? configStore.get(testId) || currentConfig : currentConfig;

    console.log('\n========== CLIENT ERROR RECEIVED ==========');
    console.log('Test ID:', effectiveTestId);
    console.log('Error Type:', errorType);
    console.log('Error Message:', errorMessage);
    console.log('Operation:', operation || 'registration');
    console.log('========== CLIENT ERROR END ==========\n');

    // Store as a failed test result
    const result: any = {
      testId: effectiveTestId || 'unknown',
      timestamp: new Date(),
      operation: operation || 'registration',
      parameters: effectiveConfig,
      success: false,
      errorType: errorType || 'UnknownError',
      errorMessage: errorMessage || 'Unknown client error',
    };

    testResultStore.addResult(result);

    console.log(`🧪 Client error recorded for test: ${effectiveTestId}`);

    res.json({
      success: true,
      recorded: true,
      testId: effectiveTestId,
    });
  } catch (error) {
    console.error('Error recording client error:', error);
    res.status(500).json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * GET /api/test/check-user
 * Check if a user exists in the database (non-blocking)
 * Used by E2E tests to determine if setup is needed
 */
router.get('/check-user', async (req: Request, res: Response): Promise<void> => {
  try {
    const username = req.query.username as string;

    if (!username) {
      res.status(400).json({
        success: false,
        exists: false,
        error: 'username query parameter is required',
      });
      return;
    }

    console.log(`[CHECK-USER] Checking if user exists: ${username}`);

    const user = await User.findOne({ username });

    if (user) {
      console.log(`[CHECK-USER] ✅ User exists: ${username}`);
      res.json({
        success: true,
        exists: true,
        user: {
          username: user.username,
          createdAt: user.createdAt,
        },
      });
    } else {
      console.log(`[CHECK-USER] ❌ User does not exist: ${username}`);
      res.json({
        success: true,
        exists: false,
      });
    }
  } catch (error) {
    console.error('Error checking user:', error);
    res.status(500).json({
      success: false,
      exists: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * DELETE /api/test/delete-user
 * Delete a user from the database
 * Used by E2E tests to ensure fresh registration on new devices
 */
router.delete('/delete-user', async (req: Request, res: Response): Promise<void> => {
  try {
    const username = req.query.username as string;

    if (!username) {
      res.status(400).json({
        success: false,
        deleted: false,
        error: 'username query parameter is required',
      });
      return;
    }

    console.log(`[DELETE-USER] Deleting user: ${username}`);

    const result = await User.deleteOne({ username });

    if (result.deletedCount > 0) {
      console.log(`[DELETE-USER] ✅ User deleted: ${username}`);
      res.json({
        success: true,
        deleted: true,
        username,
      });
    } else {
      console.log(`[DELETE-USER] ❌ User not found: ${username}`);
      res.json({
        success: true,
        deleted: false,
        error: `User "${username}" not found`,
      });
    }
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({
      success: false,
      deleted: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

/**
 * GET /api/test/wait-for-user
 * Wait for a user to be registered in the database
 * Used by E2E tests to ensure registration completes before authentication
 */
router.get('/wait-for-user', async (req: Request, res: Response): Promise<void> => {
  try {
    const username = req.query.username as string;
    const timeoutMs = parseInt(req.query.timeout as string) || 30000;

    if (!username) {
      res.status(400).json({
        success: false,
        found: false,
        error: 'username query parameter is required',
      });
      return;
    }

    console.log(`\n========== WAIT FOR USER ==========`);
    console.log(`Waiting for user: ${username}`);
    console.log(`Timeout: ${timeoutMs}ms`);

    const startTime = Date.now();
    const pollInterval = 500; // Poll every 500ms

    while (Date.now() - startTime < timeoutMs) {
      const user = await User.findOne({ username });

      if (user) {
        const elapsed = Date.now() - startTime;
        console.log(`✅ User found after ${elapsed}ms: ${username}`);
        console.log(`========== WAIT FOR USER END ==========\n`);

        res.json({
          success: true,
          found: true,
          user: {
            username: user.username,
            createdAt: user.createdAt,
          },
          elapsedMs: elapsed,
        });
        return;
      }

      // Wait before next poll
      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }

    // Timeout reached
    console.log(`❌ Timeout: User not found: ${username}`);
    console.log(`========== WAIT FOR USER END ==========\n`);

    res.json({
      success: false,
      found: false,
      error: `User "${username}" not found within ${timeoutMs}ms`,
      timeoutMs,
    });
  } catch (error) {
    console.error('Error waiting for user:', error);
    res.status(500).json({
      success: false,
      found: false,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
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
 * Get configuration by testId
 * Used for parallel test support
 */
export function getConfigByTestId(testId: string): TestConfiguration | undefined {
  return configStore.get(testId);
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
  // See: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
  const validAlgorithms = [
    -7,   // ES256 (ECDSA w/ SHA-256, P-256)
    -8,   // EdDSA (Ed25519, Ed448)
    -35,  // ES384 (ECDSA w/ SHA-384, P-384)
    -36,  // ES512 (ECDSA w/ SHA-512, P-521)
    -37,  // PS256 (RSASSA-PSS w/ SHA-256)
    -38,  // PS384 (RSASSA-PSS w/ SHA-384)
    -39,  // PS512 (RSASSA-PSS w/ SHA-512)
    -257, // RS256 (RSASSA-PKCS1-v1_5 w/ SHA-256)
    -258, // RS384 (RSASSA-PKCS1-v1_5 w/ SHA-384)
    -259, // RS512 (RSASSA-PKCS1-v1_5 w/ SHA-512)
  ];
  for (const alg of config.pubKeyCredParams) {
    if (!validAlgorithms.includes(alg)) {
      errors.push(`Invalid algorithm in pubKeyCredParams: ${alg}`);
    }
  }

  return errors;
}

export default router;
