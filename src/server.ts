import express from "express";
import cors from "cors";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();
import {
  generateRegistrationOptions,
  generateAndroidDirectRegistrationOptions,
  verifyRegistration,
  generateAuthenticationOptions,
  generateDiscoverableAuthenticationOptions,
  verifyAuthentication,
  verifyDiscoverableAuthentication,
  base64UrlToArrayBuffer,
} from "./webauthn";
import path from "path";
import { connectDB } from "./mongodb";
import User from "./models/User";
import { Pool } from "pg";
import appAttestRouter from "./appattest";
import { verifyIOSRegistration } from "./ios-registration";
import { registerIOSSimple } from "./ios-simple-registration";
import { getChallenge } from "./challenge-store";
import { testResultStore, createRegistrationResult, createAuthenticationResult } from './testing/test-results';
import { getCurrentTestConfig, isTestModeActive } from './testing/test-controller';
import { applyTestConfigToRegistrationOptions } from './testing/test-webauthn-config';

// Configure PostgreSQL connection (Neon Postgres on Heroku)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

const app = express();
const PORT = parseInt(process.env.PORT || "3000", 10);
const MONGOPORT = process.env.MONGOPORT || 27017;

app.use(express.json());
app.use(
  cors({
    origin: "*", // 👈 Erlaubt ALLE Origins (nur für lokale Tests)
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type"],
  })
);


app.get("/.well-known/apple-app-site-association", (req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.sendFile(
    path.join(__dirname, "../public/.well-known/apple-app-site-association")
  );
});

app.use(express.static(path.join(__dirname, "../public")));

// Apple App Attest Router
app.use("/api/appattest", appAttestRouter);

// FIDO E2E Test Router
import testRouter from "./testing/test-controller";
app.use("/api/test", testRouter);
console.log("🧪 Test API endpoints registered at /api/test/*");

// Import security config
import { requiresAppAttest } from "./config/security-config";

/**
 * 🔹 Combined Passkey + App Attest Registration
 * iOS-App sendet beide Attestations in einem Request
 */
app.post("/api/register/combined", async (req: any, res: any) => {
  try {
    console.log("\n========== COMBINED REGISTRATION START ==========");
    console.log("Timestamp:", new Date().toISOString());
    
    // Helper function to format Buffer data
    const formatBuffer = (buffer: Buffer, maxBytes: number = 50): string => {
      if (!Buffer.isBuffer(buffer)) return 'Not a buffer';
      const hex = buffer.slice(0, maxBytes).toString('hex');
      const truncated = buffer.length > maxBytes ? `... (${buffer.length - maxBytes} more bytes)` : '';
      return `${hex}${truncated}`;
    };
    
    const { username, passkey, appAttest, platform } = req.body;
    
    // Validate required fields
    if (!username || !passkey) {
      console.error("Missing required fields in combined registration");
      return res.status(400).json({ 
        error: "Username and passkey data are required" 
      });
    }
    
    // Check if App Attest is required for this user
    const appAttestRequired = requiresAppAttest(username);
    console.log(`App Attest required for ${username}: ${appAttestRequired}`);
    
    if (appAttestRequired && !appAttest) {
      console.error("App Attest required but not provided");
      return res.status(400).json({ 
        error: "App Attest is required for this account",
        requiresAppAttest: true
      });
    }
    
    console.log("Processing combined registration for:", username);
    console.log("Platform:", platform || "web");
    
    // Step 1: Verify Passkey Registration
    console.log("\n📱 Step 1: Verifying Passkey...");
    let passkeyResult;
    try {
      if (platform === "ios-extension") {
        console.log("🍎 iOS Extension detected - using special handling");
        // For iOS extensions, we need to handle the challenge differently
        // iOS generates its own challenge that we cannot override
        console.log("Server challenge (for audit):", passkey.challenge);
        
        // Use iOS-specific registration handler
        passkeyResult = await verifyIOSRegistration(
          passkey.credential,
          username,
          passkey.challenge // Server challenge for audit
        );
        console.log("✅ iOS Passkey verification successful");
      } else {
        // Normal web flow - validate challenge as usual
        passkeyResult = await verifyRegistration(passkey.credential, username);
        console.log("✅ Passkey verification successful");
      }
    } catch (error) {
      console.error("❌ Passkey verification failed:", error);
      return res.status(400).json({ 
        error: "Passkey verification failed",
        detail: error instanceof Error ? error.message : "Unknown error"
      });
    }
    
    // Step 2: Verify App Attest (if provided)
    let appAttestResult: any = null;
    if (appAttest) {
      console.log("\n🔒 Step 2: Verifying App Attest...");
      try {
      // Create a mock request/response to use the app attest router
      const appAttestReq = {
        body: {
          username,
          keyId: appAttest.keyId,
          attestationObject: appAttest.attestationObject,
          localChallenge: appAttest.localChallenge
        }
      };
      
      // Create a response object to capture the result
      const appAttestRes = {
        json: (data: any) => { appAttestResult = data; },
        status: (code: number) => ({
          json: (data: any) => {
            throw new Error(`App Attest failed with status ${code}: ${JSON.stringify(data)}`);
          }
        })
      };
      
      // Find the attest route handler and call it
      const attestRoute = appAttestRouter.stack.find((layer: any) => 
        layer.route && layer.route.path === '/attest' && layer.route.methods.post
      );
      
      if (!attestRoute || !attestRoute.route || !attestRoute.route.stack || !attestRoute.route.stack[0]) {
        throw new Error("App Attest route handler not found");
      }
      
      // Call the handler with proper typing
      const handler = attestRoute.route.stack[0].handle;
      await handler(appAttestReq as any, appAttestRes as any, () => {});
      
      // Check if we got a result
      if (!appAttestResult || !appAttestResult.verified) {
        throw new Error("App Attest verification failed");
      }
      
        console.log("✅ App Attest verification successful");
      } catch (error) {
        console.error("❌ App Attest verification failed:", error);
        return res.status(400).json({ 
          error: "App Attest verification failed",
          detail: error instanceof Error ? error.message : "Unknown error"
        });
      }
    } else {
      console.log("ℹ️ App Attest not provided - skipping verification");
    }
    
    // Step 3: Link credentials in database (if needed)
    console.log("\n🔗 Step 3: Linking credentials...");
    // TODO: Update user model to store both credential IDs if needed
    // For now, both are independently stored and linked by username
    
    // Prepare combined response
    const response: any = {
      success: true,
      username,
      passkey: {
        verified: true,
        attestationObject: passkeyResult.request.response.attestationObject,
        clientDataJSON: passkeyResult.request.response.clientDataJSON
      },
      message: appAttest ? "Combined registration successful" : "Passkey registration successful"
    };
    
    // Log response size info instead of full data
    console.log("\n📦 Response summary:");
    console.log(`  attestationObject: ${response.passkey.attestationObject?.length || 0} chars`);
    console.log(`  clientDataJSON: ${response.passkey.clientDataJSON?.length || 0} chars`);
    
    // Add App Attest data only if it was verified
    if (appAttestResult) {
      response.appAttest = {
        verified: appAttestResult.verified,
        keyId: appAttestResult.keyId,
        publicKey: appAttestResult.publicKey,
        counter: appAttestResult.counter,
        appId: appAttestResult.appId
      };
    }
    
    console.log("\n✅ COMBINED REGISTRATION SUCCESSFUL!");
    console.log("========== COMBINED REGISTRATION END ==========");
    
    res.json(response);
    
  } catch (error) {
    console.error("\n❌ Combined registration error:", error);
    res.status(500).json({ 
      error: "Combined registration failed",
      detail: error instanceof Error ? error.message : "Unknown error"
    });
  }
});

/**
 * 🔹 Schritt 1: Registrierung - Challenge generieren
 * iOS-App sendet: { username: "alice" }
 * Server antwortet mit den WebAuthn-Registrierungsoptionen
 */
app.post("/api/register", async (req: any, res: any) => {
  try {
    // Benutzername trimmen, egal ob er in req.body.user.username oder req.body.username übergeben wird
    const username = (
      (req.body.user && req.body.user.username) ||
      req.body.username ||
      ""
    ).trim();
    if (!username) {
      return res.status(400).json({ error: "Username ist erforderlich" });
    }

    let options = await generateRegistrationOptions(username);

    // Apply test config if in test mode (for excludeCredentials, etc.)
    if (isTestModeActive()) {
      const testConfig = getCurrentTestConfig();
      console.log("🧪 Applying test config to registration options");
      console.log("🧪 excludeCredentials count:", testConfig.excludeCredentials?.length || 0);
      options = applyTestConfigToRegistrationOptions(options, testConfig);
      console.log("🧪 Final options.excludeCredentials:", JSON.stringify(options.excludeCredentials, null, 2));
    }

    res.json(options);
  } catch (error) {
    console.error("Fehler beim Erstellen der Registrierungschallenge:", error);
    res
      .status(500)
      .json({ error: "Fehler beim Erstellen der Registrierungschallenge" });
  }
});

/**
 * 🔹 Schritt 2: Registrierung - Schlüssel verifizieren
 * iOS-App sendet: { username: "alice", credential: {...} }
 * Server überprüft den Passkey und speichert ihn
 */
app.post("/api/register/verify", async (req: any, res: any) => {
  try {
    // DEBUG: Log complete request from iOS/Safari
    console.log("🔍 DEBUG: Complete request received at /api/register/verify:");
    console.log("🔍 DEBUG: Headers:", JSON.stringify(req.headers, null, 2));
    console.log("🔍 DEBUG: Body:", JSON.stringify(req.body, null, 2));

    // Check for originApp parameter (from PasskeyGuard iOS deeplink flow)
    if (req.body.originApp) {
      console.log("🔗 DEBUG: originApp detected:", req.body.originApp);
    }
    
    // Helper function to format Buffer data
    const formatBuffer = (buffer: Buffer, maxBytes: number = 50): string => {
      if (!Buffer.isBuffer(buffer)) return 'Not a buffer';
      const hex = buffer.slice(0, maxBytes).toString('hex');
      const truncated = buffer.length > maxBytes ? `... (${buffer.length - maxBytes} more bytes)` : '';
      return `${hex}${truncated}`;
    };
    
    // Helper function to format object with Buffers
    const formatObjectWithBuffers = (obj: any, indent: number = 0): string => {
      const spaces = ' '.repeat(indent);
      let result = '';
      
      for (const [key, value] of Object.entries(obj)) {
        if (Buffer.isBuffer(value)) {
          result += `${spaces}${key}: Buffer(${value.length} bytes) [${formatBuffer(value, 32)}]\n`;
        } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
          result += `${spaces}${key}:\n${formatObjectWithBuffers(value, indent + 2)}`;
        } else if (Array.isArray(value)) {
          result += `${spaces}${key}: Array(${value.length} items)\n`;
        } else {
          result += `${spaces}${key}: ${JSON.stringify(value)}\n`;
        }
      }
      return result;
    };

    const { username, credential, platform } = req.body;
    if (!username || !credential) {
      console.error(
        "[REGISTER/VERIFY] Fehler: Username oder Credential fehlen"
      );
      return res
        .status(400)
        .json({ error: "Username und Credential sind erforderlich" });
    }
    
    console.log(
      `[REGISTER/VERIFY] Starte Verifikation für Benutzer: ${username}`
    );
    
    // DEBUG: Log credential details
    console.log("🔍 DEBUG: Credential structure received from iOS:");
    console.log("🔍 DEBUG: - ID:", credential.id);
    console.log("🔍 DEBUG: - Raw ID:", credential.rawId);
    console.log("🔍 DEBUG: - Type:", credential.type);
    console.log("🔍 DEBUG: - Response object keys:", Object.keys(credential.response || {}));
    
    if (credential.response) {
      console.log("🔍 DEBUG: - clientDataJSON (base64):", credential.response.clientDataJSON?.substring(0, 100) + "...");
      console.log("🔍 DEBUG: - attestationObject (base64):", credential.response.attestationObject?.substring(0, 100) + "...");
      console.log("🔍 DEBUG: - attestationObject size:", credential.response.attestationObject?.length || 0);
      
      // Try to decode clientDataJSON
      try {
        const clientDataBuffer = Buffer.from(credential.response.clientDataJSON, 'base64');
        const clientData = JSON.parse(clientDataBuffer.toString());
        console.log("🔍 DEBUG: Decoded clientDataJSON:", JSON.stringify(clientData, null, 2));
      } catch (e) {
        console.log("🔍 DEBUG: Could not decode clientDataJSON:", e);
      }
      
      // Try to decode attestationObject structure
      try {
        const attestationBuffer = Buffer.from(credential.response.attestationObject, 'base64');
        console.log("🔍 DEBUG: AttestationObject buffer size:", attestationBuffer.length);
        console.log("🔍 DEBUG: AttestationObject hex preview:", formatBuffer(attestationBuffer, 50));
        
        // Import cbor at the top of the function if needed
        const cbor = require('cbor');
        
        // Decode CBOR attestation object
        try {
          const attestationObject = cbor.decodeFirstSync(attestationBuffer);
          console.log("\n🔍 DEBUG: Decoded attestation object:");
          console.log("  fmt (attestation format):", attestationObject.fmt);
          console.log("  authData:", attestationObject.authData ? `Buffer(${attestationObject.authData.length} bytes)` : 'N/A');
          
          // Log attStmt structure concisely
          console.log("\n🔍 DEBUG: attStmt (attestation statement):");
          if (attestationObject.attStmt) {
            console.log(formatObjectWithBuffers(attestationObject.attStmt, 2));
            
            // Special check for dcAppAttest
            if ('dcAppAttest' in attestationObject.attStmt) {
              console.log("\n✅ dcAppAttest field found in attStmt!");
              const dcAppAttest = attestationObject.attStmt.dcAppAttest;
              
              if (Buffer.isBuffer(dcAppAttest)) {
                console.log(`  Size: ${dcAppAttest.length} bytes`);
                console.log(`  Preview: ${formatBuffer(dcAppAttest, 32)}`);
                
                // Try to parse dcAppAttest as CBOR if it's large enough
                if (dcAppAttest.length > 100) {
                  try {
                    const dcAppAttestDecoded = cbor.decodeFirstSync(dcAppAttest);
                    console.log("  Decoded dcAppAttest structure:");
                    console.log(formatObjectWithBuffers(dcAppAttestDecoded, 4));
                  } catch (e) {
                    console.log("  dcAppAttest is not CBOR encoded, might be raw certificate data");
                  }
                }
              }
            } else {
              console.log("\n❌ dcAppAttest field NOT found in attStmt");
              console.log("  Available fields:", Object.keys(attestationObject.attStmt).join(', '));
            }
          } else {
            console.log("  attStmt is null or undefined");
          }
          
          // Log attestation format check
          if (attestationObject.fmt === 'none') {
            console.log("\n✅ Attestation format is 'none' (expected for passkey with embedded App Attest)");
          } else if (attestationObject.fmt === 'apple-appattest') {
            console.log("\n✅ Attestation format is 'apple-appattest'");
          } else {
            console.log("\n⚠️ Unexpected attestation format:", attestationObject.fmt);
          }
          
        } catch (cborError) {
          console.log("🔍 DEBUG: Failed to decode attestation object as CBOR:", cborError);
        }
      } catch (e) {
        console.log("🔍 DEBUG: Could not decode attestationObject:", e);
      }
    }
    
    try {
      // Try standard verification first
      const result = await verifyRegistration(credential, username);
      console.log(
        "[REGISTER/VERIFY] Verifikation erfolgreich. Ergebnis:",
        result
      );

      // Extrahiere nur die relevanten Felder und gebe sie an ios zurück
      const simpleResult = {
        attestationObject: result.request.response.attestationObject,
        clientDataJSON: result.request.response.clientDataJSON,
      };

      console.log("[REGISTER/VERIFY] Einfaches Ergebnis:", simpleResult);

      // Test Result speichern wenn im Test-Modus
      if (isTestModeActive()) {
        const testConfig = getCurrentTestConfig();

        // Extrahiere rawAuthnrData aus dem result für E2E Test-Validierung
        const rawAuthnrData = result.authnrData.get('rawAuthnrData');
        const authDataBuffer = rawAuthnrData ? Buffer.from(rawAuthnrData) : undefined;

        const testResult = createRegistrationResult(
          testConfig.testId || 'unknown',
          testConfig,
          true,
          {
            rawRequest: req.body,
            rawResponse: simpleResult,
            authenticatorData: authDataBuffer,
            attestationObject: {
              fmt: result.authnrData.get('fmt') || 'none',
              attStmt: {}  // 'none' format hat keine attestation statement
            },
            credential: {
              id: typeof credential.id === 'string' ? credential.id : Buffer.from(credential.id).toString('base64url'),
              rawId: typeof credential.rawId === 'string' ? credential.rawId : Buffer.from(credential.rawId).toString('base64url'),
              type: credential.type || 'public-key'
            }
          }
        );
        testResultStore.addResult(testResult);
        console.log("🧪 Test result stored for:", testConfig.testId);
      }

      // Antworte mit dem Ergebnis
      res.json({ success: true, ...simpleResult });
    } catch (error: any) {
      // Check if the error is due to clientDataHash from iOS
      if (error.message?.includes("clientDataJson") || 
          error.message?.includes("parse") ||
          error.message?.includes("JSON")) {
        
        console.log("🍎 Standard verification failed - trying iOS-compatible approach");
        
        // Get the stored challenge
        const storedChallenge = await getChallenge(username);
        if (!storedChallenge) {
          console.error("No challenge found for user:", username);
          return res.status(400).json({ error: "Challenge not found" });
        }
        
        try {
          // Use simplified iOS registration handler
          const iosResult = await registerIOSSimple({
            credential,
            username,
            challenge: storedChallenge
          });
          
          if (!iosResult.success) {
            throw new Error(iosResult.error || "iOS registration failed");
          }
          
          console.log("✅ iOS-compatible registration successful");

          // Test Result speichern wenn im Test-Modus
          if (isTestModeActive()) {
            const testConfig = getCurrentTestConfig();

            // Für iOS-Pfad: Parse authenticatorData aus dem attestationObject
            let authDataBuffer: Buffer | undefined;
            try {
              const attObjBase64 = credential.response.attestationObject;
              const attObjBuffer = Buffer.from(attObjBase64.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
              const cbor = require('cbor');
              const decoded = cbor.decodeFirstSync(attObjBuffer);
              if (decoded.authData) {
                authDataBuffer = Buffer.from(decoded.authData);
              }
            } catch (e) {
              console.log('Could not parse authenticatorData for test result:', e);
            }

            const testResult = createRegistrationResult(
              testConfig.testId || 'unknown',
              testConfig,
              true,
              {
                rawRequest: req.body,
                authenticatorData: authDataBuffer,
                credential: {
                  id: typeof credential.id === 'string' ? credential.id : Buffer.from(credential.id).toString('base64url'),
                  rawId: typeof credential.rawId === 'string' ? credential.rawId : Buffer.from(credential.rawId).toString('base64url'),
                  type: credential.type || 'public-key'
                }
              }
            );
            testResultStore.addResult(testResult);
            console.log("🧪 Test result stored (iOS path) for:", testConfig.testId);
          }

          // Return success with the original credential data
          res.json({
            success: true,
            attestationObject: credential.response.attestationObject,
            clientDataJSON: credential.response.clientDataJSON
          });
        } catch (iosError) {
          console.error("iOS registration also failed:", iosError);
          return res.status(400).json({ 
            error: "Registration failed",
            detail: iosError instanceof Error ? iosError.message : "Unknown error"
          });
        }
      } else {
        // Other error - return original error
        console.error(
          "[REGISTER/VERIFY] Fehler beim Verifizieren der Registrierung:",
          error
        );
        res
          .status(500)
          .json({ error: "Fehler beim Verifizieren der Registrierung" });
      }
    }
  } catch (error) {
    console.error(
      "[REGISTER/VERIFY] Fehler beim Verifizieren der Registrierung:",
      error
    );
    res
      .status(500)
      .json({ error: "Fehler beim Verifizieren der Registrierung" });
  }
});

/**
 * 🔹 Android Attestation Direct Endpoint
 * Android-App kann direkte Attestation-Daten anfordern
 */
app.post("/api/android/attestation-direct", async (req: any, res: any) => {
  try {
    const { username, platform } = req.body;
    
    if (!username) {
      return res.status(400).json({ error: "Username ist erforderlich" });
    }
    
    console.log(`[ANDROID-ATTESTATION-DIRECT] Request for: ${username}`);
    
    // Generiere WebAuthn Optionen für Android Direct Attestation
    const options = await generateAndroidDirectRegistrationOptions(username);
    
    console.log("[ANDROID-ATTESTATION-DIRECT] Direct attestation options:", {
      attestation: options.attestation,
      authenticatorSelection: options.authenticatorSelection
    });
    
    res.json({
      success: true,
      options: options,
      attestation: "direct"
    });
    
  } catch (error) {
    console.error("[ANDROID-ATTESTATION-DIRECT] Error:", error);
    res.status(500).json({ 
      error: "Fehler bei Android Attestation Direct",
      detail: error instanceof Error ? error.message : "Unknown error"
    });
  }
});

/**
 * 🔹 Schritt 3: Login - Challenge generieren
 * iOS-App sendet: { username: "alice" }
 * Server antwortet mit den WebAuthn-Login-Optionen
 */
app.post("/api/login", async (req: any, res: any) => {
  try {
    const username = (req.body.username || "").trim();
    if (!username) {
      return res.status(400).json({ error: "Username ist erforderlich" });
    }
    const options = await generateAuthenticationOptions(username);
    res.json(options);
  } catch (error) {
    console.error("Fehler beim Erstellen der Login-Challenge:", error);
    res
      .status(500)
      .json({ error: "Fehler beim Erstellen der Login-Challenge" });
  }
});

/**
 * 🔹 Schritt 3b: Discoverable Login - Challenge generieren (Usernameless)
 * Kein Username erforderlich - iOS zeigt ALLE Passkeys fuer diese Domain
 * allowCredentials ist leer -> Discoverable/Resident Key Flow
 */
app.post("/api/login/discoverable", async (req: any, res: any) => {
  try {
    console.log("Discoverable Login angefordert (kein Username)");
    const options = await generateDiscoverableAuthenticationOptions();
    res.json(options);
  } catch (error) {
    console.error("Fehler beim Erstellen der Discoverable Login-Challenge:", error);
    res
      .status(500)
      .json({ error: "Fehler beim Erstellen der Discoverable Login-Challenge" });
  }
});

/**
 * 🔹 Schritt 3c: Discoverable Login - Verifizierung
 * Kein Username - User wird anhand der credentialId identifiziert
 */
app.post("/api/login/discoverable/verify", async (req: any, res: any) => {
  try {
    const { assertion, sessionId } = req.body;
    if (!assertion || !sessionId) {
      return res
        .status(400)
        .json({ error: "Assertion und sessionId sind erforderlich" });
    }

    console.log("Discoverable Login Verify mit sessionId:", sessionId);

    // Convert base64 strings back to ArrayBuffers for fido2-lib
    const convertedAssertion = convertAssertionToArrayBuffers(assertion);

    const result = await verifyDiscoverableAuthentication(convertedAssertion, sessionId);

    // Test Result speichern wenn im Test-Modus
    if (isTestModeActive()) {
      const testConfig = getCurrentTestConfig();
      const testResult = createAuthenticationResult(
        testConfig.testId || 'unknown',
        testConfig,
        true,
        { rawRequest: req.body }
      );
      testResultStore.addResult(testResult);
      console.log("🧪 Discoverable auth test result stored for:", testConfig.testId);
    }

    res.json({ success: true, username: result.username });
  } catch (error) {
    console.error("Fehler beim Verifizieren der Discoverable Authentifizierung:", error);
    res
      .status(500)
      .json({ error: "Fehler beim Verifizieren der Discoverable Authentifizierung" });
  }
});

/**
 * 🔹 Schritt 4: Login - Authentifizierung verifizieren
 * iOS-App sendet: { username: "alice", assertion: {...}, publicKey: "abc123..." }
 * Server überprüft die Authentifizierung
 */
// Convert base64 strings back to ArrayBuffers for fido2-lib
function convertAssertionToArrayBuffers(assertion: any) {
  console.log('Converting assertion from base64 strings to ArrayBuffers:', {
    id: assertion.id,
    rawId: assertion.rawId,
    type: assertion.type,
    response: {
      authenticatorData: assertion.response.authenticatorData?.substring(0, 20) + '...',
      clientDataJSON: assertion.response.clientDataJSON?.substring(0, 20) + '...',
      signature: assertion.response.signature?.substring(0, 20) + '...',
      userHandle: assertion.response.userHandle,
    }
  });
  
  const converted = {
    id: assertion.rawId ? base64UrlToArrayBuffer(assertion.rawId) : assertion.id,
    rawId: assertion.rawId ? base64UrlToArrayBuffer(assertion.rawId) : base64UrlToArrayBuffer(assertion.id),
    response: {
      authenticatorData: base64UrlToArrayBuffer(assertion.response.authenticatorData),
      clientDataJSON: base64UrlToArrayBuffer(assertion.response.clientDataJSON),
      signature: base64UrlToArrayBuffer(assertion.response.signature),
      userHandle: assertion.response.userHandle ? base64UrlToArrayBuffer(assertion.response.userHandle) : null,
    },
    type: assertion.type,
  };
  
  console.log('Converted assertion types:', {
    id: converted.id?.constructor?.name,
    rawId: converted.rawId?.constructor?.name,
    authenticatorData: converted.response.authenticatorData?.constructor?.name,
    clientDataJSON: converted.response.clientDataJSON?.constructor?.name,
    signature: converted.response.signature?.constructor?.name,
    userHandle: converted.response.userHandle?.constructor?.name,
  });
  
  return converted;
}

app.post("/api/login/verify", async (req: any, res: any) => {
  try {
    const { username, assertion, publicKey } = req.body;
    if (!username || !assertion) {
      return res
        .status(400)
        .json({ error: "Username und Assertion sind erforderlich" });
    }
    
    // Convert base64 strings back to ArrayBuffers for fido2-lib
    const convertedAssertion = convertAssertionToArrayBuffers(assertion);
    
    const result = await verifyAuthentication(convertedAssertion, publicKey, username);

    // Test Result speichern wenn im Test-Modus
    if (isTestModeActive()) {
      const testConfig = getCurrentTestConfig();

      // Extract authenticatorData from the assertion for test analysis
      let authenticatorDataBuffer: Buffer | undefined;
      if (convertedAssertion.response?.authenticatorData) {
        authenticatorDataBuffer = Buffer.from(convertedAssertion.response.authenticatorData);
      }

      const testResult = createAuthenticationResult(
        testConfig.testId || 'unknown',
        testConfig,
        true,
        {
          authenticatorData: authenticatorDataBuffer,
          rawRequest: req.body,
        }
      );
      testResultStore.addResult(testResult);
      console.log("🧪 Auth test result stored for:", testConfig.testId);
    }

    res.json({ success: true, result });
  } catch (error) {
    console.error("Fehler beim Verifizieren der Authentifizierung:", error);
    res
      .status(500)
      .json({ error: "Fehler beim Verifizieren der Authentifizierung" });
  }
});

/**
 * 🔹 Debugging - JSON speichern
 * POST /api/debugging
 * Empfängt ein JSON-Objekt im Request-Body und speichert es in der Tabelle "debugging" (Spalte "data" vom Typ JSONB).
 */
app.post("/api/debugging", async (req: any, res: any) => {
  // 🔒 Prüfe API-Schlüssel aus Query-Parameter
  const apiKey = req.query.APIKEY;
  if (!apiKey || apiKey !== process.env.API_KEY) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  try {
    const jsonData = req.body;
    // Stelle sicher, dass eine Tabelle "debugging" mit einer JSONB-Spalte "data" existiert.
    const query = 'INSERT INTO debugging (data) VALUES ($1)';
    await pool.query(query, [jsonData]);
    res.status(201).json({ success: true });
  } catch (error) {
    console.error("Fehler beim Speichern der Debugging-Daten:", error);
    res.status(500).json({ error: "Fehler beim Speichern der Debugging-Daten" });
  }
});

/**
 * 🔹 User-Liste Endpoint
 * GET /api/users
 * Gibt alle registrierten User zurück
 */
app.get("/api/users", async (req: any, res: any) => {
  try {
    const users = await User.find({}, 'username registrationPlatform createdAt').lean();
    const totalUsers = users.length;

    res.json({
      totalUsers,
      users: users.map(u => ({
        username: u.username,
        platform: u.registrationPlatform || 'unknown',
        createdAt: u.createdAt || null
      }))
    });
  } catch (error) {
    console.error("Fehler beim Abrufen der User:", error);
    res.status(500).json({ error: "Fehler beim Abrufen der User" });
  }
});

/**
 * 🔹 User löschen Endpoint
 * DELETE /api/users/:username
 */
app.delete("/api/users/:username", async (req: any, res: any) => {
  try {
    const { username } = req.params;
    const result = await User.deleteOne({ username });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: "User nicht gefunden" });
    }

    res.json({ success: true, message: `User ${username} gelöscht` });
  } catch (error) {
    console.error("Fehler beim Löschen des Users:", error);
    res.status(500).json({ error: "Fehler beim Löschen des Users" });
  }
});

/**
 * 🔹 Alle User löschen Endpoint
 * DELETE /api/users
 */
app.delete("/api/users", async (req: any, res: any) => {
  try {
    const result = await User.deleteMany({});
    res.json({ success: true, deletedCount: result.deletedCount });
  } catch (error) {
    console.error("Fehler beim Löschen aller User:", error);
    res.status(500).json({ error: "Fehler beim Löschen aller User" });
  }
});

// Server starten
connectDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server läuft auf Port ${PORT}`);
  });
});
