import express from "express";
import cors from "cors";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();
import {
  generateRegistrationOptions,
  verifyRegistration,
  generateAuthenticationOptions,
  verifyAuthentication,
} from "./webauthn";
import path from "path";
import { connectDB } from "./mongodb";
import { Pool } from "pg";
import appAttestRouter from "./appattest";
import { verifyIOSRegistration } from "./ios-registration";

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

connectDB().then(() => {
  app.listen(MONGOPORT, () => {
    console.log(`Server läuft auf http://localhost:${MONGOPORT}`);
  });
});

app.get("/.well-known/apple-app-site-association", (req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.sendFile(
    path.join(__dirname, "../public/.well-known/apple-app-site-association")
  );
});

app.use(express.static(path.join(__dirname, "../public")));

// Apple App Attest Router
app.use("/api/appattest", appAttestRouter);

/**
 * 🔹 Combined Passkey + App Attest Registration
 * iOS-App sendet beide Attestations in einem Request
 */
app.post("/api/register/combined", async (req: any, res: any) => {
  try {
    console.log("\n========== COMBINED REGISTRATION START ==========");
    console.log("Timestamp:", new Date().toISOString());
    
    const { username, passkey, appAttest, platform } = req.body;
    
    // Validate required fields
    if (!username || !passkey || !appAttest) {
      console.error("Missing required fields in combined registration");
      return res.status(400).json({ 
        error: "Username, passkey, and appAttest data are required" 
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
    
    // Step 2: Verify App Attest
    console.log("\n🔒 Step 2: Verifying App Attest...");
    let appAttestResult: any;
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
    
    // Step 3: Link credentials in database (if needed)
    console.log("\n🔗 Step 3: Linking credentials...");
    // TODO: Update user model to store both credential IDs if needed
    // For now, both are independently stored and linked by username
    
    // Prepare combined response
    const response = {
      success: true,
      username,
      passkey: {
        verified: true,
        attestationObject: passkeyResult.request.response.attestationObject,
        clientDataJSON: passkeyResult.request.response.clientDataJSON
      },
      appAttest: {
        verified: appAttestResult.verified,
        keyId: appAttestResult.keyId,
        publicKey: appAttestResult.publicKey,
        counter: appAttestResult.counter,
        appId: appAttestResult.appId
      },
      message: "Combined registration successful"
    };
    
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

    const options = await generateRegistrationOptions(username);
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
    // console.log("[REGISTER/VERIFY] Request received:", req.body);

    const { username, credential } = req.body;
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
    // console.log(
    //   "[REGISTER/VERIFY] Credential:",
    //   JSON.stringify(credential, null, 2)
    // );

    // Führe die Verifikation durch
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

    // Antworte mit dem Ergebnis
    // iOS-App wird die Daten speichern und für zukünftige Authentifizierungen verwenden
    // Die an ios zurückgegebenen Daten enthalten die AttestationObject und clientDataJSON
    res.json({ success: true, ...simpleResult });
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
 * 🔹 Schritt 4: Login - Authentifizierung verifizieren
 * iOS-App sendet: { username: "alice", assertion: {...}, publicKey: "abc123..." }
 * Server überprüft die Authentifizierung
 */
app.post("/api/login/verify", async (req: any, res: any) => {
  try {
    const { username, assertion, publicKey } = req.body;
    if (!username || !assertion) {
      return res
        .status(400)
        .json({ error: "Username und Assertion sind erforderlich" });
    }
    const result = await verifyAuthentication(assertion, publicKey, username);
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

// Server starten
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server läuft auf Port ${PORT}`);
});
