import express from "express";
import cors from "cors";
import {
  generateRegistrationOptions,
  verifyRegistration,
  generateAuthenticationOptions,
  verifyAuthentication,
} from "./webauthn";
import path from "path";
import { connectDB } from "./mongodb";
import { Pool } from "pg";

// Configure PostgreSQL connection (Neon Postgres on Heroku)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

const app = express();
const PORT = process.env.PORT || 3000;
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
    // Die an ios zurückgegebenen Daten sind in verifyRegistration gepatcht worden
    // und enthalten die AttestationObject und clientDataJSON mit den Werten fmt: "none" und attStmt: {}
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
app.listen(PORT, () => {
  console.log(`🚀 Server läuft auf http://localhost:${PORT}`);
});
