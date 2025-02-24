import express from "express";
import cors from "cors";
import {
  generateRegistrationOptions,
  verifyRegistration,
  generateAuthenticationOptions,
  verifyAuthentication,
} from "./webauthn";
import path from "path";

const app = express();
const PORT = process.env.PORT || 3000;

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

/**
 * 🔹 Schritt 1: Registrierung - Challenge generieren
 * iOS-App sendet: { username: "alice" }
 * Server antwortet mit den WebAuthn-Registrierungsoptionen
 */
app.post("/api/register", async (req: any, res: any) => {
  try {
    const { username } = req.body;
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
    const { username, credential } = req.body;
    if (!username || !credential) {
      return res
        .status(400)
        .json({ error: "Username und Credential sind erforderlich" });
    }

    const result = await verifyRegistration(credential, username);
    res.json({ success: true, result });
  } catch (error) {
    console.error("Fehler beim Verifizieren der Registrierung:", error);
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
    const { username } = req.body;
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

// Server starten
app.listen(PORT, () => {
  console.log(`🚀 Server läuft auf http://localhost:${PORT}`);
});
