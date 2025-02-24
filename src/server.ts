import express from "express";
import cors from "cors";
import {
  generateRegistrationOptions,
  verifyRegistration,
  generateAuthenticationOptions,
  verifyAuthentication,
} from "./webauthn";
import path from "path";
import { Fido2AttestationResult } from "fido2-lib";

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

    // Debug und Konvertierung:
    const flatResult = convertAttestationResult(result);

    res.json({ success: true, result: flatResult });
  } catch (error) {
    console.error("Fehler beim Verifizieren der Registrierung:", error);
    res
      .status(500)
      .json({ error: "Fehler beim Verifizieren der Registrierung" });
  }
});
// Hilfsfunktion: Wandelt eine Map rekursiv in ein normales Objekt um.
function mapToObj(map: any[] | Map<any, any>) {
  if (!(map instanceof Map)) {
    return map; // falls es schon kein Map ist
  }
  const obj: { [key: string]: any } = {};
  for (const [key, value] of map.entries()) {
    obj[key] = value instanceof Map ? mapToObj(value) : value;
  }
  return obj;
}

// Debug-Funktion, die das Attestation-Ergebnis konvertiert und alle Zwischenschritte loggt.
function convertAttestationResult(result: Fido2AttestationResult) {
  console.log("=== Raw Fido2AttestationResult ===");
  console.dir(result, { depth: null });

  // Konvertiere einzelne Bestandteile:
  const authnrDataObj = mapToObj(result.authnrData);
  console.log("Converted authnrData:", authnrDataObj);

  const clientDataObj = mapToObj(result.clientData);
  console.log("Converted clientData:", clientDataObj);

  const expectationsObj = mapToObj(result.expectations);
  console.log("Converted expectations:", expectationsObj);

  const auditObj = {
    validExpectations: result.audit.validExpectations,
    validRequest: result.audit.validRequest,
    complete: result.audit.complete,
    journal: Array.from(result.audit.journal),
    warning: mapToObj(result.audit.warning),
    info: mapToObj(result.audit.info),
  };
  console.log("Converted audit:", auditObj);

  // Erstelle ein flaches Objekt, das nur primitive Datentypen enthält.
  const flatResult = {
    authnrData: authnrDataObj,
    clientData: clientDataObj,
    expectations: expectationsObj,
    request: {
      // Wir extrahieren nur die benötigten Felder aus der Request
      response: {
        attestationObject: result.request.response.attestationObject,
        clientDataJSON: result.request.response.clientDataJSON,
      },
    },
    audit: auditObj,
  };

  console.log("=== Flach konvertiertes Attestation-Ergebnis ===");
  console.dir(flatResult, { depth: null });
  return flatResult;
}

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
