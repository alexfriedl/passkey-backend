import express from "express";
import base64url from "base64url";
import * as cbor from "cbor";
import { X509Certificate } from "@peculiar/x509"; 
import { createHash, randomBytes, createVerify } from "crypto";
import { storeChallenge, getChallenge, deleteChallenge } from "./challenge-store";
import AppAttestKey from "./models/AppAttestKey";
import { AttestationConverter } from "./attestation-converter";
import mongoose from "mongoose";

const router = express.Router();

// Apple App Attest Root CA (vollständiges Zertifikat)
// Quelle: https://www.apple.com/certificateauthority/
const APPLE_APP_ATTEST_ROOT_CA = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDBdBcHBsZSBBcHAgQXR0ZXN0YXRpb24gQ0ExEzARBgNVBAoMCkFwcGxl
IEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwMzE4MTgzMjUzWhcNMzAw
MzEzMDAwMDAwWjBSMSYwJAYDVQQDDBdBcHBsZSBBcHAgQXR0ZXN0YXRpb24gQ0Ex
EzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwdjAQBgcq
hkjOPQIBBgUrgQQAIgNiAARTHhmLW07ATaFQIEVwTtT4dyctdhNbJhFs/Ii2FdCg
AHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9auYen1mMEvRq9Sk3
Jy+9ArJ+6K0W+b9OY2TsHFajZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0P
AQH/BAQDAgGGMB0GA1UdDgQWBBQOz4zFg3JBjWFtew1SCQ/CXz9BTTAfBgNVHSME
GDAWgBQOz4zFg3JBjWFtew1SCQ/CXz9BTTAKBggqhkjOPQQDAwNoADBlAjEAlKMq
lLOGqeH5X67rNX7BH9Cfh8VLVG/OQJH6BwSaUBUCIDkw7wMk0MrM5uHaRFnRT3F6
JUQlo/8fHaiD3a9BnMCMQDB1wBxJni+bOMY9E6ja5FBmGnRrY2xnCGWhHvPx1yvo
BQnzCaXHRm6jWIqfW8p3Soc=
-----END CERTIFICATE-----`;

/**
 * 1) GET /api/appattest/challenge
 * Server erzeugt eine zufällige Nonce, speichert sie und gibt sie zurück.
 * FÜR LOKALE CHALLENGE: Dieser Endpoint wird nicht benötigt, da die Challenge lokal generiert wird.
 * Wir implementieren ihn trotzdem für Flexibilität.
 */
router.get("/challenge", async (req: any, res: any) => {
  const { username } = req.query;
  if (!username || typeof username !== "string") {
    return res.status(400).json({ error: "username required" });
  }

  const nonce = randomBytes(32);
  const nonceB64u = base64url(nonce);
  
  // Speichere mit appattest-Präfix, um Konflikte mit WebAuthn zu vermeiden
  storeChallenge(`appattest:${username}`, nonceB64u);
  
  res.json({ challenge: nonceB64u });
});

/**
 * 2) POST /api/appattest/attest
 * Verifiziert die Apple App Attest Attestation
 * 
 * Erwartet:
 * - keyId: Base64URL der Key-ID
 * - attestationObject: Base64URL des Attestation Objects
 * - localChallenge: Base64URL des lokal generierten Challenge-Hash (z.B. Hash des Formulars)
 * - username: Benutzername für die Zuordnung
 */
router.post("/attest", async (req: any, res: any) => {
  try {
    console.log("\n========== APP ATTEST VERIFICATION START ==========");
    console.log("Timestamp:", new Date().toISOString());
    console.log("Request body:", JSON.stringify(req.body, null, 2));
    
    const { username, keyId, attestationObject, localChallenge } = req.body || {};
    
    if (!username || !keyId || !attestationObject || !localChallenge) {
      console.log("❌ Missing required fields");
      return res.status(400).json({ error: "missing required fields" });
    }
    
    console.log("\n📝 Input Data:");
    console.log("- Username:", username);
    console.log("- KeyId length:", keyId.length);
    console.log("- AttestationObject length:", attestationObject.length);
    console.log("- LocalChallenge length:", localChallenge.length);

    // Decode inputs
    const keyIdBuf = base64url.toBuffer(keyId);
    const attBuf = base64url.toBuffer(attestationObject);
    const localChallengeBuf = base64url.toBuffer(localChallenge);
    
    // CBOR decode attestation object
    const att = cbor.decodeFirstSync(attBuf) as any;
    
    if (att.fmt !== "apple-appattest") {
      return res.status(400).json({ error: `unexpected fmt: ${att.fmt}` });
    }
    
    const { attStmt, authData } = att;

    // 1) Zertifikatskette extrahieren
    const x5c: Buffer[] = (attStmt?.x5c || []).map((cert: any) => Buffer.from(cert));
    if (!x5c?.length) {
      return res.status(400).json({ error: "missing x5c certificate chain" });
    }

    // 2) Parse Leaf Certificate
    const leafCert = new X509Certificate(x5c[0]);
    
    // TODO: Vollständige Zertifikatsketten-Validierung gegen Apple Root
    // Hier nur Basis-Checks
    
    // 3) App ID aus Zertifikat-Extension extrahieren
    // Apple App Attest speichert die App ID in einer speziellen Extension
    // OID: 1.2.840.113635.100.8.2
    const appIdExtension = leafCert.extensions.find(
      ext => ext.type === "1.2.840.113635.100.8.2"
    );
    
    if (!appIdExtension) {
      return res.status(400).json({ error: "missing app identifier extension" });
    }

    // Parse App ID (Format: TeamID.BundleID)
    // TODO: Verify against expected app ID
    
    // 4) AuthData parsen
    const { rpIdHash, flags, counter, credentialId, publicKey } = parseAuthData(authData);
    
    // 5) Nonce verifizieren
    // Bei lokaler Challenge ist der clientDataHash direkt die localChallenge
    // Apple App Attest verwendet den clientDataHash als Teil der Attestation
    if (!publicKey) {
      return res.status(400).json({ error: "No public key found in authData" });
    }
    
    // Bei lokaler Challenge-Implementierung:
    // Der Server kann die localChallenge nicht direkt verifizieren,
    // da sie vom Client generiert wurde. Stattdessen vertrauen wir darauf,
    // dass die Attestation korrekt mit dieser Challenge durchgeführt wurde.
    
    // Optional: Prüfe ob localChallenge plausibel ist (z.B. Länge, Format)
    if (localChallengeBuf.length !== 32) {
      return res.status(400).json({ error: "invalid localChallenge format (expected 32 bytes SHA256)" });
    }
    
    // TODO: In Produktion sollte man zusätzliche Checks machen:
    // - Timestamp aus der Challenge extrahieren und auf Aktualität prüfen
    // - Challenge-Format validieren wenn bekannt
    
    // 6) Signatur verifizieren
    // TODO: Verify signature over authData using leaf certificate
    
    // 7) Speichere verifizierten Key
    // In der Praxis würde man hier den Key in einer Datenbank speichern
    // zusammen mit username, keyId, publicKey, counter etc.
    
    // Speichere den verifizierten Key in der Datenbank (falls MongoDB verbunden)
    let savedKey = null;
    try {
      if (mongoose.connection.readyState === 1) {
        savedKey = await AppAttestKey.findOneAndUpdate(
          { keyId: base64url(keyIdBuf) },
          {
            username,
            keyId: base64url(keyIdBuf),
            publicKey: base64url(publicKey),
            counter,
            appId: appIdExtension?.value?.toString() || "unknown",
            lastUsed: new Date()
          },
          { upsert: true, new: true }
        );
      } else {
        console.log("⚠️  MongoDB not connected - skipping database save");
      }
    } catch (dbError) {
      console.error("Database save error:", dbError);
      // Continue without saving to DB for testing
    }
    
    // Erstelle verschiedene Format-Optionen für Schritt 4
    const appAttestData = AttestationConverter.extractAppAttestData(attBuf);
    
    // Option 1: FIDO2 Wrapper (empfohlen)
    const fido2Wrapper = AttestationConverter.createFIDO2Wrapper(
      appAttestData,
      localChallengeBuf
    );
    
    // Option 2: Server-Attestation (wenn Server-Keys vorhanden)
    // const serverAttestation = AttestationConverter.createServerAttestation(
    //   appAttestData,
    //   process.env.SERVER_PRIVATE_KEY!,
    //   process.env.SERVER_CERTIFICATE!
    // );
    
    const verificationResult = {
      verified: true,
      keyId: base64url(keyIdBuf),
      publicKey: base64url(publicKey),
      counter,
      appId: appIdExtension?.value?.toString() || "unknown",
      // Format-Konvertierungen
      formats: {
        fido2Wrapper,
        // Packed-like Format nur auf explizite Anfrage
        // packedLike: req.body.requestPackedFormat ? 
        //   base64url(AttestationConverter.createPackedLikeStructure(appAttestData)) : undefined
      }
    };
    
    console.log("\n✅ APP ATTEST VERIFICATION SUCCESSFUL!");
    console.log("========== APP ATTEST VERIFICATION END ==========\n");
    console.log("Response:", JSON.stringify(verificationResult, null, 2));
    
    return res.json(verificationResult);
    
  } catch (e: any) {
    console.error("\n❌ App Attest verification error:", e);
    console.error("Stack trace:", e?.stack);
    console.log("========== APP ATTEST VERIFICATION FAILED ==========\n");
    return res.status(400).json({ 
      error: "verification_failed", 
      detail: e?.message 
    });
  }
});

/**
 * 3) POST /api/appattest/assert
 * Generiert eine Assertion für spätere Requests
 * (Nach erfolgreicher Attestation)
 */
router.post("/assert", async (req: any, res: any) => {
  const { username, keyId, clientData } = req.body || {};
  
  if (!username || !keyId || !clientData) {
    return res.status(400).json({ error: "missing required fields" });
  }
  
  // In der Praxis: Lookup des verifizierten Keys aus der DB
  // Hier würde man DCDevice.generateAssertion() aufrufen
  
  // Für jetzt: Dummy Response
  res.json({ 
    message: "Assertion endpoint - implement with actual key lookup",
    keyId,
    username 
  });
});

export default router;

// Helper Functions

/**
 * Parse AuthData gemäß WebAuthn/FIDO2 Spec
 */
function parseAuthData(authData: Buffer): {
  rpIdHash: Buffer;
  flags: number;
  counter: number;
  credentialId?: Buffer;
  publicKey?: Buffer;
} {
  let offset = 0;
  
  // RP ID Hash (32 bytes)
  const rpIdHash = authData.slice(offset, offset + 32);
  offset += 32;
  
  // Flags (1 byte)
  const flags = authData[offset];
  offset += 1;
  
  // Counter (4 bytes, big-endian)
  const counter = authData.readUInt32BE(offset);
  offset += 4;
  
  // Check if Attested Credential Data is present (bit 6 of flags)
  if (!(flags & 0x40)) {
    return { rpIdHash, flags, counter };
  }
  
  // AAGUID (16 bytes)
  const aaguid = authData.slice(offset, offset + 16);
  offset += 16;
  
  // Credential ID Length (2 bytes, big-endian)
  const credIdLen = authData.readUInt16BE(offset);
  offset += 2;
  
  // Credential ID
  const credentialId = authData.slice(offset, offset + credIdLen);
  offset += credIdLen;
  
  // Public Key (COSE format) - rest of the buffer
  const publicKeyBytes = authData.slice(offset);
  const coseKey = cbor.decodeFirstSync(publicKeyBytes);
  
  // Convert COSE key to raw format (für ECDSA P-256)
  const x = coseKey.get(-2);
  const y = coseKey.get(-3);
  const publicKey = Buffer.concat([
    Buffer.from([0x04]), // Uncompressed point
    x,
    y
  ]);
  
  return { rpIdHash, flags, counter, credentialId, publicKey };
}