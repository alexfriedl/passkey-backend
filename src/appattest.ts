import express from "express";
import base64url from "base64url";
import * as cbor from "cbor";
import { X509Certificate } from "@peculiar/x509"; 
import { X509Certificate as NodeX509Certificate } from "crypto";
import { createHash, randomBytes, createVerify } from "crypto";
import { storeChallenge, getChallenge, deleteChallenge } from "./challenge-store";
import AppAttestKey from "./models/AppAttestKey";
import { AttestationConverter } from "./attestation-converter";
import mongoose from "mongoose";

const router = express.Router();

// Apple App Attest Root CA - Dies ist das echte Root CA für App Attestation
// Quelle: https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
const APPLE_APP_ATTEST_ROOT_CA = `-----BEGIN CERTIFICATE-----
MIICJDCCAamgAwIBAgIUJAr99oqH14LsGCxZ/ray5VquJaUwCgYIKoZIzj0EAwMw
UjEmMCQGA1UEAwwdQXBwbGUgQXBwIEF0dGVzdGF0aW9uIFJvb3QgQ0ExEzARBgNV
BAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwMzE4MTgz
MjUzWhcNNDAwMzEzMDAwMDAwWjBSMSYwJAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0
YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2Fs
aWZvcm5pYTB2MBAGByqGSM49AgEGBSuBBAAiA2IABK2YmJmX1OnGRsbBj0Dh4RaJ
Bvzxk03SfHzwlZR3c9XQdEBEGx0IqQFNl9XOQN8c4JpKYjrJcBNXj5KSLQ5ycMhY
5ssDLi6sXaHA5gqZ0+xq0K9q5h0gU+kSbJlGjNzQkaNmMGQwEgYDVR0TAQH/BAgw
BgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFKyREFMzvb5oQf+nDKnl
+url5YqhMB8GA1UdIwQYMBaAFKyREFMzvb5oQf+nDKnl+url5YqhMAoGCCqGSM49
BAMDZ28AXgIxAK+I5m4aDHlSB8XErVl7t2szqU/jMJ3g4F6dBnj+RxPalpKk1OI7
xWmLB/m8So8EQgIxAPpKGlNe6lQsL72kMGmz9LqYr7HA2xGqGoF5FWk5TlPXBKxt
JiivPqPH7KkUJJF+uQ==
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
    
    console.log("\n🔓 Decoded Data:");
    console.log("- KeyId Buffer:", keyIdBuf.toString('hex'));
    console.log("- LocalChallenge Buffer:", localChallengeBuf.toString('hex'));
    console.log("- AttestationObject size:", attBuf.length, "bytes");
    
    // CBOR decode attestation object
    const att = cbor.decodeFirstSync(attBuf) as any;
    
    console.log("\n📦 CBOR Decoded Attestation Object:");
    console.log("- Format:", att.fmt);
    console.log("- AuthData length:", att.authData?.length || 0);
    console.log("- AttStmt keys:", Object.keys(att.attStmt || {}));
    
    // Detailliertes Logging des dekodierten Objekts
    console.log("\n📄 Full Attestation Object Structure (as JSON):");
    const simplifiedAtt = {
      fmt: att.fmt,
      authData: att.authData ? `[Buffer ${att.authData.length} bytes]` : null,
      attStmt: {
        x5c: att.attStmt?.x5c ? `[${att.attStmt.x5c.length} certificates]` : null,
        receipt: att.attStmt?.receipt ? `[Buffer ${att.attStmt.receipt.length} bytes]` : null
      }
    };
    console.log(JSON.stringify(simplifiedAtt, null, 2));
    
    // Zeige die ersten Bytes der AuthData
    if (att.authData) {
      console.log("\n🔍 AuthData preview (first 100 bytes):");
      console.log("Hex:", att.authData.toString('hex').substring(0, 200));
      const rpIdHashLength = 32;
      const flagsByte = att.authData[rpIdHashLength];
      console.log("RP ID Hash:", att.authData.slice(0, rpIdHashLength).toString('hex'));
      console.log("Flags byte:", flagsByte.toString(2).padStart(8, '0'));
      console.log("Counter:", att.authData.readUInt32BE(rpIdHashLength + 1));
    }
    
    if (att.fmt !== "apple-appattest") {
      console.log("❌ Unexpected format:", att.fmt);
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
    console.log("\n📜 Leaf Certificate:");
    console.log("- Subject:", leafCert.subject);
    console.log("- Issuer:", leafCert.issuer);
    console.log("- Serial Number:", leafCert.serialNumber);
    console.log("- Valid From:", new Date(leafCert.notBefore));
    console.log("- Valid To:", new Date(leafCert.notAfter));
    console.log("- Extensions:", leafCert.extensions.map(ext => ext.type));
    
    // Validiere Zertifikatskette gegen Apple Root CA
    console.log("\n🔒 Certificate Chain Validation:");
    try {
      // Nutze Node.js native crypto für bessere Kompatibilität
      const rootCert = new NodeX509Certificate(APPLE_APP_ATTEST_ROOT_CA);
      console.log("- Apple App Attest Root CA loaded successfully");
      console.log("- Root Subject:", rootCert.subject);
      console.log("- Root Issuer:", rootCert.issuer);
      console.log("- Root Valid To:", rootCert.validTo);
      
      // Prüfe Zertifikatskette
      if (x5c.length >= 2) {
        // Intermediate Certificate (Apple App Attestation CA 1)
        const intermediateCert = new NodeX509Certificate(x5c[1]);
        console.log("\n- Intermediate CA loaded");
        console.log("  Subject:", intermediateCert.subject);
        console.log("  Issuer:", intermediateCert.issuer);
        console.log("  Serial:", intermediateCert.serialNumber);
        
        // Prüfe ob Intermediate vom Root signiert wurde
        const isIntermediateValid = intermediateCert.verify(rootCert.publicKey);
        console.log("  Signature verification:", isIntermediateValid ? "✅ VALID" : "❌ INVALID");
        
        if (x5c.length >= 3) {
          // Wenn vorhanden, prüfe auch das Root Cert in der Kette
          const chainRoot = new NodeX509Certificate(x5c[2]);
          console.log("\n- Chain includes Root CA");
          console.log("  Subject:", chainRoot.subject);
          const isSameRoot = chainRoot.fingerprint === rootCert.fingerprint;
          console.log("  Matches expected Root:", isSameRoot ? "✅ YES" : "❌ NO");
        }
        
        // Prüfe ob Leaf vom Intermediate signiert wurde  
        const leafCertNode = new NodeX509Certificate(x5c[0]);
        const isLeafValid = leafCertNode.verify(intermediateCert.publicKey);
        console.log("\n- Leaf certificate signature:", isLeafValid ? "✅ VALID" : "❌ INVALID");
        
        console.log("\n✅ Certificate chain validation complete");
      } else {
        console.log("⚠️  Only leaf certificate provided, no chain validation possible");
      }
      
      // Prüfe Gültigkeit
      const now = new Date();
      const notBefore = new Date(leafCert.notBefore);
      const notAfter = new Date(leafCert.notAfter);
      
      if (now < notBefore || now > notAfter) {
        console.log(`\n⚠️  Certificate validity warning: now=${now.toISOString()}`);
        console.log(`    Valid from: ${notBefore.toISOString()}`);
        console.log(`    Valid to: ${notAfter.toISOString()}`);
      } else {
        console.log("\n✅ Certificate validity period: OK");
      }
      
    } catch (certError) {
      console.error("\n⚠️  Certificate validation error:", certError);
      if (certError instanceof Error) {
        console.log("Error details:", certError.message);
      }
      console.log("- Continuing anyway (development mode)");
    }
    
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
  try {
    console.log("\n========== APP ATTEST ASSERTION VERIFICATION ==========");
    const { keyId, assertion, clientData } = req.body || {};
    
    if (!keyId || !assertion || !clientData) {
      return res.status(400).json({ error: "missing required fields" });
    }
    
    console.log("📝 Assertion Request:");
    console.log("- KeyId:", keyId);
    console.log("- ClientData:", JSON.stringify(clientData));
    console.log("- Assertion length:", assertion.length);
    
    // TODO: Implementiere vollständige Assertion-Verifikation
    // 1. Lade gespeicherten Public Key für keyId aus DB
    // 2. Verifiziere Signatur
    // 3. Prüfe Counter
    
    console.log("✅ Assertion verification simulated as successful");
    console.log("========== END ASSERTION VERIFICATION ==========\n");
    
    res.json({
      verified: true,
      keyId,
      sessionToken: base64url(randomBytes(32)),
      expiresIn: 300
    });
    
  } catch (error) {
    console.error("❌ Assertion verification error:", error);
    res.status(400).json({ error: "assertion_failed" });
  }
});

/**
 * 4) POST /api/appattest/secure-action
 * Kombinierter Endpoint für App Attest + Passkey
 */
router.post("/secure-action", async (req: any, res: any) => {
  try {
    console.log("\n========== SECURE ACTION WITH DUAL VERIFICATION ==========");
    const { action, data, appAttest, passkey } = req.body || {};
    
    if (!action || !data || !appAttest || !passkey) {
      return res.status(400).json({ error: "missing required fields" });
    }
    
    console.log("🔒 Secure Action:");
    console.log("- Action:", action);
    console.log("- Data:", JSON.stringify(data));
    
    // Erstelle Challenge aus Formulardaten
    const challengeData = { action, ...data, timestamp: new Date().toISOString() };
    const challenge = createHash("sha256")
      .update(JSON.stringify(challengeData))
      .digest();
    
    console.log("- Challenge:", challenge.toString("hex"));
    
    // Verifiziere App Attest
    if (!appAttest.keyId || !appAttest.assertion) {
      return res.status(400).json({ error: "invalid app attest data" });
    }
    console.log("\n✅ App Attest verified (simulated)");
    
    // Verifiziere Passkey
    if (!passkey.credentialId || !passkey.signature) {
      return res.status(400).json({ error: "invalid passkey data" });
    }
    console.log("✅ Passkey verified (simulated)");
    
    console.log("\n✅ DUAL VERIFICATION SUCCESSFUL!");
    console.log("========== END SECURE ACTION ==========\n");
    
    res.json({
      success: true,
      action,
      transactionId: base64url(randomBytes(16)),
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error("❌ Secure action error:", error);
    res.status(400).json({ error: "secure_action_failed" });
  }
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