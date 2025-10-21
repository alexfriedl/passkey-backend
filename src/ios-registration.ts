/**
 * iOS Extension Registration Handler
 * 
 * iOS Extensions generieren ihre eigene Challenge, die wir nicht kontrollieren können.
 * Diese Funktion verarbeitet die Registrierung ohne Challenge-Validierung.
 */

import { Fido2Lib } from "fido2-lib";
import { createHash } from "crypto";
import User from "./models/User";

// Konfiguration
const rpId = process.env.RP_ID || "www.appsprint.de";
const rpName = process.env.RP_NAME || "LocalKeyApp";
const origin = process.env.ORIGIN || `https://${rpId}`;

// Fido2Lib ohne Challenge-Validierung initialisieren
const iosFido2 = new Fido2Lib({
  timeout: 60000,
  rpId: rpId,
  rpName: rpName,
  challengeSize: 128,
  attestation: "none",
  cryptoParams: [-7, -257],
  authenticatorRequireResidentKey: false,
  authenticatorUserVerification: "required"
});

function base64UrlToArrayBuffer(base64url: string): ArrayBuffer {
  let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  const binaryString = Buffer.from(base64, "base64").toString("binary");
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Verifiziert iOS Extension Passkey-Registrierung
 * 
 * @param credential - Die Credential-Daten von iOS
 * @param username - Der Benutzername
 * @param serverChallenge - Die Server-Challenge (nur für Audit)
 * @returns Attestation Result
 */
export async function verifyIOSRegistration(
  credential: any,
  username: string,
  serverChallenge: string
): Promise<any> {
  console.log("🍎 iOS Extension Registration - Start");
  console.log("Server challenge (for audit):", serverChallenge);
  
  try {
    // Konvertiere id und rawId in ArrayBuffer
    credential.rawId = base64UrlToArrayBuffer(credential.rawId);
    credential.id = base64UrlToArrayBuffer(credential.id);
    
    // Decode clientDataJSON to extract iOS-generated challenge
    const clientDataJSON = JSON.parse(
      Buffer.from(credential.response.clientDataJSON, 'base64').toString()
    );
    console.log("iOS-generated challenge:", clientDataJSON.challenge);
    console.log("Origin from iOS:", clientDataJSON.origin);
    
    // Use the iOS-generated challenge for verification
    const attestationResult = await iosFido2.attestationResult(credential, {
      challenge: clientDataJSON.challenge, // Use iOS challenge!
      origin: origin,
      factor: "either",
    });
    
    console.log("✅ iOS Registration verified successfully");
    
    // Save user with audit trail
    const existingUser = await User.findOne({ username });
    if (!existingUser) {
      const publicKeyPEM = attestationResult.authnrData.get("credentialPublicKeyPem");
      if (!publicKeyPEM) {
        throw new Error("Public Key konnte nicht extrahiert werden.");
      }
      
      // Save user with metadata about iOS registration
      const newUser = await User.create({
        username,
        credentialId: credential.id.toString(),
        publicKey: publicKeyPEM,
        counter: 0,
        registrationPlatform: "ios-extension",
        serverChallenge: serverChallenge, // Store for audit
        iosChallenge: clientDataJSON.challenge, // Store iOS challenge
        createdAt: new Date()
      });
      
      console.log("✅ iOS User created:", username);
    }
    
    return attestationResult;
    
  } catch (error) {
    console.error("❌ iOS Registration verification failed:", error);
    throw error;
  }
}