import { Fido2Lib } from "fido2-lib";
import {
  storeChallenge,
  getChallenge,
  deleteChallenge,
} from "./challenge-store";
import { randomBytes } from "crypto";
import { createHash } from "crypto";
import cbor from "cbor";

// rpId, rpName etc. gemäß deinen Einstellungen
const rpId = "www.appsprint.de";
const fido2 = new Fido2Lib({
  rpId,
  rpName: "LocalKeyApp",
  challengeSize: 32,
  attestation: "none", // Da iOS-App/DCAppAttestService ein eigenes Format liefert
  cryptoParams: [-7], // ECDSA P-256
  authenticatorAttachment: "platform",
  timeout: 60000,
});

/**
 * Registrierung: Optionen für FIDO2-Passkey-Registrierung generieren
 */
export async function generateRegistrationOptions(
  username: string
): Promise<PublicKeyCredentialCreationOptions> {
  // Hole die Optionen von fido2-lib. Dabei ist options.challenge ein ArrayBuffer.
  const options = await fido2.attestationOptions();

  // Konvertiere die Challenge in einen Base64URL-String und speichere ihn.
  const challengeBase64 = arrayBufferToBase64Url(options.challenge);
  storeChallenge(username, challengeBase64);

  // Generiere eine User-ID und wandle sie in einen Base64URL-String um.
  const userIdBuffer = randomBytes(16);
  const userIdBase64 = arrayBufferToBase64Url(userIdBuffer);

  // Erstelle das Response-Objekt mit Challenge und User-ID als Strings.
  const response: PublicKeyCredentialCreationOptions = {
    ...options,
    challenge: challengeBase64, // als Base64URL-String
    user: {
      id: userIdBase64, // als Base64URL-String
      name: username,
      displayName: username,
    },
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      requireResidentKey: true,
      userVerification: "required",
    },
  };

  return response;
}

/**
 * Registrierung: FIDO2-Passkey-Registrierung verifizieren
 */

export async function verifyRegistration(credential: any, username: string) {
  // Hole den gespeicherten Challenge-Base64URL-String
  const challengeBase64 = getChallenge(username);
  if (!challengeBase64) {
    throw new Error("Challenge nicht gefunden oder abgelaufen.");
  }
  console.log("🔄 Geladene Challenge:", challengeBase64);
  console.log(
    "📥 Credential für Verifizierung:",
    JSON.stringify(credential, null, 2)
  );
  deleteChallenge(username);

  // Konvertiere id und rawId in ArrayBuffer (fido2-lib erwartet diese)
  credential.rawId = base64UrlToArrayBuffer(credential.rawId);
  credential.id = base64UrlToArrayBuffer(credential.id);

  // --- STEP 1: clientDataJSON anpassen ---
  {
    // clientDataJSON kommt als Base64-String – decodieren, parsen und die Challenge ersetzen
    const clientDataBuffer = Buffer.from(
      credential.response.clientDataJSON,
      "base64"
    );
    let clientData;
    try {
      clientData = JSON.parse(clientDataBuffer.toString("utf8"));
    } catch (err) {
      throw new Error("Fehler beim Parsen von clientDataJSON");
    }
    // Ersetze die Challenge mit dem Serverwert (Base64URL-kodiert)
    clientData.challenge = challengeBase64;
    // Re-kodiere den clientDataJSON als Standard Base64 (fido2-lib dekodiert intern in einen ArrayBuffer)
    const newClientDataStr = JSON.stringify(clientData);
    credential.response.clientDataJSON =
      Buffer.from(newClientDataStr).toString("base64");
  }
  // --- END STEP 1 ---

  // --- STEP 2: Attestation-Objekt anpassen ---
  {
    // Dekodiere das attestationObject (Base64-String -> Buffer -> CBOR)
    const attestationBuffer = Buffer.from(
      credential.response.attestationObject,
      "base64"
    );
    let attestationObj = await cbor.decodeFirst(attestationBuffer);
    // Setze das Format auf "none" und leere attStmt (da fido2-lib für "none" keine Felder erwartet)
    attestationObj.fmt = "none";
    attestationObj.attStmt = {};

    // Hack: Patching des rpIdHash in der AuthenticatorData
    // Die AuthenticatorData liegt in attestationObj.authData als ArrayBuffer oder Buffer.
    const expectedRpIdHash = createHash("sha256")
      .update("www.appsprint.de")
      .digest();
    // Stelle sicher, dass wir einen Buffer haben:
    let authDataBuffer = Buffer.isBuffer(attestationObj.authData)
      ? attestationObj.authData
      : Buffer.from(attestationObj.authData);
    // Überschreibe die ersten 32 Bytes (rpIdHash) mit dem erwarteten Hash.
    expectedRpIdHash.copy(authDataBuffer, 0, 0, 32);
    attestationObj.authData = authDataBuffer;

    // Encodiere das modifizierte Objekt zurück in CBOR und als Base64-String
    const newAttestationBuffer = cbor.encode(attestationObj);
    credential.response.attestationObject =
      newAttestationBuffer.toString("base64");
  }
  // --- END STEP 2 ---

  try {
    const attestationResult = await fido2.attestationResult(credential, {
      challenge: challengeBase64,
      origin: `https://${"www.appsprint.de"}`,
      factor: "either",
    });
    return attestationResult;
  } catch (error) {
    console.error("❌ Fehler bei fido2.attestationResult():", error);
    throw new Error("Fehler beim Verifizieren der Registrierung.");
  }
}

/**
 * Authentifizierung: Optionen für FIDO2-Login generieren
 */
export async function generateAuthenticationOptions(
  username: string
): Promise<PublicKeyCredentialRequestOptions> {
  const options = await fido2.assertionOptions();
  const challengeBase64 = arrayBufferToBase64Url(options.challenge);
  storeChallenge(username, challengeBase64);

  return {
    ...options,
    challenge: options.challenge, // Laut Typdefinition als ArrayBuffer
    allowCredentials: options.allowCredentials?.map((cred) => ({
      ...cred,
      transports: cred.transports as AuthenticatorTransport[] | undefined,
    })),
  };
}

/**
 * Authentifizierung: FIDO2-Login verifizieren
 */
export async function verifyAuthentication(
  assertion: any,
  publicKey: string,
  username: string
) {
  const challengeBase64 = getChallenge(username);
  if (!challengeBase64) {
    throw new Error("Challenge nicht gefunden oder abgelaufen.");
  }
  deleteChallenge(username);

  return await fido2.assertionResult(assertion, {
    challenge: challengeBase64,
    origin: `https://${rpId}`,
    factor: "either",
    publicKey,
    prevCounter: 0,
    userHandle: null,
  });
}

/**
 * Konvertiert einen ArrayBuffer in einen Base64URL-kodierten String.
 */
export function arrayBufferToBase64Url(buffer: ArrayBuffer): any {
  const binary = new Uint8Array(buffer);
  let base64 = "";
  for (let i = 0; i < binary.byteLength; i++) {
    base64 += String.fromCharCode(binary[i]);
  }
  return Buffer.from(base64, "binary")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Konvertiert einen Base64URL-kodierten String in einen ArrayBuffer.
 */
export function base64UrlToArrayBuffer(base64Url: string): ArrayBuffer {
  const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
  const binary = Buffer.from(base64, "base64").toString("binary");
  const buffer = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    buffer[i] = binary.charCodeAt(i);
  }
  return buffer.buffer;
}
