import { Fido2Lib } from "fido2-lib";
import {
  storeChallenge,
  getChallenge,
  deleteChallenge,
} from "./challenge-store";
import { arrayBufferToBase64Url, base64UrlToArrayBuffer } from "./conversion";
import { randomBytes } from "crypto";
import cbor from "cbor";
import { adjustAttestationObject } from "./attestation";

const rpId = "www.appsprint.de";
const fido2 = new Fido2Lib({
  rpId,
  rpName: "LocalKeyApp",
  challengeSize: 32,
  attestation: "none", // Wir verwenden "none" (d.h. keine vollwertige Attestationsprüfung)
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
  const options = await fido2.attestationOptions();

  console.log(
    "🔍 Originale Challenge von fido2.attestationOptions():",
    options.challenge
  );

  // Challenge als Base64url speichern
  const challengeBase64 = arrayBufferToBase64Url(options.challenge);
  storeChallenge(username, challengeBase64);
  console.log("✅ Gespeicherte Challenge (Base64url):", challengeBase64);

  const userId = arrayBufferToBase64Url(randomBytes(16));
  console.log("🆔 Generierte User ID (Base64url):", userId);

  const response: PublicKeyCredentialCreationOptions = {
    ...options,
    challenge: challengeBase64 as unknown as BufferSource,
    user: {
      id: userId as unknown as BufferSource,
      name: username,
      displayName: username,
    },
    authenticatorSelection: {
      authenticatorAttachment: "platform" as AuthenticatorAttachment,
      residentKey: "required",
      userVerification: "required",
    },
  };

  console.log("📦 Finale generateRegistrationOptions Response:", response);
  return response;
}

/**
 * Registrierung: FIDO2-Passkey-Registrierung verifizieren
 */
export async function verifyRegistration(credential: any, username: string) {
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

  // Konvertiere id und rawId in ArrayBuffer (falls nötig)
  credential.rawId = base64UrlToArrayBuffer(credential.rawId);
  credential.id = base64UrlToArrayBuffer(credential.id);

  // Passe das attestationObject an (für den "none"-Flow)
  if (credential.response && credential.response.attestationObject) {
    // Konvertiere den Base64-String in einen Buffer
    const originalBuffer = Buffer.from(
      credential.response.attestationObject,
      "base64"
    );
    // Dekodiere das CBOR-Objekt
    const attestationObj = cbor.decodeAllSync(originalBuffer)[0];
    console.log("Original attestation object:", attestationObj);
    // Falls das Format "apple-appattest" ist, setze es auf "none" und entferne attStmt
    if (attestationObj.fmt === "apple-appattest") {
      attestationObj.fmt = "none";
      delete attestationObj.attStmt;
    }
    // Encodiere das Objekt wieder per CBOR
    const newAttestationBuffer = cbor.encode(attestationObj);
    // Konvertiere in einen ArrayBuffer (nicht den Node-Buffer verwenden)
    credential.response.attestationObject = newAttestationBuffer.buffer.slice(
      newAttestationBuffer.byteOffset,
      newAttestationBuffer.byteOffset + newAttestationBuffer.byteLength
    );
  }

  // Stelle sicher, dass clientDataJSON als ArrayBuffer vorliegt
  if (credential.response && credential.response.clientDataJSON) {
    let clientDataStr: string;
    if (typeof credential.response.clientDataJSON === "string") {
      // Dekodiere den Base64-String in einen UTF-8-String
      clientDataStr = Buffer.from(
        credential.response.clientDataJSON,
        "base64"
      ).toString("utf8");
    } else {
      clientDataStr = Buffer.from(credential.response.clientDataJSON).toString(
        "utf8"
      );
    }
    // Parse das JSON
    const clientData = JSON.parse(clientDataStr);
    // Überschreibe den Challenge-Wert mit dem gespeicherten Wert (Base64url)
    clientData.challenge = challengeBase64;
    // Serialisiere das Objekt
    const newClientDataStr = JSON.stringify(clientData);
    // Erzeuge einen UTF-8-Buffer und konvertiere diesen in einen ArrayBuffer
    const newClientDataBuffer = Buffer.from(newClientDataStr, "utf8");
    credential.response.clientDataJSON = newClientDataBuffer.buffer.slice(
      newClientDataBuffer.byteOffset,
      newClientDataBuffer.byteOffset + newClientDataBuffer.byteLength
    );
  }

  try {
    const attestationResult = await fido2.attestationResult(credential, {
      challenge: challengeBase64,
      origin: `https://${rpId}`,
      factor: "either",
    });
    console.log("🔐 Attestation-Resultat:", attestationResult);
    console.log(
      "🔐 Attestation-Objekt (raw):",
      JSON.stringify(attestationResult.authnrData, null, 2)
    );
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
    challenge: challengeBase64 as unknown as BufferSource,
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
