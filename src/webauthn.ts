import { Fido2Lib } from "fido2-lib";
import {
  storeChallenge,
  getChallenge,
  deleteChallenge,
} from "./challenge-store";
import { arrayBufferToBase64Url, base64UrlToArrayBuffer } from "./conversion";
import { randomBytes } from "crypto";
import { adjustAttestationObject } from "./attestation";

const rpId = "www.appsprint.de";
const fido2 = new Fido2Lib({
  rpId,
  rpName: "LocalKeyApp",
  challengeSize: 32,
  attestation: "none", // Wir verwenden den "none"-Flow
  cryptoParams: [-7], // ECDSA P-256
  authenticatorAttachment: "platform", // Nur interner Authenticator
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
  console.log("[verifyRegistration] Geladene Challenge:", challengeBase64);
  console.log(
    "[verifyRegistration] Credential (raw):",
    JSON.stringify(credential, null, 2)
  );
  deleteChallenge(username);

  // Konvertiere id und rawId in ArrayBuffer
  credential.rawId = base64UrlToArrayBuffer(credential.rawId);
  credential.id = base64UrlToArrayBuffer(credential.id);

  // Attestation-Objekt anpassen (für den "none"-Flow)
  if (credential.response && credential.response.attestationObject) {
    const originalBuffer = Buffer.from(
      credential.response.attestationObject,
      "base64"
    );
    const newAttestationBuffer = adjustAttestationObject(originalBuffer);
    credential.response.attestationObject = newAttestationBuffer;
  }

  // clientDataJSON verarbeiten: Stelle sicher, dass es ein ArrayBuffer ist
  if (credential.response && credential.response.clientDataJSON) {
    let clientDataStr: string;
    if (typeof credential.response.clientDataJSON === "string") {
      clientDataStr = Buffer.from(
        credential.response.clientDataJSON,
        "base64"
      ).toString("utf8");
    } else {
      clientDataStr = Buffer.from(credential.response.clientDataJSON).toString(
        "utf8"
      );
    }
    // Optional: Anpassungen am clientData vornehmen (z. B. challenge-Anpassung)
    const clientData = JSON.parse(clientDataStr);
    const newClientDataStr = JSON.stringify(clientData);
    // Wichtig: Stelle sicher, dass clientDataJSON ein ArrayBuffer ist
    credential.response.clientDataJSON = Buffer.from(
      newClientDataStr,
      "utf8"
    ).buffer;
  }

  try {
    const attestationResult = await fido2.attestationResult(credential, {
      challenge: challengeBase64,
      origin: `https://${rpId}`,
      factor: "either",
    });
    console.log(
      "[verifyRegistration] Attestation-Resultat:",
      attestationResult
    );
    return attestationResult;
  } catch (error) {
    console.error(
      "[verifyRegistration] Fehler bei fido2.attestationResult():",
      error
    );
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
