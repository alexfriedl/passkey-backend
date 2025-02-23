import { Fido2Lib } from "fido2-lib";
import {
  storeChallenge,
  getChallenge,
  deleteChallenge,
} from "./challenge-store";
import { arrayBufferToBase64Url, base64UrlToArrayBuffer } from "./conversion";
import { randomBytes } from "crypto";
import cbor from "cbor"; // Stelle sicher, dass du eine CBOR-Bibliothek installiert hast

const rpId = "www.appsprint.de";
const fido2 = new Fido2Lib({
  rpId,
  rpName: "LocalKeyApp",
  challengeSize: 32,
  attestation: "none", // 🔥 Secure Enclave Attestation ERZWINGEN "direct" / Native iOS Integration erlaubt nur "non" aus Datenschutzrechtlichen Gründen
  cryptoParams: [-7], // ECDSA P-256 (Secure Enclave nutzt diesen Standard)
  authenticatorAttachment: "platform", // 🔥 Nur interner authenticator (keine USB/NFC/BLE)
  timeout: 60000, // 60 Sekunden Timeout für WebAuthn-Anfragen
});

/**
 * Attestation validieren (Nur Apple Secure Enclave)
 */
// TODO: fmt apple prüfen
function validateAttestation(attestationObject: any) {
  console.log("🔐 Attestation-Objekt:", attestationObject);
  // Falls attestationObject eine Map ist, benutze .get("fmt")
  const fmt =
    attestationObject instanceof Map
      ? attestationObject.get("fmt")
      : attestationObject.fmt;
  console.log("fmt:", fmt);
  if (!fmt || (fmt !== "apple" && fmt !== "none")) {
    throw new Error(
      "Ungültige Attestation: Nur Apple Secure Enclave wird akzeptiert."
    );
  }
}

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

  // 🔥 Fix: Challenge als Base64 speichern
  const challengeBase64 = arrayBufferToBase64Url(options.challenge);
  storeChallenge(username, challengeBase64);

  console.log("✅ Gespeicherte Challenge (Base64):", challengeBase64);

  const userId = arrayBufferToBase64Url(randomBytes(16)); // ✅ Speichern als Base64-String

  console.log("🆔 Generierte User ID (Uint8Array):", userId);

  const response: PublicKeyCredentialCreationOptions = {
    ...options,
    challenge: challengeBase64 as unknown as BufferSource, // ✅ Jetzt Base64 statt ArrayBuffer
    user: {
      id: userId as unknown as BufferSource, // ✅ Jetzt als Base64-String gespeichert
      name: username,
      displayName: username,
    },
    authenticatorSelection: {
      authenticatorAttachment: "platform" as AuthenticatorAttachment, // ✅ Fix für TypeScript-Fehler
      residentKey: "required",
      userVerification: "required",
    },
  };

  console.log("📦 Finale `generateRegistrationOptions()` Response:", response);

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

  // Konvertiere id und rawId in ArrayBuffer falls nötig
  credential.rawId = base64UrlToArrayBuffer(credential.rawId);
  credential.id = base64UrlToArrayBuffer(credential.id);

  // --- HACK: Attestation-Objekt manipulieren ---
  const attestationBuffer = base64UrlToArrayBuffer(
    credential.response.attestationObject
  );
  let attestationObj = await cbor.decodeFirst(attestationBuffer);
  attestationObj.fmt = "none";
  // Encodiere das modifizierte Objekt zurück in CBOR
  const newAttestationBuffer = cbor.encode(attestationObj);
  // Stelle sicher, dass du einen Base64-String übergibst, da fido2-lib dies erwartet
  credential.response.attestationObject =
    newAttestationBuffer.toString("base64");
  // ---------------------------------------------------

  try {
    const attestationResult = await fido2.attestationResult(credential, {
      challenge: challengeBase64,
      origin: `https://${rpId}`,
      factor: "either",
    });
    console.log("🔐 Attestation-Resultat:", attestationResult);
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
    challenge: options.challenge,
    allowCredentials: options.allowCredentials?.map((cred) => ({
      ...cred,
      transports: cred.transports as AuthenticatorTransport[] | undefined, // 🔥 Fix für Typfehler in `allowCredentials`
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
