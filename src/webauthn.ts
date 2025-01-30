import { Fido2Lib, AttestationResult, AssertionResult } from "fido2-lib";
import config from "../config/config.json";

const fido2 = new Fido2Lib({
  rpId: config.rpId,
  rpName: config.rpName,
  challengeSize: config.challengeSize,
  attestation: config.attestation as "none" | "direct" | "indirect",
  cryptoParams: config.cryptoParams,
});

/**
 * Generate WebAuthn Registration Challenge
 */
export function generateRegistrationOptions(username: string) {
  return fido2.attestationOptions();
}

/**
 * Verify WebAuthn Registration
 */
export async function verifyRegistration(
  credential: AttestationResult,
  userChallenge: string
) {
  try {
    const expectedChallenge = {
      challenge: Buffer.from(userChallenge, "base64").toString("utf8"),
      origin: `https://${config.rpId}`,
      factor: "either" as "first" | "second" | "either",
    };

    const result = await fido2.attestationResult(credential, expectedChallenge);
    return { success: true, credential: result.authnrData };
  } catch (error) {
    return { success: false, error };
  }
}

/**
 * Generate WebAuthn Authentication Challenge
 */
export function generateAuthenticationOptions(publicKey: string) {
  return fido2.assertionOptions();
}

/**
 * Verify WebAuthn Authentication
 */
export async function verifyAuthentication(
  assertion: AssertionResult,
  publicKey: string,
  userChallenge: string
) {
  try {
    const expectedChallenge = {
      challenge: Buffer.from(userChallenge, "base64").toString("utf8"),
      origin: `https://${config.rpId}`,
      factor: "either" as "first" | "second" | "either",
      publicKey,
      prevCounter: 0, // Replace with actual previous counter if available
      userHandle: null, // Replace with actual user handle if available
    };

    const result = await fido2.assertionResult(assertion, expectedChallenge);
    return { success: result.authnrData !== undefined };
  } catch (error) {
    return { success: false, error };
  }
}
