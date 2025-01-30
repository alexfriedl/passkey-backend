import { AttestationResult } from "fido2-lib";

/**
 * Nutzerprofil für WebAuthn
 */
export interface WebAuthnUser {
  id: string; // Benutzer-ID
  name: string; // Benutzername
  displayName: string; // Anzeigename
  publicKey?: string; // Öffentlicher Schlüssel für die Authentifizierung
  challenge?: string; // WebAuthn-Challenge
}

/**
 * WebAuthn-Anmeldeinformationen
 */
export interface WebAuthnCredential {
  id: ArrayBuffer; // Muss ArrayBuffer sein für fido2-lib
  rawId: ArrayBuffer;
  response: {
    clientDataJSON: ArrayBuffer;
    attestationObject?: ArrayBuffer;
    authenticatorData?: ArrayBuffer;
    signature?: ArrayBuffer;
    userHandle?: ArrayBuffer;
  };
  type: string;
}

/**
 * Speichert das Ergebnis einer Attestation (Registrierung)
 */
export interface WebAuthnAttestation {
  credential: AttestationResult;
}
