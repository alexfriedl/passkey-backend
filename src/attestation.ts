import cbor from "cbor";

/**
 * Adjusts the attestationObject for a "none" attestation.
 * If the original fmt is "apple-appattest", set fmt to "none" and remove attStmt.
 */
export function adjustAttestationObject(
  attestationObject: ArrayBuffer | Buffer
): ArrayBuffer {
  // Stelle sicher, dass wir mit einem Buffer arbeiten
  const buffer = Buffer.isBuffer(attestationObject)
    ? attestationObject
    : Buffer.from(attestationObject);
  // CBOR dekodieren
  const decoded = cbor.decodeAllSync(buffer)[0];

  console.log("[attestation.ts] Original fmt:", decoded.fmt);

  // Wenn fmt "apple-appattest" ist, anpassen:
  if (decoded.fmt === "apple-appattest") {
    decoded.fmt = "none";
    // Entferne attStmt (oder setze es auf ein leeres Objekt)
    decoded.attStmt = {};
  }

  // CBOR neu codieren
  const adjustedBuffer = cbor.encode(decoded);
  // Gib einen ArrayBuffer zurück
  return Buffer.from(adjustedBuffer).buffer;
}
