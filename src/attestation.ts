import cbor from "cbor";

/**
 * Adjusts the attestationObject for a "none" attestation.
 * If the original fmt is "apple-appattest", set fmt to "none" and replace attStmt with an empty object.
 */
export function adjustAttestationObject(attestationObject: ArrayBuffer | Buffer): ArrayBuffer {
  // Decodiere das attestationObject mittels CBOR
  const buffer = Buffer.isBuffer(attestationObject)
    ? attestationObject
    : Buffer.from(attestationObject);
  const decoded = cbor.decodeAllSync(buffer)[0];

  console.log("Original attestation fmt:", decoded.fmt);

  // Wenn fmt "apple-appattest" ist, anpassen:
  if (decoded.fmt === "apple-appattest") {
    decoded.fmt = "none";
    // Stelle sicher, dass attStmt vorhanden ist – hier ein leeres Objekt
    decoded.attStmt = {};
  }

  // Encodiere das angepasste Objekt wieder in CBOR
  const adjustedBuffer = cbor.encode(decoded);
  // Gib einen ArrayBuffer zurück
  return Uint8Array.from(adjustedBuffer).buffer;
}
