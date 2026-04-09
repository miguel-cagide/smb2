import crypto from "crypto";
import HeaderFlag from "./HeaderFlag";

/**
 * Byte offset of the Signature field within the SMB2 header.
 * The SMB2 header is 64 bytes: signature occupies bytes 48–63.
 */
const SIGNATURE_OFFSET = 48;
const SIGNATURE_LENGTH = 16;

/**
 * Byte offset of the Flags field within the SMB2 header (4 bytes, little-endian).
 */
const FLAGS_OFFSET = 16;

/**
 * Signs an SMB2 message buffer **without** the 4-byte NetBIOS transport prefix.
 *
 * Per MS-SMB2 section 3.1.4.1 (for SMB 2.0.2 / 2.1):
 *  1. Set the Signed flag (bit 3) in the Flags field.
 *  2. Zero the 16-byte Signature field.
 *  3. Compute HMAC-SHA-256(SigningKey, entireMessage).
 *  4. Copy the first 16 bytes of the HMAC into the Signature field.
 *
 * @param sessionKey  The 16-byte session signing key.
 * @param message     The SMB2 message buffer (header + body, no NetBIOS prefix).
 * @returns           The signed message buffer (modified in place and returned).
 */
export function signMessage(sessionKey: Buffer, message: Buffer): Buffer {
  // Set the Signed flag in the Flags field (4-byte LE at FLAGS_OFFSET)
  const flags = message.readUInt32LE(FLAGS_OFFSET);
  message.writeUInt32LE(flags | HeaderFlag.Signed, FLAGS_OFFSET);

  // Zero the Signature field
  message.fill(0, SIGNATURE_OFFSET, SIGNATURE_OFFSET + SIGNATURE_LENGTH);

  // Compute HMAC-SHA-256 over the entire message
  const hmac = crypto.createHmac("sha256", sessionKey);
  hmac.update(message);
  const signature = hmac.digest().slice(0, SIGNATURE_LENGTH);

  // Write signature into the header
  signature.copy(message, SIGNATURE_OFFSET);

  return message;
}

/**
 * Verifies the signature of an incoming SMB2 message buffer
 * **without** the 4-byte NetBIOS transport prefix.
 *
 * @param sessionKey  The 16-byte session signing key.
 * @param message     The SMB2 message buffer (header + body, no NetBIOS prefix).
 * @returns           `true` if the signature is valid.
 */
export function verifyMessage(sessionKey: Buffer, message: Buffer): boolean {
  // Save the received signature
  const receivedSignature = Buffer.alloc(SIGNATURE_LENGTH);
  message.copy(receivedSignature, 0, SIGNATURE_OFFSET, SIGNATURE_OFFSET + SIGNATURE_LENGTH);

  // Zero the Signature field for computation
  message.fill(0, SIGNATURE_OFFSET, SIGNATURE_OFFSET + SIGNATURE_LENGTH);

  // Compute expected HMAC-SHA-256
  const hmac = crypto.createHmac("sha256", sessionKey);
  hmac.update(message);
  const expectedSignature = hmac.digest().slice(0, SIGNATURE_LENGTH);

  // Restore the original signature
  receivedSignature.copy(message, SIGNATURE_OFFSET);

  // Constant-time comparison to prevent timing attacks
  return crypto.timingSafeEqual(receivedSignature, expectedSignature);
}

/**
 * Checks whether the Signed flag is set in a message's SMB2 header.
 *
 * @param message  The SMB2 message buffer (no NetBIOS prefix).
 */
export function isMessageSigned(message: Buffer): boolean {
  const flags = message.readUInt32LE(FLAGS_OFFSET);
  return (flags & HeaderFlag.Signed) !== 0;
}
