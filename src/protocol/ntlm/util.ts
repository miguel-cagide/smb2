import crypto from "crypto";
import desjs from "des.js";
import jsmd4 from "js-md4";
import NegotiateFlag from "./NegotiateFlag";

const ntlmV1NegotiateFlags = NegotiateFlag.UnicodeEncoding | NegotiateFlag.NTLMSessionSecurity | NegotiateFlag.AlwaysSign;

// TargetNameSupplied = NTLMSSP_REQUEST_TARGET and NTLMSessionSecurity = NTLMSSP_NEGOTIATE_NTLM in MS-NLMP terms.
export const ntlmV2NegotiateFlags =
  NegotiateFlag.UnicodeEncoding |
  NegotiateFlag.TargetNameSupplied |
  NegotiateFlag.Sign |
  NegotiateFlag.NTLMSessionSecurity |
  NegotiateFlag.AlwaysSign |
  NegotiateFlag.ExtendedSessionSecurity |
  NegotiateFlag.Use128BitEncryption |
  NegotiateFlag.Use56BitEncryption;

export const encodeNegotiationMessage = (hostname: string, domain: string, negotiateFlags: number = ntlmV1NegotiateFlags) => {
  hostname = hostname.toUpperCase();
  domain = domain.toUpperCase();

  const hostnameLength = Buffer.byteLength(hostname, "ascii");
  const domainLength = Buffer.byteLength(domain, "ascii");

  let offset = 0;
  const buffer = Buffer.alloc(32 + hostnameLength + domainLength);

  buffer.write("NTLMSSP", offset, 7, "ascii");
  offset += 7;
  buffer.writeUInt8(0, offset);
  offset += 1;

  buffer.writeUInt32LE(1, offset);
  offset += 4;

  buffer.writeUInt32LE(negotiateFlags >>> 0, offset);
  offset += 4;

  buffer.writeUInt16LE(domainLength, offset);
  offset += 2;
  buffer.writeUInt16LE(domainLength, offset);
  offset += 2;

  const domainOffset = 0x20 + hostnameLength;
  buffer.writeUInt32LE(domainOffset, offset);
  offset += 4;

  buffer.writeUInt16LE(hostnameLength, offset);
  offset += 2;
  buffer.writeUInt16LE(hostnameLength, offset);
  offset += 2;

  buffer.writeUInt32LE(0x20, offset);
  offset += 4;

  buffer.write(hostname, 0x20, hostnameLength, "ascii");
  buffer.write(domain, domainOffset, domainLength, "ascii");

  return buffer;
};

export const decodeNegotiationMessage = (buffer: Buffer) => {
  let offset = 0;

  const protocol = buffer.slice(0, 7).toString("ascii");
  if (
    protocol !== "NTLMSSP" ||
    buffer.readInt8(7) !== 0x00
  ) throw new Error("ntlmssp_header_not_found");
  offset += 8;

  const type = buffer.readUInt32LE(offset);
  if (type !== 0x01) throw new Error("ntlmssp_type_is_not_one");
  offset += 4;

  const negotiateFlags = buffer.readUInt32LE(offset);
  offset += 4;

  const domainLength = buffer.readUInt16LE(offset);
  offset += 2;
  const domainMaxLength = buffer.readUInt16LE(offset);
  offset += 2;
  const domainOffset = buffer.readUInt32LE(offset);
  offset += 4;

  const hostnameLength = buffer.readUInt16LE(offset);
  offset += 2;
  const hostnameMaxLength = buffer.readUInt16LE(offset);
  offset += 2;
  const hostnameOffset = buffer.readUInt32LE(offset);
  offset += 4;

  const domain = buffer.slice(domainOffset, domainOffset + domainLength).toString("ascii");
  const hostname = buffer.slice(hostnameOffset, hostnameOffset + hostnameLength).toString("ascii");

  return {
    negotiateFlags,
    domain,
    hostname
  };
};

export const encodeChallengeMessage = (negotiateFlags: number) => {
  let offset = 0;
  const buffer = Buffer.alloc(64);

  buffer.write("NTLMSSP", offset, 7, "ascii");
  offset += 7;
  buffer.writeUInt8(0, offset);
  offset += 1;

  buffer.writeUInt32LE(2, offset);
  offset += 4;

  buffer.writeUInt16LE(0, offset);
  offset += 2;

  buffer.writeUInt16LE(0, offset);
  offset += 2;

  buffer.writeUInt32LE(0, offset);
  offset += 4;

  buffer.writeUInt32LE(negotiateFlags, offset);
  offset += 4;

  generateServerChallenge().copy(buffer, offset);
  offset += 8;

  buffer.fill(0, offset, offset + 8);
  offset += 8;

  return buffer;
};

export interface ChallengeMessage {
  negotiateFlags: number;
  serverChallenge: Buffer;
  targetName: Buffer;
  targetInfo: Buffer;
}

export const parseChallengeMessage = (buffer: Buffer): ChallengeMessage => {
  const protocol = buffer.slice(0, 7).toString("ascii");
  if (
    protocol !== "NTLMSSP" ||
    buffer.readInt8(7) !== 0x00
  ) throw new Error("ntlmssp_header_not_found");

  const type = buffer.readUInt32LE(8);
  if (type !== 0x02) throw new Error("ntlmssp_type_is_not_two");

  const readField = (fieldOffset: number) => {
    if (buffer.length < fieldOffset + 8) return Buffer.alloc(0);
    const length = buffer.readUInt16LE(fieldOffset);
    const offset = buffer.readUInt32LE(fieldOffset + 4);
    return Buffer.from(buffer.slice(offset, offset + length));
  };

  return {
    targetName: readField(12),
    negotiateFlags: buffer.readUInt32LE(20),
    serverChallenge: Buffer.from(buffer.slice(24, 32)),
    targetInfo: readField(40)
  };
};

export const decodeChallengeMessage = (buffer: Buffer) => {
  return parseChallengeMessage(buffer).serverChallenge;
};

export const encodeAuthenticationMessage = (username: string, hostname: string, domain: string, nonce: Buffer, password: string) => {
  hostname = hostname.toUpperCase();
  domain = domain.toUpperCase();

  const lmHash = Buffer.alloc(21);
  createLmHash(password).copy(lmHash);
  lmHash.fill(0x00, 16);

  const ntHash = Buffer.alloc(21);
  createNtHash(password).copy(ntHash);
  ntHash.fill(0x00, 16);

  const lmResponse = createResponse(lmHash, nonce);
  const ntResponse = createResponse(ntHash, nonce);

  const usernameLength = Buffer.byteLength(username, "ucs2");
  const hostnameLength = Buffer.byteLength(hostname, "ucs2");
  const domainLength = Buffer.byteLength(domain, "ucs2");
  const lmResponseLength = 0x18;
  const ntResponseLength = 0x18;

  const domainOffset = 0x40;
  const usernameOffset = domainOffset + domainLength;
  const hostnameOffset = usernameOffset + usernameLength;
  const lmResponseOffset = hostnameOffset + hostnameLength;
  const ntResponseOffset = lmResponseOffset + lmResponseLength;

  let offset = 0;
  const messageLength = 64 + domainLength + usernameLength + hostnameLength + lmResponseLength + ntResponseLength;
  const buffer = Buffer.alloc(messageLength);

  buffer.write("NTLMSSP", offset, 7, "ascii"); // byte protocol[8];
  offset += 7;
  buffer.writeUInt8(0, offset);
  offset++;

  buffer.writeUInt8(0x03, offset); // byte type;
  offset++;

  buffer.fill(0x00, offset, offset + 3); // byte zero[3];
  offset += 3;

  buffer.writeUInt16LE(lmResponseLength, offset); // short lm_resp_len;
  offset += 2;
  buffer.writeUInt16LE(lmResponseLength, offset); // short lm_resp_len;
  offset += 2;
  buffer.writeUInt16LE(lmResponseOffset, offset); // short lm_resp_off;
  offset += 2;
  buffer.fill(0x00, offset, offset + 2); // byte zero[2];
  offset += 2;

  buffer.writeUInt16LE(ntResponseLength, offset); // short nt_resp_len;
  offset += 2;
  buffer.writeUInt16LE(ntResponseLength, offset); // short nt_resp_len;
  offset += 2;
  buffer.writeUInt16LE(ntResponseOffset, offset); // short nt_resp_off;
  offset += 2;
  buffer.fill(0x00, offset, offset + 2); // byte zero[2];
  offset += 2;

  buffer.writeUInt16LE(domainLength, offset); // short dom_len;
  offset += 2;
  buffer.writeUInt16LE(domainLength, offset); // short dom_len;
  offset += 2;
  buffer.writeUInt16LE(domainOffset, offset); // short dom_off;
  offset += 2;
  buffer.fill(0x00, offset, offset + 2); // byte zero[2];
  offset += 2;

  buffer.writeUInt16LE(usernameLength, offset); // short user_len;
  offset += 2;
  buffer.writeUInt16LE(usernameLength, offset); // short user_len;
  offset += 2;
  buffer.writeUInt16LE(usernameOffset, offset); // short user_off;
  offset += 2;
  buffer.fill(0x00, offset, offset + 2); // byte zero[2];
  offset += 2;

  buffer.writeUInt16LE(hostnameLength, offset); // short host_len;
  offset += 2;
  buffer.writeUInt16LE(hostnameLength, offset); // short host_len;
  offset += 2;
  buffer.writeUInt16LE(hostnameOffset, offset); // short host_off;
  offset += 2;
  buffer.fill(0x00, offset, offset + 6); // byte zero[6];
  offset += 6;

  buffer.writeUInt16LE(messageLength, offset); // short msg_len;
  offset += 2;
  buffer.fill(0x00, offset, offset + 2); // byte zero[2];
  offset += 2;

  const negotiateFlags = NegotiateFlag.UnicodeEncoding | NegotiateFlag.NTLMSessionSecurity | NegotiateFlag.AlwaysSign;
  buffer.writeUInt32LE(negotiateFlags, offset);
  offset += 4;

  buffer.write(domain, domainOffset, domainLength, "ucs2");
  buffer.write(username, usernameOffset, usernameLength, "ucs2");
  buffer.write(hostname, hostnameOffset, hostnameLength, "ucs2");
  lmResponse.copy(buffer, lmResponseOffset, 0, lmResponseLength);
  ntResponse.copy(buffer, ntResponseOffset, 0, ntResponseLength);

  // Derive the NTLM User Session Key: MD4(MD4(unicode(password)))
  const ntHashForSessionKey = createNtHash(password);
  const sessionKeyMd4 = jsmd4.create();
  sessionKeyMd4.update(ntHashForSessionKey);
  const sessionKey = Buffer.from(sessionKeyMd4.digest());

  return { buffer, sessionKey };
};

const AvId = {
  EOL: 0,
  Flags: 6,
  Timestamp: 7
};

const AV_FLAG_MIC_PRESENT = 0x00000002;
const AUTHENTICATE_V2_HEADER_LENGTH = 88;
const MIC_OFFSET = 72;

interface AvPair {
  id: number;
  value: Buffer;
}

const parseAvPairs = (buffer: Buffer): AvPair[] => {
  const pairs: AvPair[] = [];
  let offset = 0;
  while (offset + 4 <= buffer.length) {
    const id = buffer.readUInt16LE(offset);
    const length = buffer.readUInt16LE(offset + 2);
    if (id === AvId.EOL) break;
    pairs.push({ id, value: Buffer.from(buffer.slice(offset + 4, offset + 4 + length)) });
    offset += 4 + length;
  }
  return pairs;
};

const serializeAvPairs = (pairs: AvPair[]) => {
  const buffers = pairs.map(pair => {
    const header = Buffer.alloc(4);
    header.writeUInt16LE(pair.id, 0);
    header.writeUInt16LE(pair.value.length, 2);
    return Buffer.concat([header, pair.value]);
  });
  buffers.push(Buffer.alloc(4)); // MsvAvEOL
  return Buffer.concat(buffers);
};

const hmacMd5 = (key: Buffer, data: Buffer) => crypto.createHmac("md5", key).update(data).digest();

const getFileTime = (date: Date = new Date()) => {
  const buffer = Buffer.alloc(8);
  buffer.writeBigUInt64LE((BigInt(date.getTime()) + 11644473600000n) * 10000n);
  return buffer;
};

export const createNtlmV2Hash = (username: string, domain: string, password: string) => {
  return hmacMd5(createNtHash(password), Buffer.from(username.toUpperCase() + domain, "utf16le"));
};

export interface AuthenticationV2Options {
  /** 8 random bytes by default; only override for deterministic tests. */
  clientChallenge?: Buffer;
  /** FILETIME; defaults to the server's MsvAvTimestamp or the current time. */
  timestamp?: Buffer;
  /** Raw NEGOTIATE_MESSAGE and CHALLENGE_MESSAGE, required to compute the MIC. */
  negotiateMessage?: Buffer;
  challengeMessage?: Buffer;
}

/**
 * Builds an NTLMv2 AUTHENTICATE_MESSAGE as per MS-NLMP 3.1.5.1.2 / 3.3.2.
 * Key exchange is not negotiated, so the exported session key is the SessionBaseKey.
 */
export const encodeAuthenticationMessageV2 = (
  username: string,
  hostname: string,
  domain: string,
  challenge: ChallengeMessage,
  password: string,
  options: AuthenticationV2Options = {}
) => {
  hostname = hostname.toUpperCase();

  const clientChallenge = options.clientChallenge || crypto.randomBytes(8);
  const avPairs = parseAvPairs(challenge.targetInfo);
  const serverTimestamp = avPairs.find(pair => pair.id === AvId.Timestamp)?.value;
  const timestamp = options.timestamp || serverTimestamp || getFileTime();

  // When the server sends MsvAvTimestamp the client must omit the LMv2 response and should send a MIC.
  const includeMic = !!serverTimestamp && !!options.negotiateMessage && !!options.challengeMessage;
  if (includeMic) {
    let flagsPair = avPairs.find(pair => pair.id === AvId.Flags);
    if (!flagsPair) {
      flagsPair = { id: AvId.Flags, value: Buffer.alloc(4) };
      avPairs.push(flagsPair);
    }
    flagsPair.value.writeUInt32LE((flagsPair.value.readUInt32LE(0) | AV_FLAG_MIC_PRESENT) >>> 0, 0);
  }

  const responseKeyNt = createNtlmV2Hash(username, domain, password);
  const temp = Buffer.concat([
    Buffer.from([0x01, 0x01, 0, 0, 0, 0, 0, 0]),
    timestamp,
    clientChallenge,
    Buffer.alloc(4),
    serializeAvPairs(avPairs),
    Buffer.alloc(4)
  ]);
  const ntProofStr = hmacMd5(responseKeyNt, Buffer.concat([challenge.serverChallenge, temp]));
  const ntResponse = Buffer.concat([ntProofStr, temp]);
  const lmResponse = serverTimestamp ?
    Buffer.alloc(24) :
    Buffer.concat([hmacMd5(responseKeyNt, Buffer.concat([challenge.serverChallenge, clientChallenge])), clientChallenge]);
  const sessionKey = hmacMd5(responseKeyNt, ntProofStr);

  const domainBuffer = Buffer.from(domain, "utf16le");
  const usernameBuffer = Buffer.from(username, "utf16le");
  const hostnameBuffer = Buffer.from(hostname, "utf16le");

  const domainOffset = AUTHENTICATE_V2_HEADER_LENGTH;
  const usernameOffset = domainOffset + domainBuffer.length;
  const hostnameOffset = usernameOffset + usernameBuffer.length;
  const lmResponseOffset = hostnameOffset + hostnameBuffer.length;
  const ntResponseOffset = lmResponseOffset + lmResponse.length;
  const messageLength = ntResponseOffset + ntResponse.length;

  const buffer = Buffer.alloc(messageLength);
  buffer.write("NTLMSSP\0", 0, 8, "ascii");
  buffer.writeUInt32LE(3, 8);

  const fields: [Buffer, number][] = [
    [lmResponse, lmResponseOffset],
    [ntResponse, ntResponseOffset],
    [domainBuffer, domainOffset],
    [usernameBuffer, usernameOffset],
    [hostnameBuffer, hostnameOffset],
    [Buffer.alloc(0), messageLength] // EncryptedRandomSessionKey: empty, key exchange is not negotiated
  ];
  fields.forEach(([payload, payloadOffset], index) => {
    const fieldOffset = 12 + index * 8;
    buffer.writeUInt16LE(payload.length, fieldOffset);
    buffer.writeUInt16LE(payload.length, fieldOffset + 2);
    buffer.writeUInt32LE(payloadOffset, fieldOffset + 4);
    payload.copy(buffer, payloadOffset);
  });

  const negotiateFlags = (ntlmV2NegotiateFlags & challenge.negotiateFlags) | NegotiateFlag.UnicodeEncoding;
  buffer.writeUInt32LE(negotiateFlags >>> 0, 60);

  // Version (64-71) and MIC (72-87) remain zero until the MIC is computed
  if (includeMic) {
    hmacMd5(sessionKey, Buffer.concat([options.negotiateMessage, options.challengeMessage, buffer])).copy(buffer, MIC_OFFSET);
  }

  return { buffer, sessionKey };
};

export const generateServerChallenge = () => {
  return crypto.randomBytes(8);
};

const bytes2binaryArray = (buf: Buffer): number[] => {
  const hex2binary = {
    0: [0, 0, 0, 0],
    1: [0, 0, 0, 1],
    2: [0, 0, 1, 0],
    3: [0, 0, 1, 1],
    4: [0, 1, 0, 0],
    5: [0, 1, 0, 1],
    6: [0, 1, 1, 0],
    7: [0, 1, 1, 1],
    8: [1, 0, 0, 0],
    9: [1, 0, 0, 1],
    A: [1, 0, 1, 0],
    B: [1, 0, 1, 1],
    C: [1, 1, 0, 0],
    D: [1, 1, 0, 1],
    E: [1, 1, 1, 0],
    F: [1, 1, 1, 1],
  };

  const hexString = buf.toString("hex").toUpperCase();
  let array: number[] = [];
  for (let i = 0; i < hexString.length; i++) {
    const hexchar = hexString.charAt(i);
    array = array.concat(hex2binary[hexchar]);
  }
  return array;
};

const binaryArray2bytes = (array: number[]): Buffer => {
  const binary2hex = {
    "0000": 0,
    "0001": 1,
    "0010": 2,
    "0011": 3,
    "0100": 4,
    "0101": 5,
    "0110": 6,
    "0111": 7,
    "1000": 8,
    "1001": 9,
    "1010": "A",
    "1011": "B",
    "1100": "C",
    "1101": "D",
    "1110": "E",
    "1111": "F",
  };

  const bufArray: Buffer[] = [];

  for (let i = 0; i < array.length; i += 8) {
    if (i + 7 > array.length) break;

    const binString1 =
      "" + array[i] + "" + array[i + 1] + "" + array[i + 2] + "" + array[i + 3];
    const binString2 =
      "" +
      array[i + 4] +
      "" +
      array[i + 5] +
      "" +
      array[i + 6] +
      "" +
      array[i + 7];
    const hexchar1 = binary2hex[binString1];
    const hexchar2 = binary2hex[binString2];

    const buf = Buffer.from(hexchar1 + "" + hexchar2, "hex");
    bufArray.push(buf);
  }

  return Buffer.concat(bufArray);
};

const insertZerosEvery7Bits = (buf: Buffer): Buffer => {
  const binaryArray = bytes2binaryArray(buf);
  const newBinaryArray = [];
  for (let i = 0; i < binaryArray.length; i++) {
    newBinaryArray.push(binaryArray[i]);

    if ((i + 1) % 7 === 0) {
      newBinaryArray.push(0);
    }
  }
  return binaryArray2bytes(newBinaryArray);
};

const createLmHash = (password: string): Buffer => {
  password = password.toUpperCase();
  const passwordBytes = Buffer.from(password, "ascii");

  const passwordBytesPadded = Buffer.alloc(14);
  passwordBytesPadded.fill("\0");
  let sourceEnd = 14;
  if (passwordBytes.length < 14) sourceEnd = passwordBytes.length;
  passwordBytes.copy(passwordBytesPadded, 0, 0, sourceEnd);

  const firstPart = passwordBytesPadded.slice(0, 7);
  const secondPart = passwordBytesPadded.slice(7);

  function encrypt(buf) {
    const key = insertZerosEvery7Bits(buf);
    const des = desjs.DES.create({ type: "encrypt", key: key });
    const magicKey = Buffer.from("KGS!@#$%", "ascii");
    const encrypted = des.update(magicKey);
    return Buffer.from(encrypted);
  }

  const firstPartEncrypted = encrypt(firstPart);
  const secondPartEncrypted = encrypt(secondPart);

  return Buffer.concat([firstPartEncrypted, secondPartEncrypted]);
};

const createNtHash = (password: string): Buffer => {
  const buf = Buffer.from(password, "utf16le");
  const md4 = jsmd4.create();
  md4.update(buf);
  return Buffer.from(md4.digest());
};

const createResponse = (hash: Buffer, nonce: Buffer) => {
  const passHashPadded = Buffer.alloc(21);
  passHashPadded.fill("\0");
  hash.copy(passHashPadded, 0, 0, hash.length);

  const resArray = [];

  const des1 = desjs.DES.create({
    type: "encrypt",
    key: insertZerosEvery7Bits(passHashPadded.slice(0, 7)),
  });
  resArray.push(Buffer.from(des1.update(nonce.slice(0, 8))));

  const des2 = desjs.DES.create({
    type: "encrypt",
    key: insertZerosEvery7Bits(passHashPadded.slice(7, 14)),
  });
  resArray.push(Buffer.from(des2.update(nonce.slice(0, 8))));

  const des3 = desjs.DES.create({
    type: "encrypt",
    key: insertZerosEvery7Bits(passHashPadded.slice(14, 21)),
  });
  resArray.push(Buffer.from(des3.update(nonce.slice(0, 8))));

  return Buffer.concat(resArray);
};
