import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import * as ntlm from "../src/protocol/ntlm/util";

// Test vectors from [MS-NLMP] 4.2.1 Common Values
const user = "User";
const domain = "Domain";
const password = "Password";
const serverChallenge = Buffer.from("0123456789abcdef", "hex");
const clientChallenge = Buffer.from("aaaaaaaaaaaaaaaa", "hex");

const avPair = (id: number, value: Buffer) => {
  const header = Buffer.alloc(4);
  header.writeUInt16LE(id, 0);
  header.writeUInt16LE(value.length, 2);
  return Buffer.concat([header, value]);
};

// MsvAvNbDomainName "Domain", MsvAvNbComputerName "Server", MsvAvEOL
const specTargetInfo = Buffer.concat([
  avPair(2, Buffer.from("Domain", "utf16le")),
  avPair(1, Buffer.from("Server", "utf16le")),
  Buffer.alloc(4)
]);

const buildChallengeMessage = (targetInfo: Buffer, negotiateFlags = 0xe28a8233) => {
  const targetName = Buffer.from("Server", "utf16le");
  const buffer = Buffer.alloc(56 + targetName.length + targetInfo.length);
  buffer.write("NTLMSSP\0", 0, "ascii");
  buffer.writeUInt32LE(2, 8);
  buffer.writeUInt16LE(targetName.length, 12);
  buffer.writeUInt16LE(targetName.length, 14);
  buffer.writeUInt32LE(56, 16);
  buffer.writeUInt32LE(negotiateFlags, 20);
  serverChallenge.copy(buffer, 24);
  buffer.writeUInt16LE(targetInfo.length, 40);
  buffer.writeUInt16LE(targetInfo.length, 42);
  buffer.writeUInt32LE(56 + targetName.length, 44);
  targetName.copy(buffer, 56);
  targetInfo.copy(buffer, 56 + targetName.length);
  return buffer;
};

const readField = (message: Buffer, fieldOffset: number) => {
  const length = message.readUInt16LE(fieldOffset);
  const offset = message.readUInt32LE(fieldOffset + 4);
  return message.subarray(offset, offset + length);
};

test("NTLMv1 matches MS-NLMP 4.2.2 test vectors", () => {
  const { buffer, sessionKey } = ntlm.encodeAuthenticationMessage(user, "COMPUTER", domain, serverChallenge, password);
  const lmOffset = buffer.readUInt16LE(16);
  const ntOffset = buffer.readUInt16LE(24);
  assert.equal(buffer.subarray(lmOffset, lmOffset + 24).toString("hex"), "98def7b87f88aa5dafe2df779688a172def11c7d5ccdef13");
  assert.equal(buffer.subarray(ntOffset, ntOffset + 24).toString("hex"), "67c43011f30298a2ad35ece64f16331c44bdbed927841f94");
  assert.equal(sessionKey.toString("hex"), "d87262b0cde4b1cb7499becccdf10784");
});

test("parseChallengeMessage reads flags, challenge and target info", () => {
  const challenge = ntlm.parseChallengeMessage(buildChallengeMessage(specTargetInfo));
  assert.equal(challenge.negotiateFlags, 0xe28a8233);
  assert.deepEqual(challenge.serverChallenge, serverChallenge);
  assert.deepEqual(challenge.targetInfo, specTargetInfo);
  assert.equal(challenge.targetName.toString("utf16le"), "Server");
  assert.deepEqual(ntlm.decodeChallengeMessage(buildChallengeMessage(specTargetInfo)), serverChallenge);
});

test("NTLMv2 matches MS-NLMP 4.2.4 test vectors", () => {
  assert.equal(ntlm.createNtlmV2Hash(user, domain, password).toString("hex"), "0c868a403bfd7a93a3001ef22ef02e3f");

  const challenge = ntlm.parseChallengeMessage(buildChallengeMessage(specTargetInfo));
  const { buffer, sessionKey } = ntlm.encodeAuthenticationMessageV2(user, "COMPUTER", domain, challenge, password, {
    clientChallenge,
    timestamp: Buffer.alloc(8)
  });

  assert.equal(buffer.subarray(0, 8).toString("ascii"), "NTLMSSP\0");
  assert.equal(buffer.readUInt32LE(8), 3);
  assert.equal(readField(buffer, 12).toString("hex"), "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa");
  const ntResponse = readField(buffer, 20);
  assert.equal(ntResponse.subarray(0, 16).toString("hex"), "68cd0ab851e51c96aabc927bebef6a1c");
  assert.equal(
    ntResponse.subarray(16).toString("hex"),
    "0101000000000000" + "0000000000000000" + "aaaaaaaaaaaaaaaa" + "00000000" + specTargetInfo.toString("hex") + "00000000"
  );
  assert.equal(readField(buffer, 28).toString("utf16le"), domain);
  assert.equal(readField(buffer, 36).toString("utf16le"), user);
  assert.equal(readField(buffer, 44).toString("utf16le"), "COMPUTER");
  assert.equal(readField(buffer, 52).length, 0);
  assert.equal(sessionKey.toString("hex"), "8de40ccadbc14a82f15cb0ad0de95ca3");
  assert.deepEqual(buffer.subarray(72, 88), Buffer.alloc(16), "no MIC without server timestamp");
});

test("NTLMv2 sends a MIC and empty LM response when the server provides a timestamp", () => {
  const serverTimestamp = Buffer.from("0090d336b734c301", "hex");
  const targetInfo = Buffer.concat([
    avPair(2, Buffer.from("Domain", "utf16le")),
    avPair(1, Buffer.from("Server", "utf16le")),
    avPair(7, serverTimestamp),
    Buffer.alloc(4)
  ]);
  const negotiateMessage = ntlm.encodeNegotiationMessage("COMPUTER", domain, ntlm.ntlmV2NegotiateFlags);
  const challengeMessage = buildChallengeMessage(targetInfo);
  const { buffer, sessionKey } = ntlm.encodeAuthenticationMessageV2(
    user, "COMPUTER", domain, ntlm.parseChallengeMessage(challengeMessage), password,
    { negotiateMessage, challengeMessage }
  );

  assert.deepEqual(readField(buffer, 12), Buffer.alloc(24));
  const temp = readField(buffer, 20).subarray(16);
  assert.deepEqual(temp.subarray(8, 16), serverTimestamp);
  assert.ok(temp.includes(Buffer.from("060004000200000000000000", "hex")), "MsvAvFlags with MIC bit, followed by MsvAvEOL");

  const mic = Buffer.from(buffer.subarray(72, 88));
  const zeroedMic = Buffer.from(buffer);
  zeroedMic.fill(0, 72, 88);
  const expectedMic = crypto.createHmac("md5", sessionKey)
    .update(Buffer.concat([negotiateMessage, challengeMessage, zeroedMic]))
    .digest();
  assert.deepEqual(mic, expectedMic);
});

test("NTLMv2 negotiate flags are written as unsigned 32-bit", () => {
  const message = ntlm.encodeNegotiationMessage("COMPUTER", domain, ntlm.ntlmV2NegotiateFlags);
  assert.equal(message.readUInt32LE(12), ntlm.ntlmV2NegotiateFlags >>> 0);
});
