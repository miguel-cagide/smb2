import test from "node:test";
import assert from "node:assert/strict";
import SmbError, { withErrorContext } from "../src/client/SmbError";
import Response from "../src/protocol/smb2/Response";
import Smb2PacketType from "../src/protocol/smb2/PacketType";
import StatusCode from "../src/protocol/smb2/StatusCode";

const makeResponse = (type: Smb2PacketType, status: number) =>
  new Response({ type, status, messageId: 2n }, {});

test("SmbError describes known NTSTATUS codes", () => {
  const err = new SmbError(makeResponse(Smb2PacketType.SessionSetup, 0xc000006d));

  assert.ok(err instanceof Error);
  assert.equal(err.name, "SmbError");
  assert.equal(err.code, "STATUS_LOGON_FAILURE");
  assert.equal(err.statusHex, "0xC000006D");
  assert.equal(err.command, "SessionSetup");
  assert.match(err.message, /^SessionSetup failed: STATUS_LOGON_FAILURE \(0xC000006D\) - /);
});

test("SmbError keeps header for status checks without exposing it in logs", () => {
  const response = makeResponse(Smb2PacketType.Create, StatusCode.FileNameNotFound);
  const err = new SmbError(response);

  assert.equal(err.header.status, StatusCode.FileNameNotFound);
  assert.equal(err.response, response);
  assert.ok(!Object.keys(err).includes("header"));
  assert.ok(!Object.keys(err).includes("response"));
});

test("SmbError handles unknown NTSTATUS codes", () => {
  const err = new SmbError(makeResponse(Smb2PacketType.Read, 0xc0001234));

  assert.equal(err.code, "STATUS_UNKNOWN");
  assert.equal(err.statusHex, "0xC0001234");
});

test("withErrorContext attributes the error to the high-level operation", async () => {
  const failing = () => Promise.reject(new SmbError(makeResponse(Smb2PacketType.Create, 0xc0000034)));

  await assert.rejects(
    withErrorContext("removeFile", "/a.txt", () => withErrorContext("inner", "/b", failing)),
    (err: SmbError) => {
      // innermost context wins; outer wrappers do not overwrite it
      assert.equal(err.operation, "inner");
      return true;
    }
  );

  await assert.rejects(withErrorContext("removeFile", "/a.txt", failing), (err: SmbError) => {
    assert.equal(err.operation, "removeFile");
    assert.equal(err.target, "/a.txt");
    assert.equal(err.command, "Create");
    assert.equal(err.message, 'removeFile "/a.txt" failed: STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034) - The file or directory was not found. (SMB2 Create)');
    assert.match(err.stack, /^SmbError: removeFile "\/a.txt" failed/);
    return true;
  });
});

test("withErrorContext leaves raw Response rejections untouched", async () => {
  const response = makeResponse(Smb2PacketType.Create, 0xc0000034);
  await assert.rejects(withErrorContext("removeFile", "/a.txt", () => Promise.reject(response)), (err) => err === response);
});
