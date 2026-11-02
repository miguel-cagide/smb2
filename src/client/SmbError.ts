import Header from "../protocol/smb2/Header";
import Response from "../protocol/smb2/Response";
import Request from "../protocol/smb2/Request";
import Smb2PacketType from "../protocol/smb2/PacketType";
import * as structureUtil from "../protocol/structureUtil";
import { getStatusInfo, formatStatus } from "../protocol/smb2/statusMessages";

export default class SmbError extends Error {
  /** NTSTATUS name, e.g. "STATUS_LOGON_FAILURE" */
  code: string;
  /** Raw NTSTATUS value */
  status: number;
  /** NTSTATUS value as hex string, e.g. "0xC000006D" */
  statusHex: string;
  description: string;
  /** SMB2 command that failed, e.g. "SessionSetup" */
  command: string;
  /** High-level client operation that failed, e.g. "removeFile" */
  operation?: string;
  /** Path, share or account the operation was applied to */
  target?: string;

  // Kept for compatibility with code inspecting `err.header.status`; non-enumerable to keep logs readable.
  declare header: Header;
  declare response: Response;
  declare request: Request;

  constructor(response: Response) {
    const status = response.header.status;
    const { code, description } = getStatusInfo(status);
    const command = structureUtil.parseEnumValue(Smb2PacketType, response.header.type) || `Command(${response.header.type})`;
    const statusHex = formatStatus(status);

    super(`${command} failed: ${code} (${statusHex}) - ${description}`);

    this.name = "SmbError";
    this.code = code;
    this.status = status;
    this.statusHex = statusHex;
    this.description = description;
    this.command = command;

    Object.defineProperties(this, {
      header: { value: response.header, enumerable: false, writable: true },
      response: { value: response, enumerable: false, writable: true },
      request: { value: response.request, enumerable: false, writable: true }
    });
  }

  /**
   * Attributes the error to the high-level operation the caller invoked, so the message reads
   * `removeFile "/a.txt" failed: ... (SMB2 Create)` instead of only naming the low-level command.
   */
  setContext(operation: string, target?: string) {
    if (this.operation) return this;

    this.operation = operation;
    if (typeof target !== "undefined") this.target = target;

    const subject = typeof target !== "undefined" ? `${operation} "${target}"` : operation;
    this.message = `${subject} failed: ${this.code} (${this.statusHex}) - ${this.description} (SMB2 ${this.command})`;
    // Recapture so the stack shows the caller's async frames instead of the socket data handler.
    Error.captureStackTrace(this, this.setContext);

    return this;
  }
}

export const withErrorContext = async <T>(operation: string, target: string | undefined, fn: () => Promise<T>): Promise<T> => {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof SmbError) err.setContext(operation, target);
    throw err;
  }
};
