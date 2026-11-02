export interface StatusInfo {
  code: string;
  description: string;
}

// Common NTSTATUS values returned by SMB2 servers ([MS-ERREF] 2.3.1)
const statusMessages: { [status: number]: StatusInfo } = {
  0x80000005: { code: "STATUS_BUFFER_OVERFLOW", description: "The data was too large to fit into the specified buffer." },
  0x80000006: { code: "STATUS_NO_MORE_FILES", description: "No more files were found which match the file specification." },
  0xc0000002: { code: "STATUS_NOT_IMPLEMENTED", description: "The requested operation is not implemented by the server." },
  0xc0000003: { code: "STATUS_INVALID_INFO_CLASS", description: "The specified information class is not valid." },
  0xc0000008: { code: "STATUS_INVALID_HANDLE", description: "An invalid file handle was specified." },
  0xc000000d: { code: "STATUS_INVALID_PARAMETER", description: "An invalid parameter was passed to the server." },
  0xc000000f: { code: "STATUS_NO_SUCH_FILE", description: "The file does not exist." },
  0xc0000010: { code: "STATUS_INVALID_DEVICE_REQUEST", description: "The specified request is not valid for the target device." },
  0xc0000011: { code: "STATUS_END_OF_FILE", description: "The end of the file has been reached." },
  0xc0000022: { code: "STATUS_ACCESS_DENIED", description: "Access denied. The user does not have the required permissions." },
  0xc0000023: { code: "STATUS_BUFFER_TOO_SMALL", description: "The buffer is too small to contain the entry." },
  0xc0000033: { code: "STATUS_OBJECT_NAME_INVALID", description: "The object name is invalid." },
  0xc0000034: { code: "STATUS_OBJECT_NAME_NOT_FOUND", description: "The file or directory was not found." },
  0xc0000035: { code: "STATUS_OBJECT_NAME_COLLISION", description: "The file or directory already exists." },
  0xc0000039: { code: "STATUS_OBJECT_PATH_INVALID", description: "The object path is invalid." },
  0xc000003a: { code: "STATUS_OBJECT_PATH_NOT_FOUND", description: "The path does not exist." },
  0xc000003b: { code: "STATUS_OBJECT_PATH_SYNTAX_BAD", description: "The object path syntax is invalid." },
  0xc0000043: { code: "STATUS_SHARING_VIOLATION", description: "The file is in use by another process." },
  0xc0000054: { code: "STATUS_FILE_LOCK_CONFLICT", description: "A file lock conflicts with the requested operation." },
  0xc0000055: { code: "STATUS_LOCK_NOT_GRANTED", description: "The requested file lock could not be granted." },
  0xc0000056: { code: "STATUS_DELETE_PENDING", description: "The file is pending deletion." },
  0xc0000061: { code: "STATUS_PRIVILEGE_NOT_HELD", description: "A required privilege is not held by the client." },
  0xc0000064: { code: "STATUS_NO_SUCH_USER", description: "The specified user account does not exist." },
  0xc000006a: { code: "STATUS_WRONG_PASSWORD", description: "The password is incorrect." },
  0xc000006d: { code: "STATUS_LOGON_FAILURE", description: "Logon failure: unknown user name, bad password or wrong domain." },
  0xc000006e: { code: "STATUS_ACCOUNT_RESTRICTION", description: "Logon failure: user account restriction (e.g. blank password not allowed)." },
  0xc000006f: { code: "STATUS_INVALID_LOGON_HOURS", description: "Logon failure: the account is not allowed to log on at this time." },
  0xc0000070: { code: "STATUS_INVALID_WORKSTATION", description: "Logon failure: the account is not allowed to log on from this computer." },
  0xc0000071: { code: "STATUS_PASSWORD_EXPIRED", description: "Logon failure: the password has expired." },
  0xc0000072: { code: "STATUS_ACCOUNT_DISABLED", description: "Logon failure: the account is disabled." },
  0xc000007f: { code: "STATUS_DISK_FULL", description: "There is not enough space on the disk." },
  0xc000009a: { code: "STATUS_INSUFFICIENT_RESOURCES", description: "The server has insufficient resources to complete the request." },
  0xc00000b5: { code: "STATUS_IO_TIMEOUT", description: "The I/O operation timed out." },
  0xc00000ba: { code: "STATUS_FILE_IS_A_DIRECTORY", description: "The target is a directory, not a file." },
  0xc00000bb: { code: "STATUS_NOT_SUPPORTED", description: "The request is not supported by the server." },
  0xc00000c3: { code: "STATUS_INVALID_NETWORK_RESPONSE", description: "The network responded incorrectly." },
  0xc00000c9: { code: "STATUS_NETWORK_NAME_DELETED", description: "The share has been deleted or is no longer available." },
  0xc00000ca: { code: "STATUS_NETWORK_ACCESS_DENIED", description: "Network access to the share is denied." },
  0xc00000cc: { code: "STATUS_BAD_NETWORK_NAME", description: "The share name does not exist on the server." },
  0xc00000d0: { code: "STATUS_REQUEST_NOT_ACCEPTED", description: "The server cannot accept more connections." },
  0xc0000101: { code: "STATUS_DIRECTORY_NOT_EMPTY", description: "The directory is not empty." },
  0xc0000103: { code: "STATUS_NOT_A_DIRECTORY", description: "The target is a file, not a directory." },
  0xc000011f: { code: "STATUS_TOO_MANY_OPENED_FILES", description: "Too many files are open on the server." },
  0xc0000120: { code: "STATUS_CANCELLED", description: "The operation was cancelled." },
  0xc0000121: { code: "STATUS_CANNOT_DELETE", description: "The file cannot be deleted." },
  0xc0000123: { code: "STATUS_FILE_DELETED", description: "The file has been deleted." },
  0xc0000128: { code: "STATUS_FILE_CLOSED", description: "The file handle has been closed." },
  0xc000015b: { code: "STATUS_LOGON_TYPE_NOT_GRANTED", description: "Logon failure: the user has not been granted the requested logon type." },
  0xc0000193: { code: "STATUS_ACCOUNT_EXPIRED", description: "Logon failure: the account has expired." },
  0xc0000203: { code: "STATUS_USER_SESSION_DELETED", description: "The session has been deleted by the server." },
  0xc0000205: { code: "STATUS_INSUFF_SERVER_RESOURCES", description: "The server has insufficient resources to complete the request." },
  0xc0000224: { code: "STATUS_PASSWORD_MUST_CHANGE", description: "Logon failure: the password must be changed before logging on." },
  0xc0000225: { code: "STATUS_NOT_FOUND", description: "The object was not found." },
  0xc0000234: { code: "STATUS_ACCOUNT_LOCKED_OUT", description: "Logon failure: the account is locked out." },
  0xc0000257: { code: "STATUS_PATH_NOT_COVERED", description: "The path is not covered by this server (DFS referral required)." },
  0xc000035c: { code: "STATUS_NETWORK_SESSION_EXPIRED", description: "The session has expired; re-authentication is required." },
  0xc0000388: { code: "STATUS_DOWNGRADE_DETECTED", description: "A security downgrade was detected during negotiation." }
};

export const formatStatus = (status: number) =>
  `0x${(status >>> 0).toString(16).toUpperCase().padStart(8, "0")}`;

export const getStatusInfo = (status: number): StatusInfo =>
  statusMessages[status >>> 0] || {
    code: "STATUS_UNKNOWN",
    description: `Unknown NTSTATUS ${formatStatus(status)}.`
  };

export default statusMessages;
