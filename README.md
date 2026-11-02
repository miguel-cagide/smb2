# @awo00/smb2

> A SMB2 implementation in TypeScript.

Forked from https://github.com/ardean/smb2 using code from https://github.com/SamDecrock/node-http-ntlm to fix Node 17+ OpenSSL error to prevent having to use legacy support.

## Requirements

Node.js 22 or newer.

## Installation
```sh
$ npm i @awo00/smb2
```

## Usage
```ts
import smb2 from "@awo00/smb2";

const client = new smb2.Client(host);
const session = await client.authenticate({
  domain,
  username,
  password
});
const tree = await session.connectTree(share);

const entries = await tree.readDirectory("/");
console.log(entries);
```

### Authentication

NTLMv2 is used by default. NTLMv1 is still available for legacy servers, but most modern servers reject it (Samba's default `ntlm auth = ntlmv2-only`, Windows 11 24H2 / Server 2025).

```ts
await client.authenticate({
  domain,
  username,
  password,
  ntlmVersion: 1, // optional, defaults to 2
  signingRequired: true // optional, defaults to false
});
```

### Readable errors

By default, failed requests reject with the raw SMB2 `Response` object (backwards compatible). Enable `readableErrors` to reject with an `SmbError` instead:

```ts
const client = new smb2.Client(host, { readableErrors: true });

try {
  await client.authenticate({ domain, username, password });
} catch (err) {
  console.error(err.message);
  // authenticate "DOMAIN\user" failed: STATUS_LOGON_FAILURE (0xC000006D) - Logon failure: unknown user name, bad password or wrong domain. (SMB2 SessionSetup)
  if (err instanceof smb2.SmbError) {
    err.operation; // "authenticate" (client method that failed)
    err.target;    // "DOMAIN\user" (path, share or account it was applied to)
    err.command;   // "SessionSetup" (underlying SMB2 command)
    err.code;      // "STATUS_LOGON_FAILURE"
    err.status;    // 3221225581
    err.response;  // the raw Response (err.header is also available)
  }
}
```

## Development

```sh
$ npm run build
$ npm test
```

## Features

### Client
- NTLMv2 (default) and NTLMv1 authentication
- SMB2 message signing
- watch shares for file and directory changes
- create, read & remove & rename files
- create, list & remove & rename directories
- check directory/file exists

## WIP
- SMB
- Server

## License

[MIT](LICENSE.md)
