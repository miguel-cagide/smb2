# @miguel-cagide/smb2

> A SMB2 implementation in TypeScript.

Forked from https://github.com/awo00/smb2.

## Requirements

Node.js 22 or newer.

## Installation
```sh
$ npm i @miguel-cagide/smb2
```

## Usage
```ts
import smb2 from "@miguel-cagide/smb2";

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

### Reading and writing files

`readFile` and `createFile` transfer the whole content at once. Under the hood, data is sent in chunks of up to 64 KiB per SMB2 Read/Write request, so large files work without extra configuration:

```ts
await tree.createFile("/hello.txt", "Hello world");
const content = await tree.readFile("/hello.txt"); // Buffer
```

### Streams

Use streams to transfer large files without loading them into memory. `createFileReadStream` returns a Node.js `Readable` that reads the file chunk by chunk. You can pass optional `start` (inclusive) and `end` (exclusive) byte offsets to read only part of the file:

```ts
import { createWriteStream } from "fs";
import { pipeline } from "stream/promises";

const readStream = await tree.createFileReadStream("/big-file.bin");
await pipeline(readStream, createWriteStream("./big-file.bin"));

// read only bytes 1024..4095
const partial = await tree.createFileReadStream("/big-file.bin", { start: 1024, end: 4096 });
```

`createFileWriteStream` returns a Node.js `Writable`. Large writes are split into chunks automatically. You can pass an optional `offset` to start writing at a given byte position. When the stream closes, the file size is set to the number of bytes written and the file is closed:

```ts
import { createReadStream } from "fs";
import { pipeline } from "stream/promises";

const writeStream = await tree.createFileWriteStream("/big-file.bin");
await pipeline(createReadStream("./big-file.bin"), writeStream);
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
- chunked reads and writes (large files are split into 64 KiB SMB2 requests)
- read & write streams (`createFileReadStream` with `start`/`end` ranges, `createFileWriteStream` with `offset`)
- create, list & remove & rename directories
- check directory/file exists

## WIP
- SMB
- Server

## License

[MIT](LICENSE.md)
