import Tree from "./Tree";
import Client from "./Client";
import { EventEmitter } from "events";
import Dialect from "../protocol/smb2/Dialect";
import Header from "../protocol/smb2/Header";
import * as ntlmUtil from "../protocol/ntlm/util";
import PacketType from "../protocol/smb2/PacketType";

/**
 * SecurityMode flag values as per MS-SMB2 2.2.3 / 2.2.5.
 */
const SIGNING_ENABLED  = 0x01;
const SIGNING_REQUIRED = 0x02;

export interface AuthenticateOptions {
  domain: string;
  username: string;
  password: string;
  /** When true the client will require signing. Defaults to false (signing enabled but not required). */
  signingRequired?: boolean;
}

interface Session {
  on(event: "authenticate" | "logoff", callback: (session: Session) => void): this;

  once(event: "authenticate" | "logoff", callback: (session: Session) => void): this;
}

class Session extends EventEmitter {
  _id: string;
  authenticated: boolean = false;

  /** The negotiated session signing key (NTLM User Session Key). */
  signingKey: Buffer | null = null;
  /** Whether message signing is active for this session. */
  signingActive: boolean = false;

  connectedTrees: Tree[] = [];

  constructor(
    public client: Client
  ) {
    super();
  }

  async connectTree(path: string) {
    const tree = new Tree(this);
    this.registerTree(tree);
    await tree.connect(path);

    return tree;
  }

  createRequest(header: Header = {}, body: any = {}) {
    return this.client.createRequest({
      sessionId: this._id,
      ...header
    }, body);
  }

  async request(header: Header = {}, body: any = {}) {
    return await this.client.request(
      {
        sessionId: this._id,
        ...header
      },
      body
    );
  }

  async authenticate(options: AuthenticateOptions) {
    if (this.authenticated) return;

    const clientSigningRequired = options.signingRequired === true;
    const securityMode = clientSigningRequired
      ? (SIGNING_ENABLED | SIGNING_REQUIRED)
      : SIGNING_ENABLED;

    // Step 1 — Negotiate
    const negotiateResponse = await this.request({
      type: PacketType.Negotiate
    }, {
      dialects: [
        Dialect.Smb202,
        Dialect.Smb210
      ],
      securityMode
    });

    // Determine whether the server requires signing
    const serverSecurityMode: number = negotiateResponse.body.securityMode ?? 0;
    const serverSigningRequired = (serverSecurityMode & SIGNING_REQUIRED) !== 0;

    // Step 2 — SessionSetup (NTLM Type 1 – Negotiation)
    const sessionSetupResponse = await this.request(
      { type: PacketType.SessionSetup },
      {
        buffer: ntlmUtil.encodeNegotiationMessage(this.client.host, options.domain),
        securityMode
      }
    );
    this._id = sessionSetupResponse.header.sessionId;

    // Step 3 — SessionSetup (NTLM Type 3 – Authentication)
    const nonce = ntlmUtil.decodeChallengeMessage(sessionSetupResponse.body.buffer as Buffer);
    const authResult = ntlmUtil.encodeAuthenticationMessage(
      options.username,
      this.client.host,
      options.domain,
      nonce,
      options.password
    );
    await this.request(
      { type: PacketType.SessionSetup },
      {
        buffer: authResult.buffer,
        securityMode
      }
    );

    // Activate signing if either side requires it
    if (clientSigningRequired || serverSigningRequired) {
      this.signingKey = authResult.sessionKey;
      this.signingActive = true;
    }

    this.authenticated = true;

    this.emit("authenticate", this);
  }

  private registerTree(tree: Tree) {
    tree
      .once("connect", () => this.connectedTrees.push(tree))
      .once("disconnect", () => this.connectedTrees.splice(this.connectedTrees.indexOf(tree), 1));
  }

  async logoff() {
    if (!this.authenticated) return;
    this.authenticated = false;

    await Promise.all(this.connectedTrees.map(x => x.disconnect()));

    await this.request({ type: PacketType.LogOff });
    delete this._id;

    this.emit("logoff", this);
  }
}

export default Session;