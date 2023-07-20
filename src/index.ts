import axios from "axios";


/**
 * +-------------------------+-----------------------------------------+
 * | Type                    | Description                             |
 * +-------------------------+-----------------------------------------+
 * | accountDoesNotExist     | The request specified an account that   |
 * |                         | does not exist                          |
 * |                         |                                         |
 * | alreadyRevoked          | The request specified a certificate to  |
 * |                         | be revoked that has already been        |
 * |                         | revoked                                 |
 * |                         |                                         |
 * | badCSR                  | The CSR is unacceptable (e.g., due to a |
 * |                         | short key)                              |
 * |                         |                                         |
 * | badNonce                | The client sent an unacceptable anti-   |
 * |                         | replay nonce                            |
 * |                         |                                         |
 * | badPublicKey            | The JWS was signed by a public key the  |
 * |                         | server does not support                 |
 * |                         |                                         |
 * | badRevocationReason     | The revocation reason provided is not   |
 * |                         | allowed by the server                   |
 * |                         |                                         |
 * | badSignatureAlgorithm   | The JWS was signed with an algorithm    |
 * |                         | the server does not support             |
 * |                         |                                         |
 * | caa                     | Certification Authority Authorization   |
 * |                         | (CAA) records forbid the CA from        |
 * |                         | issuing a certificate                   |
 * |                         |                                         |
 * | compound                | Specific error conditions are indicated |
 * |                         | in the "subproblems" array              |
 * |                         |                                         |
 * | connection              | The server could not connect to         |
 * |                         | validation target                       |
 * |                         |                                         |
 * | dns                     | There was a problem with a DNS query    |
 * |                         | during identifier validation            |
 * |                         |                                         |
 * | externalAccountRequired | The request must include a value for    |
 * |                         | the "externalAccountBinding" field      |
 * |                         |                                         |
 * | incorrectResponse       | Response received didn't match the      |
 * |                         | challenge's requirements                |
 * |                         |                                         |
 * | invalidContact          | A contact URL for an account was        |
 * |                         | invalid                                 |
 * |                         |                                         |
 * | malformed               | The request message was malformed       |
 * |                         |                                         |
 * | orderNotReady           | The request attempted to finalize an    |
 * |                         | order that is not ready to be finalized |
 * |                         |                                         |
 * | rateLimited             | The request exceeds a rate limit        |
 * |                         |                                         |
 * | rejectedIdentifier      | The server will not issue certificates  |
 * |                         | for the identifier                      |
 * |                         |                                         |
 * | serverInternal          | The server experienced an internal      |
 * |                         | error                                   |
 * |                         |                                         |
 * | tls                     | The server received a TLS error during  |
 * |                         | validation                              |
 * |                         |                                         |
 * | unauthorized            | The client lacks sufficient             |
 * |                         | authorization                           |
 * |                         |                                         |
 * | unsupportedContact      | A contact URL for an account used an    |
 * |                         | unsupported protocol scheme             |
 * |                         |                                         |
 * | unsupportedIdentifier   | An identifier is of an unsupported type |
 * |                         |                                         |
 * | userActionRequired      | Visit the "instance" URL and take       |
 * |                         | actions specified there                 |
 * +-------------------------+-----------------------------------------+
 */
export type ACMEProblemType = 
'urn:ietf:params:acme:error:accountDoesNotExist' |
'urn:ietf:params:acme:error:alreadyRevoked' |
'urn:ietf:params:acme:error:badCSR' |
'urn:ietf:params:acme:error:badNonce' |
'urn:ietf:params:acme:error:badPublicKey' |
'urn:ietf:params:acme:error:badRevocationReason' |
'urn:ietf:params:acme:error:badSignatureAlgorithm' |
'urn:ietf:params:acme:error:caa' |
'urn:ietf:params:acme:error:compound' |
'urn:ietf:params:acme:error:connection' |
'urn:ietf:params:acme:error:dns' |
'urn:ietf:params:acme:error:externalAccountRequired' |
'urn:ietf:params:acme:error:incorrectResponse' |
'urn:ietf:params:acme:error:invalidContact' |
'urn:ietf:params:acme:error:malformed' |
'urn:ietf:params:acme:error:orderNotReady' |
'urn:ietf:params:acme:error:rateLimited' |
'urn:ietf:params:acme:error:rejectedIdentifier' |
'urn:ietf:params:acme:error:serverInternal' |
'urn:ietf:params:acme:error:tls' |
'urn:ietf:params:acme:error:unauthorized' |
'urn:ietf:params:acme:error:unsupportedContact' |
'urn:ietf:params:acme:error:unsupportedIdentifier' |
'urn:ietf:params:acme:error:userActionRequired';

export type ACMESubProblemDocument = {
  /**
   * Type of problem (identifier)
   */
  type: ACMEProblemType,
  
  /**
   * Human readable description of the problem
   */
  detail: string,

  /**
   * Identifier object.
   */
  identifiers: {

    /**
     * The type of identifier.  This document
     * defines the "dns" identifier type.  See the registry defined in
     * Section 9.7.7 (https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.7) for any others.
     */
    type: 'dns',

    /**
     * The identifier itself.
     */
    value: string,
  }
};



export type ACMEProblemDocument = ACMESubProblemDocument & {

  /** Additional problems */
  subproblems?: ACMESubProblemDocument[],
};


/** 
 * In order to help clients configure themselves with the right URLs for
 * each ACME operation, ACME servers provide a directory object.  This
 * should be the only URL needed to configure clients.  It is a JSON
 * object, whose field names are drawn from the resource registry
 * (Section 9.7.5 https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.5) 
 * and whose values are the corresponding URLs.
 */
export type ACMEDirectory = {
  /** Optional additional metadata */
  meta?: {
    /** URL pointing to the current terms of service of the CA */
    termsOfService?: string,

    /** Optional URL pointing to the website of the CA */
    website?: string,

    /** Optional array of hostnames that are belonging to the CAs ACME servers */
    caaIdentities?: string[],

    /** Optional boolean indicating if the CA requires an additional externalAccountBinding for the newAccount operation */
    externalAccountRequired?: boolean,
  },

  /** URL for creating a new nonce */
  newNonce: string,

  /** URL for creating a new account  */
  newAccount: string,

  /** URL for creating a new order (certificate) */
  newOrder: string,

  /** Optional URL for authorization */
  newAuthz?: string,

  /** URL for revoking certificates */
  revokeCert: string,

  /** URL for updating keys */
  keyChange: string,

  /** URL for fetching renewal information of a certificate (LetsEncrypt only) */
  renewalInfo?: string,
};



/** 
 * An ACME account resource represents a set of metadata associated with
 * an account.
 */
export type ACMEAccount = {
  /** 
   * The status of this account.  Possible
   * values are "valid", "deactivated", and "revoked".  The value
   * "deactivated" should be used to indicate client-initiated
   * deactivation whereas "revoked" should be used to indicate server-
   * initiated deactivation. 
   * See Section 7.1.6 (https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.6).
   */
  status: 'valid' | 'deactivated' | 'revoked',

  /**
   * An array of URLs that the
   * server can use to contact the client for issues related to this
   * account.  For example, the server may wish to notify the client
   * about server-initiated revocation or certificate expiration.  For
   * information on supported URL schemes. 
   * See Section 7.3 (https://datatracker.ietf.org/doc/html/rfc8555#section-7.3).
   */
  contact?: string[],

  /** 
   * Including this field in a
   * newAccount request, with a value of true, indicates the client's
   * agreement with the terms of service.  This field cannot be updated
   * by the client.
   */
  termsOfServiceAgreed?: boolean,

  /**
   * Including this field in a
   * newAccount request indicates approval by the holder of an existing
   * non-ACME account to bind that account to this ACME account.  This
   * field is not updateable by the client. 
   * See Section 7.3.4 (https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.4).
   */
  externalAccountBinding?: any,

  /**
   * A URL from which a list of orders
   * submitted by this account can be fetched via a POST-as-GET
   * request.
   * See Section 7.1.2.1 (https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.2.1).
   */
  orders: string,
};



/** 
 * Each account object includes an "orders" URL from which a list of
 * orders created by the account can be fetched via POST-as-GET request.
 * The result of the request MUST be a JSON object whose "orders" field
 * is an array of URLs, each identifying an order belonging to the
 * account.  The server SHOULD include pending orders and SHOULD NOT
 * include orders that are invalid in the array of URLs.  The server MAY
 * return an incomplete list, along with a Link header field with a
 * "next" link relation indicating where further entries can be acquired.
 */
export type ACMEOrderList = {
  orders: string[],
};


/** 
 * An ACME order object represents a client's request for a certificate
 * and is used to track the progress of that order through to issuance.
 * Thus, the object contains information about the requested
 * certificate, the authorizations that the server requires the client
 * to complete, and any certificates that have resulted from this order.
 */
export type ACMEOrderObject = {

  /**
   * The status of this order. Possible
   * values are "pending", "ready", "processing", "valid", and
   * "invalid".
   * See Section 7.1.6 (https://datatracker.ietf.org/doc/html/rfc8555#section-7.1.6).
   */
  status: 'pending' | 'ready' | 'processing' | 'valid' | 'invalid',

  /**
   * The timestamp after which the server
   * will consider this order invalid, encoded in the format specified
   * in [RFC3339].  This field is REQUIRED for objects with "pending"
   * or "valid" in the status field.
   */
  expires?: string,

  /**
   * An array of identifier objects that the order pertains to.
   */
  identifiers: {

    /**
     * The type of identifier.  This document
     * defines the "dns" identifier type.  See the registry defined in
     * Section 9.7.7 (https://datatracker.ietf.org/doc/html/rfc8555#section-9.7.7) for any others.
     */
    type: 'dns',

    /**
     * The identifier itself.
     * For dns this is the domain name or a wildcard domain name 
     * e.g. 'example.com', '*.example.com', or '*.sub.example.com'.
     */
    value: string,
  }[],

  /**
   * The requested value of the notBefore
   * field in the certificate, in the date format defined in [RFC3339].
   */
  notBefore?: string,

  /**
   * The requested value of the notAfter
   * field in the certificate, in the date format defined in [RFC3339].
   */
  notAfter?: string,

  /**
   * The error that occurred while processing
   * the order, if any.  This field is structured as a problem document [RFC7807].
   */
  error?: ACMEProblemDocument,

  /**
   * For pending orders, the
   * authorizations that the client needs to complete before the
   * requested certificate can be issued 
   * (see Section 7.5 https://datatracker.ietf.org/doc/html/rfc8555#section-7.5), 
   * including unexpired authorizations that the client has completed in the past
   * for identifiers specified in the order.  The authorizations
   * required are dictated by server policy; there may not be a 1:1
   * relationship between the order identifiers and the authorizations
   * required.  For final orders (in the "valid" or "invalid" state),
   * the authorizations that were completed.  Each entry is a URL from
   * which an authorization can be fetched with a POST-as-GET request.
   */
  authorizations: string[],

  /**
   * A URL that a CSR must be POSTed to once
   * all of the order's authorizations are satisfied to finalize the
   * order.  The result of a successful finalization will be the
   * population of the certificate URL for the order.
   */
  finalize: string,

  /**
   * A URL for the certificate that has been issued in response to this order.
   */
  certificate?: string,
};


/** Represents a servers authorization for an account to represent an identifier. */
export type ACMEAuthorizationObject = {

  // TODO

};


/**
 * An ACME challenge object represents a server's offer to validate a
 * client's possession of an identifier in a specific way.  Unlike the
 * other objects listed above, there is not a single standard structure
 * for a challenge object.  The contents of a challenge object depend on
 * the validation method being used.  The general structure of challenge
 * objects and an initial set of validation methods are described in
 * Section 8 (https://datatracker.ietf.org/doc/html/rfc8555#section-8).
 */
export type ACMEChallengeObject = {

  // TODO

};


const GET = (url: string, nonce: string) => {
  return POST(url, nonce, '');
};

const POST = (url: string, nonce: string, json: any) => {
  json = typeof json === 'string' ? json : JSON.stringify(json);

  return axios.post(url, json, {

    // TODO JWS ( alg=none, nonce, url, jwk OR kid )
    
  });
};


export type LupACMEOptions = {

  /** Account identifier needed by some CAs */
  externalAccountBinding?: any,

};

class LupACME {
  #url: string;
  #options: LupACMEOptions;
  #directory: ACMEDirectory | null = null;
  #account: ACMEAccount | null = null;

  /**
   * Creates an ACME client for interacting with a CA.
   * @param ca Identifier of CA or URL of directory.
   * @param options Optional options needed by some CAs.
   */
  constructor(ca: 'letsencrypt' | string, options?: LupACMEOptions){
    switch(ca) {
      case 'letsencrypt': this.#url = 'https://acme-v02.api.letsencrypt.org/directory'; break;
      default: this.#url = ca;
    }
    this.#options = options || {};
  }

  async #getDirectory(): Promise<ACMEDirectory> {
    if(this.#directory) return this.#directory;
    this.#directory = await axios.get(this.#url).then(res => res.data).catch((err) => null) as ACMEDirectory;
    if(!this.#directory) throw new Error("Invalid directory url '"+this.#url+"'");
    return this.#directory;
  }

  async getAccount(): Promise<ACMEAccount> {
    const url = (await this.#getDirectory()).newAccount;
    
    // TODO

    throw new Error("Not implemented");
  }

}
export default LupACME;
