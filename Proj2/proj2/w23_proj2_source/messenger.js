'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  byteArrayToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/

class MessengerClient {
  constructor (certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate (username) {
    this.EGKeyPair = await generateEG();
    const certificate = {
      username: username,
      publicKeyJSON: await cryptoKeyToJSON(this.EGKeyPair.pub),
      publicKey: this.EGKeyPair.pub
    };
    return certificate;
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: string
 *
 * Return Type: void
 */
  async receiveCertificate (certificate, signature) {
  // The signature will be on the output of stringifying the certificate
  // rather than on the certificate directly.
  const certString = JSON.stringify(certificate);
  const verification = await verifyWithECDSA(this.caPublicKey, certString, signature);
  if (!verification) {
    throw ("This is not a valid certificate!");
  }

  this.certs[certificate.username] = certificate;
    // throw ('not implemented!')
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, string]
 */
  async sendMessage (name, plaintext) {
    

    
    // throw ('not implemented!')
    if (!(name in this.conns)) { 
      const initialRootKey = await computeDH(this.EGKeyPair.sec, this.certs[name].publicKey);

      const dhs = await generateEG();
      const dhsOutput = await computeDH(dhs.sec, this.certs[name].publicKey);

      const [rk, cks] = await HKDF(initialRootKey, dhsOutput,"ratchet-str");

      this.conns[name] = {
        DHs: dhs,
        DHr: this.certs[name].publicKey,
        RK: rk,
        CKs: cks,
        CKr: null,
        Ns : 0,
        Nr : 0,
      };
    }

    const connection = this.conns[name];
    if (connection.CKs === null) {
      const initialRootKey = await computeDH(this.EGKeyPair.sec, this.certs[name].publicKey);

      const dhs = await generateEG();
      const dhsOutput = await computeDH(dhs.sec, this.certs[name].publicKey);

      const [rk, cks] = await HKDF(initialRootKey, dhsOutput, "ratchet-str");
      connection.DHs = dhs;
      connection.CKs = cks;
      connection.RK = rk
    }
    // const [CKs,mk] = await HKDF(connection.CKs, connection.RK, "ratchet-str");
    const CKs = await HMACtoHMACKey(connection.CKs,"chainKey")
    const mk = await HMACtoAESKey(connection.CKs, "messageKey");
    const mkBuf = await HMACtoAESKey(connection.CKs, "messageKey", true);
    connection.CKs = CKs;

    const iv = genRandomSalt();

    const ivGov = genRandomSalt();
    const dhGov = await generateEG();

    const sharedGovKey = await computeDH(dhGov.sec, this.govPublicKey);
    const aesKeyGov = await HMACtoAESKey(sharedGovKey, govEncryptionDataStr);
    const cGov = await encryptWithGCM(aesKeyGov, mkBuf, ivGov)

    const header = {
      DH: connection.DHs.pub,
      receiverIV: iv,
      vGov: dhGov.pub,
      cGov: cGov,
      ivGov: ivGov,
    }
    connection.Nr += 1
    const ciphertext = await encryptWithGCM(mk, plaintext, iv, JSON.stringify(header));
    return [header, ciphertext]

  }

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, string]
 *
 * Return Type: string
 */
  async receiveMessage (name, [header, ciphertext]) {
    if (!(name in this.conns)) { 
      const initialRootKey = await computeDH(this.EGKeyPair.sec, this.certs[name].publicKey);
      const dhOutputOne = await computeDH(this.EGKeyPair.sec, header.DH);
      const [rk, ckr] = await HKDF(initialRootKey, dhOutputOne,"ratchet-str");

      this.conns[name] = {
        DHs: this.EGKeyPair,
        DHr: header.DH,
        RK: initialRootKey,
        CKs: null,
        CKr: ckr,
        Ns : 0,
        Nr : 0,
        RK : rk
      };

    }
    let connection = this.conns[name];
    if (connection.CKr === null) {
      const initialRootKey = await computeDH(this.EGKeyPair.sec, this.certs[name].publicKey);
      const dhOutputOne = await computeDH(this.EGKeyPair.sec, header.DH);
      const [rk, ckr] = await HKDF(initialRootKey, dhOutputOne,"ratchet-str");
      connection.CKr = ckr;
      connection.DHr = header.DH;
      connection.RK = rk
    }

    if (header.DH !== connection.DHr)
    {
      connection.DHr = header.DH;
      connection.DHs = this.EGKeyPair;
      const [rk, ckr] = await HKDF(connection.RK, await computeDH(connection.DHs.sec, connection.DHr),"ratchet-str");
      connection.CKr = ckr;
      connection.RK = rk
      // connection.DHs = await generateEG();
      // const [rks, cks] = await HKDF(connection.RK, await computeDH(connection.DHs.sec, connection.DHr),"ratchet-str");
      // connection.CKs = cks;
    }
    const CKr = await HMACtoHMACKey(connection.CKr,"chainKey")
    const mk = await HMACtoAESKey(connection.CKr, "messageKey");
    // const mkBuf = await HMACtoAESKey(connection.CKr, "messageKey", true);
    connection.CKr = CKr
    connection.Nr += 1
    try {
      const plaintext = byteArrayToString(await decryptWithGCM(mk, ciphertext, header.receiverIV, JSON.stringify(header)));
      this.conns[name] = {...connection};
      return plaintext;
    } catch (err) {
      throw ("Message integrity check failed");
    }
  }
};

module.exports = {
  MessengerClient
}
