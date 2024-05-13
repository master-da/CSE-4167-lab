"use strict";

const { randomInt } = require("crypto");
/********* External Imports ********/

const {
  stringToBuffer,
  bufferToString,
  encodeBuffer,
  decodeBuffer,
  getRandomBytes,
} = require("./lib");
const { subtle } = require("crypto").webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
// const MASTER_PASSWORD_SALT = getRandomBytes(32); // salt for the master password
// const DOMAIN_SALT = getRandomBytes(32); // salt for the domain key
// const PASSWORD_SALT = getRandomBytes(32); // salt for the password key
const MAX_PASSWORD_LENGTH = 64; // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load.
   * Arguments:
   *  You may design the constructor with any parameters you would like.
   * Return Type: void
   */
  constructor() {
    this.data = {
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
      kvs: null,
      key_hash: null,
     
      counter: 0,
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
      master_password: null,
      master_key: null,
      domain_key: null,
      password_key: null,

      master_salt: null,
      domain_salt: null,
      password_salt: null,
    };
  }

  /**
   * Creates an empty keychain with the given password.
   *
   * Arguments:
   *   password: string
   * Return Type: void
   */
  static async init(
    password,
    master_salt = null,
    domain_salt = null,
    password_salt = null,
    password_hash = null,
  ) {
    const keychain = new Keychain();
    keychain.data.kvs = {};

    if (master_salt === null) master_salt = getRandomBytes(32);
    if (domain_salt === null) domain_salt = getRandomBytes(32);
    if (password_salt === null) password_salt = getRandomBytes(32);

    keychain.secrets.master_salt = master_salt;
    keychain.secrets.domain_salt = domain_salt;
    keychain.secrets.password_salt = password_salt;

    // Derive the master key from the password
    const master_key = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    // Derive the master key from the password
    keychain.secrets.master_key = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: keychain.secrets.master_salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      master_key,
      { name: "HMAC", hash: "SHA-256" },
      true,
      ["sign", "verify"]
    );

    // one way hash the master key for future use
    keychain.data.key_hash = await subtle.digest(
      "SHA-256",
      await subtle.exportKey("raw", keychain.secrets.master_key)
    );
    keychain.data.key_hash = encodeBuffer(keychain.data.key_hash);

    // console.log({new: keychain.data.key_hash, old: password_hash})

    if (password_hash !== null)
      if (keychain.data.key_hash !== password_hash)
        throw new Error("Invalid password");

    // Derive the domain key from the master key
    const extractedRawMasterKeyForDomain = await subtle.sign(
      "HMAC",
      keychain.secrets.master_key,
      keychain.secrets.domain_salt
    );

    keychain.secrets.domain_key = await subtle.importKey(
      "raw",
      extractedRawMasterKeyForDomain,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    // Derive the password key from the master key
    const extractedRawMasterKeyForPassword = await subtle.sign(
      "HMAC",
      keychain.secrets.master_key,
      keychain.secrets.password_salt
    );

    keychain.secrets.password_key = await subtle.importKey(
      "raw",
      extractedRawMasterKeyForPassword,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    // console.log(keychain.secrets)

    return keychain;
  }

  /**
   * Loads the keychain state from the provided representation (repr). The
   * repr variable will contain a JSON encoded serialization of the contents
   * of the KVS (as returned by the dump function). The trustedDataCheck
   * is an *optional* SHA-256 checksum that can be used to validate the
   * integrity of the contents of the KVS. If the checksum is provided and the
   * integrity check fails, an exception should be thrown. You can assume that
   * the representation passed to load is well-formed (i.e., it will be
   * a valid JSON object).Returns a Keychain object that contains the data
   * from repr.
   *
   * Arguments:
   *   password:           string
   *   repr:               string
   *   trustedDataCheck: string
   * Return Type: Keychain
   */
  static async load(password, repr, trustedDataCheck) {
    if (trustedDataCheck) {
      const checksum = await subtle.digest("SHA-256", stringToBuffer(repr));
      const checksumString = encodeBuffer(checksum);
      if (checksumString !== trustedDataCheck) {
        throw new Error("Integrity check failed");
      }
    }

    const data = JSON.parse(repr);

    const master_salt = Buffer.from(Object.values(data.master_salt));
    const domain_salt = Buffer.from(Object.values(data.domain_salt));
    const password_salt = Buffer.from(Object.values(data.password_salt));
    const password_hash = data.key_hash;
    const kvs = data.kvs;

    // console.log(password_salt);


    if (
      master_salt === undefined ||
      domain_salt === undefined ||
      password_salt === undefined ||
      password_hash == undefined ||
      kvs === undefined
    ) {
      throw new Error("Invalid data");
    }

    const keychain = await Keychain.init(
      password,
      master_salt,
      domain_salt,
      password_salt,
      password_hash
    );
    keychain.data.kvs = kvs;
    return keychain;
  }

  /**
   * Returns a JSON serialization of the contents of the keychain that can be
   * loaded back using the load function. The return value should consist of
   * an array of two strings:
   *   arr[0] = JSON encoding of password manager
   *   arr[1] = SHA-256 checksum (as a string)
   * As discussed in the handout, the first element of the array should contain
   * all of the data in the password manager. The second element is a SHA-256
   * checksum computed over the password manager to preserve integrity.
   *
   * Return Type: array
   */
  async dump() {

    // Remove the dummy password entries.
    while (true) {
      let v = await this.remove("dummy.com");

      if (v === false) break;
      // keep removing
    }

    const reprData = {
      master_salt: this.secrets.master_salt,
      domain_salt: this.secrets.domain_salt,
      password_salt: this.secrets.password_salt,
      key_hash: this.data.key_hash,
      kvs: this.data.kvs,
    };


    const repr = JSON.stringify(reprData);

    const checksum = await subtle.digest("SHA-256", stringToBuffer(repr));
    const checksumString = encodeBuffer(checksum);

    return [repr, checksumString];
  }

  /**
   * Fetches the data (as a string) corresponding to the given domain from the KVS.
   * If there is no entry in the KVS that matches the given domain, then return
   * null.
   *
   * Arguments:
   *   name: string
   * Return Type: Promise<string>
   */
  async get(name) {
    // console.log("gettin", name)

    let secureDomain = await subtle.sign(
      "HMAC",
      this.secrets.domain_key,
      stringToBuffer(name)
    );
    secureDomain = encodeBuffer(secureDomain);

    // console.log({domain: secureDomain, password: this.data.kvs[secureDomain]})

    if (this.data.kvs[secureDomain] === undefined) return null;

    const encryptedPassword = this.data.kvs[secureDomain];
    const iv = encryptedPassword.slice(0, 32);
    const encrypted = encryptedPassword.slice(32);

    const decryptedPassword = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: decodeBuffer(iv),
      },
      this.secrets.password_key,
      decodeBuffer(encrypted)
    );

    const password = bufferToString(decryptedPassword);

    const secureDomainIndex = password.indexOf(secureDomain);
    if (secureDomainIndex === -1) {
      console.log("Possible Swap Attack");
      return null;
    }
    return password.slice(0, secureDomainIndex);
  }

  /**
   * Inserts the domain and associated data into the KVS. If the domain is
   * already in the password manager, this method should update its value. If
   * not, create a new entry in the password manager.
   *
   * Arguments:
   *   name: string
   *   value: string
   * Return Type: void
   */
  async set(name, value) {
    let counter = this.data.counter;
    counter += 1;

    let secureDomain = await subtle.sign(
      "HMAC",
      this.secrets.domain_key,
      stringToBuffer(name)
    );
    secureDomain = encodeBuffer(secureDomain);

    const securePassword =
      value + secureDomain + encodeBuffer(getRandomBytes(randomInt(32, 64)));
    const iv = getRandomBytes(24);
    let encryptedPassword = await subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
      },
      this.secrets.password_key,
      stringToBuffer(securePassword)
    );

    encryptedPassword = encodeBuffer(iv) + encodeBuffer(encryptedPassword);

    // console.log({secureDomain, encryptedPassword})

    this.data.kvs[secureDomain] = encryptedPassword;

    if (randomInt(10) % 2 === 1) {
      this.set("dummy.com", "dummy|password");
    }

    // console.log(this.data.kvs)
  }

  /**
   * Removes the record with name from the password manager. Returns true
   * if the record with the specified name is removed, false otherwise.
   *
   * Arguments:
   *   name: string
   * Return Type: Promise<boolean>
   */
  async remove(name) {
    let secureDomain = await subtle.sign(
      "HMAC",
      this.secrets.domain_key,
      stringToBuffer(name)
    );
    secureDomain = encodeBuffer(secureDomain);

    if (this.data.kvs[secureDomain] !== undefined) {
      delete this.data.kvs[secureDomain];
      return true;
    }

    return false;
  }
}

async function driver() {
  // // RUN THE FOLLOPWING DRIVERS TO GENERATE A NEW CHAIN WITH A PASSWORD AND ADD DATA TO IT.
  // const keychain = await Keychain.init("password")
  // await keychain.set("google.com", "hippity_hoppity")
  // await keychain.set("gaggle.com", "dickity_duckity")
  // await keychain.set("oogle.com", "creepity_croppity")
  // await keychain.set("moodle.com", "idkwhatmoodleevendoes")
  // const password1 = await keychain.get("google.com")
  // const password2 = await keychain.get("gaggle.com")
  // const password3 = await keychain.get("oogle.com")
  // const password4 = await keychain.get("moodle.com")
  // // console.log({password1, password2, password3, password4})
  // await keychain.remove("google.com")
  // const password5 = await keychain.get("google.com")
  // // console.log({password5})
  // // THIS BIT DUMPS DATA TO MEMORY. NOT REALLY LOL BUT WELP
  // const [repr, checksum] = await keychain.dump()
  // console.log({repr, checksum})
  // // THIS BIT LOADS DATA FROM MEMORY. YOU HAVE TO MANUALLY COPY PASTE THE OUTPUT FROM THE LAST RESULT TO HERE
  // const keychain = await Keychain.load("password",
  // '{"kvs":{"wxt6rclQLHqpYdVYEwOWwI3eId3mj6UCreqDAaiwJW0=":"uYP+7MFs6fgFyqsIfIv1UM0jLPTAyyl2RPanJy2GEA5Ev0frYLjDUgLXF4V4V5M0lwthuy7feVqv708ttHaJ61iEHklaI2IB6iATbCTr+JLtWwsr5JKElswUbaAUlN86zSj43fzjlPfiDxJrikV73w/5SfHBIRegT6nxu8Btf+71PcCtadZpJ2wydfdQeqYdmo7d6gGQCg==","XGBX/3tCUj2ZPDjXwxin/6/3wgACVnMxsprevoNFul8=":"3U2GFwzm6MIWAt2fnXbPyX0hD7ZQlR80bg56DAUhpCtvOzOy+1UtkMQnkaKf2VSFOr/+4eujzjBh1a+BSKm8uneBfXNpfT75GN7FbMR3GNRJ7anY7ORJUOTXbpJEJ6vb5FKfDj5wqIi3dxigHfxEp/jmrCcTHFccA6ZXJBDTPCdkMj7OXWGivJgHiOmS5sueo+nrE5Wkms2pkTDtnA==","vPNGniOUl15e6HAJJfTuEG6fwHGKybRNEBZFDwfwccs=":"3m6GL++czjX8D4LkMMi8z57Gc6CF+UU/Hx6z7yRQlPGYlS3Bn8hdC9tqd2Thq2mB3iJrCmbzEyguCRV5YifSBr7Byr1grGLYIfE/klpDjjQwyzuLVPR7n5kcKMA0/Q1/ex1y693sXsMjIYV1PMFKYfz7HWEdusEbDPo5Ni3TYRflXeo+3sa7r/Kh+GC3L60MToKs9XxSpyUz0JGcGRNT4dC2hETntgzHGtzK8A5t8l9vbjTg2g=="},"key_hash":"PqVbq5/GhnETp79mSlj8UhjXgLEDPsgmRCD/s/MNoe8=","master_salt":{"0":1,"1":220,"2":189,"3":182,"4":20,"5":212,"6":114,"7":188,"8":42,"9":136,"10":201,"11":206,"12":107,"13":247,"14":230,"15":169,"16":203,"17":112,"18":98,"19":201,"20":236,"21":116,"22":43,"23":124,"24":203,"25":122,"26":218,"27":145,"28":119,"29":193,"30":119,"31":246},"domain_salt":{"0":62,"1":41,"2":71,"3":81,"4":77,"5":248,"6":181,"7":142,"8":180,"9":174,"10":127,"11":247,"12":147,"13":134,"14":239,"15":67,"16":140,"17":54,"18":154,"19":80,"20":128,"21":198,"22":144,"23":201,"24":162,"25":229,"26":101,"27":132,"28":250,"29":111,"30":237,"31":127},"password_salt":{"0":113,"1":97,"2":153,"3":82,"4":9,"5":181,"6":35,"7":108,"8":93,"9":149,"10":123,"11":96,"12":34,"13":100,"14":199,"15":66,"16":89,"17":149,"18":26,"19":173,"20":188,"21":18,"22":179,"23":96,"24":37,"25":222,"26":54,"27":193,"28":219,"29":217,"30":186,"31":221}}',
  // 'Iz5Zow0Y1lMea07MvL7QWpxUPRGH/iHcq38BZKqBPGo=')
  // // console.log(keychain.data)
  // const password1 = await keychain.get("google.com")
  // const password2 = await keychain.get("gaggle.com")
  // const password3 = await keychain.get("oogle.com")
  // console.log({password1, password2, password3})
}

driver();

module.exports = { Keychain };