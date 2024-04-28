"use strict";

const { randomInt } = require("crypto");
/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
// const MASTER_PASSWORD_SALT = getRandomBytes(32); // salt for the master password
// const DOMAIN_SALT = getRandomBytes(32); // salt for the domain key
// const PASSWORD_SALT = getRandomBytes(32); // salt for the password key
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

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
      master_salt: null,
      domain_salt: null,
      password_salt: null,
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
      master_password: null,
      master_key: null,
      domain_key: null,
      password_key: null,
    };

    
  };

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  async init(password, master_salt = null, domain_salt = null, password_salt = null) {

    this.data.kvs = {}

    if (master_salt === null) master_salt = getRandomBytes(32)
    if (domain_salt === null) domain_salt = getRandomBytes(32)
    if (password_salt === null) password_salt = getRandomBytes(32)

    this.data.master_salt = master_salt
    this.data.domain_salt = domain_salt
    this.data.password_salt = password_salt

    // Derive the master key from the password
    const master_key = await subtle.importKey(
      "raw",
      stringToBuffer(password),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    // Derive the master key from the password
    this.secrets.master_key = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: this.data.master_salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      master_key,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ["sign", "verify"]
    );

    // Derive the domain key from the master key
    const extractedRawMasterKeyForDomain = await subtle.sign("HMAC", this.secrets.master_key, this.data.domain_salt)

    this.secrets.domain_key = await subtle.importKey(
      "raw",
      extractedRawMasterKeyForDomain,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ["sign"]
    )

    // Derive the password key from the master key
    const extractedRawMasterKeyForPassword = await subtle.sign("HMAC", this.secrets.master_key, this.data.password_salt)

    this.secrets.password_key = await subtle.importKey(
      "raw",
      extractedRawMasterKeyForPassword,
      { name: 'AES-GCM', length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
    
    // console.log(this.secrets)

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
  async load(password, repr, trustedDataCheck) {
    if (trustedDataCheck) {
      const checksum = await subtle.digest("SHA-256", stringToBuffer(repr))
      const checksumString = encodeBuffer(checksum)
      if (checksumString !== trustedDataCheck) {
        throw new Error("Integrity check failed")
      }
    }

    const data = JSON.parse(repr)
    
    const [master_salt, domain_salt, password_salt, kvs] = [Buffer.from(Object.values(data.master_salt)), Buffer.from(Object.values(data.domain_salt)), Buffer.from(Object.values(data.password_salt)), data.kvs]
    if (master_salt === undefined || domain_salt === undefined || password_salt === undefined || kvs === undefined) {
      throw new Error("Invalid data")
    }
    
    await this.init(password, master_salt, domain_salt, password_salt)
    this.data.kvs = kvs

  };

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
    const repr = JSON.stringify(this.data)

    const checksum = await subtle.digest("SHA-256", stringToBuffer(repr))
    const checksumString = encodeBuffer(checksum)

    return [repr, checksumString]
  };

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
    
    let secureDomain = await subtle.sign("HMAC", this.secrets.domain_key, stringToBuffer(name))
    secureDomain = encodeBuffer(secureDomain)

    console.log({domain: secureDomain, password: this.data.kvs[secureDomain]})
    
    if (this.data.kvs[secureDomain] === undefined) return null

    const encryptedPassword = this.data.kvs[secureDomain]
    const iv = encryptedPassword.slice(0, 32)
    const encrypted = encryptedPassword.slice(32)

    const decryptedPassword = await subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: decodeBuffer(iv)
      },
      this.secrets.password_key,
      decodeBuffer(encrypted)
    )

    const password = bufferToString(decryptedPassword)
    
    const secureDomainIndex = password.indexOf(secureDomain)
    if (secureDomainIndex === -1) {
      console.log("Possible Swap Attack")
      return null
    }
    return password.slice(0, secureDomainIndex)
  };

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
    let secureDomain = await subtle.sign("HMAC", this.secrets.domain_key, stringToBuffer(name))
    secureDomain = encodeBuffer(secureDomain)

    const securePassword = value + secureDomain + encodeBuffer(getRandomBytes(randomInt(32, 64)))
    const iv = getRandomBytes(24)
    let encryptedPassword = await subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      this.secrets.password_key,
      stringToBuffer(securePassword)
    )

    encryptedPassword = encodeBuffer(iv) + encodeBuffer(encryptedPassword)

    // console.log({secureDomain, encryptedPassword})

    this.data.kvs[secureDomain] = encryptedPassword

    // console.log(this.data.kvs)
  };

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<boolean>
  */
  async remove(name) {
    let secureDomain = await subtle.sign("HMAC", this.secrets.domain_key, stringToBuffer(name))
    secureDomain = encodeBuffer(secureDomain)
    if (this.data.kvs[secureDomain] !== undefined) 
      delete this.data.kvs[secureDomain];
  };
};

async function driver() {
  const keychain = new Keychain();


  // RUN THE FOLLOPWING DRIVERS TO GENERATE A NEW CHAIN WITH A PASSWORD AND ADD DATA TO IT.
  // await keychain.init("password")
  // await keychain.set("google.com", "hippity_hoppity")
  // await keychain.set("gaggle.com", "dickity_duckity")
  // await keychain.set("oogle.com", "creepity_croppity")
  // await keychain.set("moodle.com", "idkwhatmoodleevendoes")
  // const password1 = await keychain.get("google.com")
  // const password2 = await keychain.get("gaggle.com")
  // const password3 = await keychain.get("oogle.com")
  // const password4 = await keychain.get("moodle.com")
  // console.log({password1, password2, password3, password4})

  // await keychain.remove("google.com")
  // const password5 = await keychain.get("google.com")
  // console.log({password5})
  
  // // THIS BIT DUMPS DATA TO MEMORY. NOT REALLY LOL BUT WELP
  // const [repr, checksum] = await keychain.dump()
  // console.log({repr, checksum})

  // THIS BIT LOADS DATA FROM MEMORY. YOU HAVE TO MANUALLY COPY PASTE THE OUTPUT FROM THE LAST RESULT TO HERE
  await keychain.load("password", 
  '{"kvs":{"WE9At3AkfbQHWhNCqUWAFlvH4qoP7824DTpOB4Yf1oU=":"8K8j4vnB9xb9esuQIownF+amKdal5SewTvingmm4XO4S5phApAd/sctdxojqnqJ/H//2B+I9uSFhCTyM0dlZESQpgt9ZoIxaC6PJTgPn6tGpCqaE6LSlgz7JZVgEyWpsAy+vQnh5whJefvJPceG6L0u86fq3rp8ykUiY6cT+CwXwYvCrHjjDz+x/H/F4fR6iLPQzUbzUWaQRrqO1ovsDpufG4A==","t873orEbvG3Hv3MsPv6AwOAEN2kTNnn7Qiu1uZTEJck=":"5ZghlfiF9j3TEEshgCoGOrCeeaWTs1DTnrmlmsukIpsxEP7BD8+c/IMNSekoR4Cxij1J27q54YkS8f5g5hvQ59Q8ho+yEIprMBZsGOvLFCqpXSZX0dT2/Qk47VIvFFhb443zN1i5Ij9yvIQqG4VkIDgQsU4SQR6lwvN2wQq002wcGwvqQ1j6fkZjHstrboCnyQ6Rzs6lH5UT","VhSGNx0Q+3bW+k0ElLaSRrOUPeuJ88lkLU/uIDYfluM=":"2bxZKayDfT1/FcYOapXxEsyA/WhwpGz1pQXIQH2nRpz3/7Qj9vqgpsD3F8RUlycd2cwM8jP0Sv9/X2ExTzIG/6JdyHn3FDaplnprWBjgq7/asW926GxP5XO1Z2dB2N5ob04T7O3CtL4wSTp9Heib+y/8tlrVw3FUE84Nvi5ghGQvDvAWC74r/Hpx5cxjUZX8NV5aSSKPbGmj/FDTLk+Iq9lvZk1zxl/rDsIfhCN01iEyhyOVC9ky1Lg="},"master_salt":{"0":236,"1":209,"2":220,"3":127,"4":129,"5":191,"6":27,"7":240,"8":245,"9":128,"10":170,"11":69,"12":145,"13":167,"14":184,"15":35,"16":205,"17":65,"18":106,"19":182,"20":135,"21":100,"22":244,"23":76,"24":219,"25":34,"26":94,"27":228,"28":171,"29":238,"30":133,"31":90},"domain_salt":{"0":64,"1":167,"2":146,"3":209,"4":44,"5":195,"6":198,"7":24,"8":39,"9":203,"10":174,"11":242,"12":232,"13":9,"14":76,"15":68,"16":89,"17":189,"18":107,"19":67,"20":128,"21":62,"22":245,"23":178,"24":226,"25":185,"26":224,"27":158,"28":85,"29":198,"30":217,"31":182},"password_salt":{"0":190,"1":153,"2":114,"3":223,"4":74,"5":154,"6":191,"7":117,"8":198,"9":148,"10":187,"11":84,"12":68,"13":172,"14":97,"15":87,"16":8,"17":5,"18":40,"19":91,"20":175,"21":248,"22":200,"23":156,"24":36,"25":102,"26":85,"27":241,"28":138,"29":211,"30":164,"31":75}}',
  'tVNGoKN0KRS9eJRQGRm/jGqRrL/MxRALNvUWQ2XYi/c=')
  console.log(keychain.data)
  const password1 = await keychain.get("google.com")
  console.log({password1})
  const password2 = await keychain.get("gaggle.com")
  const password3 = await keychain.get("oogle.com")
  console.log({password1, password2, password3})

}

driver()

module.exports = { Keychain }
