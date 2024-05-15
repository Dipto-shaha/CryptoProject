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
  generateECDSA,
  signWithECDSA,
  govEncryptionDataStr
} = require('./lib')


const generateKeyPairAuthority = async() =>{
  let signingKey = generateECDSA();
  return signingKey;
}
const authKeyPair = generateKeyPairAuthority();

const signWithAuthSecKey = async (clientPubKey) => {
  let signedKey = await signWithECDSA((await authKeyPair).sec,clientPubKey);
  return signedKey;
}
let dataStructure = {};

const question1 = async (entityName, clientPubKey) => {
  let signedKey = signWithAuthSecKey(clientPubKey);
  dataStructure[entityName] = signedKey;
}

let clientName = "Sourove";
let clientKey = generateEG();


let clientName1 = "Sourove1";
let clientKey1 = generateEG();

let clientName2 = "Sourove2";
let clientKey2 = generateEG();

question1(clientName, (clientKey.pub));
question1(clientName1, (clientKey1.pub));
question1(clientName2, (clientKey2.pub));

console.log(dataStructure);


const entityQuery = async (clientNameReceived, clientKeyReceived) => {
  let clientsPubKey = dataStructure[clientNameReceived];
  
  let success = await verifyWithECDSA(authKeyPair.pub, clientsPubKey, clientKeyReceived);
  return success;
}


console.log(entityQuery(clientName1, clientKey1))