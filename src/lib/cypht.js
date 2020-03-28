import BigInteger from 'big-integer';
import { Buffer } from 'buffer';
import { AesCtr } from './AES';
import { CyphtPrivateKey, CyphtPublicKey } from './CyphtKeys';

//Byte array functions for control bytes on cyphts
function longToByteArray(long) {
    // we want to represent the input as a 2-bytes array
    var byteArray = [0, 0];
    for ( var index = 0; index < byteArray.length; index ++ ) {
        var byte = long & 0xff;
        byteArray [ index ] = byte;
        long = (long - byte) / 256 ;
    }
    return byteArray;
};

function byteArrayToLong(byteArray) {
    var value = 0;
    for ( var i = byteArray.length - 1; i >= 0; i--) {
        value = (value * 256) + byteArray[i];
    }
    return value;
};

// Encrypt from public/private key
function encrypt(inBuffer, key) {
  return new Promise( (resolve, reject) => {
    const m = BigInteger.fromArray([...inBuffer], 256);
    const c = key.crypt(m);
    resolve(new Buffer.from(c.toArray(256).value, 256));
  });
}

// Decrypt from private key
function decrypt(enc, key) {
  return new Promise( (resolve, reject) => {
    let c = new BigInteger.fromArray([...enc], 256);
    let m = key.crypt(c);
    if(m == null) reject();
    resolve(new Buffer.from(m.toArray(256).value, 256));
  });
}

const encypht = (original, key) => {
  return new Promise( (resolve, reject) => {
    const password = key.randomToken();
    const omessage = Buffer.from(original);
    const encMessage = new Buffer.from(AesCtr.encrypt(omessage, password, 256));
    encrypt(password, key).then( encPassword => {
      const outLength = encMessage.length + encPassword.length + 2;
      const lengthToken = encPassword.length;
      const lengthBytes = longToByteArray(lengthToken);
      resolve(Buffer.concat([ Buffer.from(lengthBytes), encPassword, encMessage ], outLength));
    });
  });
};

const decypht = (cypht, key) => {
  return new Promise( (resolve, reject) => {
    let tokenLength = byteArrayToLong([cypht[0], cypht[1]]);
    const token = cypht.slice( 2, tokenLength+2 );
    decrypt(token, key).then( pass => {
      const message = cypht.slice(tokenLength+2);
      const dmessage = AesCtr.decrypt(message, pass, 256);
      resolve(dmessage);
    });
  });
};

const generateKeys = (options={}) => {
  return new Promise( (resolve, reject) => {
    const privateKey = new CyphtPrivateKey(options);
    privateKey.generate().then( success => {
      const publicKey = privateKey.publicKey();
      resolve({
        privateKey,
        publicKey
      });
    });
  });
};

export {
  generateKeys,
  encypht,
  decypht,
  CyphtPrivateKey,
  CyphtPublicKey
};
