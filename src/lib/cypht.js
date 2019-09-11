import BigInteger from 'big-integer';
import { Buffer } from 'buffer';
import { AesCtr } from './AES';
import { CyphtPrivateKey, CyphtPublicKey } from './CyphtKeys';
import { pkcs1pad2, pkcs1unpad2 } from './pkcs1';
import prng from './prng';

// Encrypt from public/private key
function encrypt(inBuffer, key) {
  let m = pkcs1pad2(inBuffer, (key.n.bitLength()+7) >> 3);
  if(m == null) return null;
  let c = key.crypt(m);
  if(c == null) return null;
  return new Buffer.from(c.toArray(256).value);
}

// Decrypt from private key
function decrypt(enc, key) {
  let c = new BigInteger.fromArray([...enc], 256);
  let m = key.crypt(c);
  if(m == null) return null;
  return pkcs1unpad2(m, (key.n.bitLength()+7)>>3);
}

const encypht = (original, publicKey) => {
  const password = Buffer.from(prng(publicKey.options.tokenSize).map( chr => {
    return chr.toString();
  }));
  const omessage = Buffer.from(original);
  const encMessage = new Buffer.from(AesCtr.encrypt(omessage, password, 256));
  const encPassword = encrypt(password, publicKey);
  const outLength = encMessage.length + encPassword.length + 1;
  return Buffer.concat([ Buffer.from([encPassword.length]), encPassword, encMessage ], outLength);
};

const decypht = (cypht, privateKey) => {
  const tokenLength = cypht[0];
  const token = cypht.slice( 1, tokenLength+1 );
  const pass = decrypt(token, privateKey);
  const message = cypht.slice(tokenLength+1);
  const dmessage = AesCtr.decrypt(message, pass, 256);
  return dmessage;
};

const generateKeys = (options={}) => {
  return new Promise( (resolve, reject) => {
    const privateKey = new CyphtPrivateKey(options);
    privateKey.generate().then( () => {
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
