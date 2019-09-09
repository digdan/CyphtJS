import BigInteger from 'big-integer';
import { Buffer } from 'buffer';
import { AesCtr } from './AES';
import { CyphtPrivateKey, CyphtPublicKey } from './CyphtKeys';
import { pkcs1pad2, pkcs1unpad2 } from './pkcs1';
import prng from './prng';

//import baseConverter from './baseConverter';

const EXPON = 65537; // Default cryptographic exponent
const KEYSIZE = 64; //In Bytes
const PRIMECHECK = 1; // Certainty of a prime
const TOKENSIZE = 32; //In Bytes - Token assymetrically encryted and used for AES cipher Password

// Key generation
const generateKeys = (keySize=KEYSIZE, exponent=EXPON) => {
  return new Promise( (resolve, reject) => {
    const privateKey = new CyphtPrivateKey();
    const qs = keySize >> 1;
    privateKey.e = parseInt(exponent, 16);
    const ee = new BigInteger(exponent, 16);
    for(;;) {
      for(;;) {
        //Populate a big int with random bytes
        privateKey.p = new BigInteger(prng(keySize - qs).join(''), 16);
        while(!privateKey.p.isProbablePrime(PRIMECHECK)) { //Is this random number prime?
          privateKey.p = new BigInteger(prng(keySize - qs).join(''), 16);
        }
        privateKey.p.subtract(BigInteger.one);
        if (BigInteger.gcd(privateKey.p, ee).compareTo(BigInteger.one) === 0 && privateKey.p.isProbablePrime(PRIMECHECK)) break;
      }
      for(;;) {
        privateKey.q = new BigInteger(prng(qs).join(''), 16);
        while(!privateKey.q.isProbablePrime(PRIMECHECK)) {
          privateKey.q = new BigInteger(prng(qs).join(''), 16);
        }
        privateKey.q.subtract(BigInteger.one);
        if (BigInteger.gcd(privateKey.q, ee).compareTo(BigInteger.one) === 0 && privateKey.q.isProbablePrime(PRIMECHECK)) break;
      }
      if (privateKey.p.compareTo(privateKey.q) <= 0) {
        const t = privateKey.p;
        privateKey.p = privateKey.q;
        privateKey.q = t;
      }
      const p1 = privateKey.p.subtract(BigInteger.one);
      const q1 = privateKey.q.subtract(BigInteger.one);
      const phi = p1.multiply(q1);
      if (BigInteger.gcd(phi, ee).compareTo(BigInteger.one) === 0) {
        privateKey.n = privateKey.p.multiply(privateKey.q);
        privateKey.d = ee.modInv(phi);
        privateKey.dmp1 = privateKey.d.mod(p1);
        privateKey.dmq1 = privateKey.d.mod(q1);
        privateKey.coeff = privateKey.q.modInv(privateKey.p);
        break;
      }
    }
    const publicKey = privateKey.publicKey();
    resolve({
      publicKey,
      privateKey
    })
  });
}

// Encrypt from public/private key
function encrypt(inBuffer, key) {
  var m = pkcs1pad2(inBuffer, (key.n.bitLength()+7) >> 3);
  if(m == null) return null;
  var c = key.crypt(m);
  if(c == null) return null;
  return new Buffer.from(c.toArray(256).value);
}

// Decrypt from private key
function decrypt(enc, key) {
  var c = new BigInteger.fromArray([...enc], 256);
  var m = key.crypt(c);
  if(m == null) return null;
  return pkcs1unpad2(m, (key.n.bitLength()+7)>>3);
}

const encypht = (original, publicKey) => {
  const password = Buffer.from(prng(TOKENSIZE).map( chr => {
    return chr.toString()
  }));
  const omessage = Buffer.from(original);
  const encMessage = new Buffer.from(AesCtr.encrypt(omessage, password, 256));
  const encPassword = encrypt(password, publicKey);
  const outLength = encMessage.length + encPassword.length + 1;
  return Buffer.concat([ Buffer.from([encPassword.length]), encPassword, encMessage ], outLength);
}

const decypht = (cypht, privateKey) => {
  const tokenLength = cypht[0];
  const token = cypht.slice( 1, tokenLength+1 );
  const pass = decrypt(token, privateKey);
  const message = cypht.slice(tokenLength+1);
  const dmessage = AesCtr.decrypt(message, pass, 256);
  return dmessage;
}

export {
  generateKeys,
  encypht,
  decypht
}
