import BigInteger from 'big-integer';
import { Buffer } from 'buffer';
import { AesCtr } from './AES';
import { CyphtPrivateKey, CyphtPublicKey } from './CyphtKeys';
import baseConverter from './baseConverter';

const EXPON = 65537; // Default cryptographic exponent
const KEYSIZE = 64; //In Bytes
const PRIMECHECK = 1; // Certainty of a prime
const TOKENSIZE = 32; //In Bytes - Token assymetrically encryted and used for AES cipher Password

//Psudo Random Number Generator -- in hex
const prng = len => Array(len)
  .fill()
  .map(() => parseInt((Math.round(Math.random() * 256))).toString(16));


// Turns integer into text
const pkcs1unpad2 = (d, n) => {
  var b = d.toArray(256).value;
  var i = 0;
  while(i < b.length && b[i] == 0) ++i;
  if(b.length-i != n-1 || b[i] != 2) {
    console.log('bad decrypt input');
    return null;
  }
  ++i;
  while(b[i] != 0)
    if(++i >= b.length) return null;
  var ret = "";
  while(++i < b.length) {
    var c = b[i] & 255;
    if(c < 128) { // utf-8 decode
      ret += String.fromCharCode(c);
    }
    else if((c > 191) && (c < 224)) {
      ret += String.fromCharCode(((c & 31) << 6) | (b[i+1] & 63));
      ++i;
    }
    else {
      ret += String.fromCharCode(((c & 15) << 12) | ((b[i+1] & 63) << 6) | (b[i+2] & 63));
      i += 2;
    }
  }
  return ret;
}

// Turns text into an integer
const pkcs1pad2 = (s, n) => {
  if(n < s.length + 11) { // TODO: fix for utf-8
    console.log("Message too long for RSA");
    return null;
  }
  var ba = new Array();
  var i = s.length - 1;
  while(i >= 0 && n > 0) {
    var c = s.charCodeAt(i--);
    if(c < 128) { // encode using utf-8
      ba[--n] = c;
    } else if((c > 127) && (c < 2048)) {
      ba[--n] = (c & 63) | 128;
      ba[--n] = (c >> 6) | 192;
    } else {
      ba[--n] = (c & 63) | 128;
      ba[--n] = ((c >> 6) & 63) | 128;
      ba[--n] = (c >> 12) | 224;
    }
  }
  ba[--n] = 0;
  var x = new Array();
  while(n > 2) { // random non-zero pad
    x[0] = 0;
    while(x[0] == 0) x[0] = (parseInt(prng(1)[0], 16) | 1);
    ba[--n] = x[0];
  }
  ba[--n] = 2;
  ba[--n] = 0;
  return new BigInteger.fromArray(ba, 256);
}

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
function encrypt(text, key) {
  var m = pkcs1pad2(text, (key.n.bitLength()+7) >> 3);
  if(m == null) return null;
  var c = key.crypt(m);
  if(c == null) return null;
  return baseConverter.encode(new Buffer(c.toArray(256).value));
}

// Decrypt from private key
function decrypt(enc, key) {
  var c = new BigInteger.fromArray([...baseConverter.decode(enc)], 256);
  var m = key.crypt(c);
  if(m == null) return null;
  return pkcs1unpad2(m, (key.n.bitLength()+7)>>3);
}

const encypht = (original, publicKey) => {
  const password = prng(TOKENSIZE).map( chr => {
    return String.fromCharCode(chr);
  }).join('');
  const encMessage = AesCtr.encrypt(original, password, 256);
  const encPassword = encrypt(password, publicKey);
  return [encPassword, baseConverter.encode(new Buffer(encMessage))].join('.');
}

const decypht = (cypht, privateKey) => {
  const cyphtp = cypht.split('.');
  const pass = decrypt(cyphtp[0], privateKey);
  return AesCtr.decrypt(baseConverter.decode(cyphtp[1]).toString(), pass, 256);
}

export {
  generateKeys,
  encypht,
  decypht
}
