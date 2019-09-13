'use strict';

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

var BigInteger = _interopDefault(require('big-integer'));
var buffer = require('buffer');

class Aes {
  static cipher(input, w) {
    const Nb = 4;
    const Nr = w.length/Nb - 1;
    let state = [ [], [], [], [] ];
    for (let i=0; i<4*Nb; i++) {
      state[i%4][Math.floor(i/4)] = input[i];
    }
    state = Aes.addRoundKey(state, w, 0, Nb);
    for (let round=1; round<Nr; round++) {
      state = Aes.subBytes(state, Nb);
      state = Aes.shiftRows(state, Nb);
      state = Aes.mixColumns(state, Nb);
      state = Aes.addRoundKey(state, w, round, Nb);
    }
    state = Aes.subBytes(state, Nb);
    state = Aes.shiftRows(state, Nb);
    state = Aes.addRoundKey(state, w, Nr, Nb);
    const output = new Array(4*Nb);
    for (let i=0; i<4*Nb; i++) {
      output[i] = state[i%4][Math.floor(i/4)];
    }
    return output;
  }

  static keyExpansion(key) {
    const Nb = 4;
    const Nk = key.length/4;
    const Nr = Nk + 6;
    const w = new Array(Nb*(Nr+1));
    let temp = new Array(4);

    for (let i=0; i<Nk; i++) {
      const r = [ key[4*i], key[4*i+1], key[4*i+2], key[4*i+3] ];
      w[i] = r;
    }
    for (let i=Nk; i<(Nb*(Nr+1)); i++) {
      w[i] = new Array(4);
      for (let t=0; t<4; t++) temp[t] = w[i-1][t];
      if (i % Nk === 0) {
        temp = Aes.subWord(Aes.rotWord(temp));
        for (let t=0; t<4; t++) {
          temp[t] ^= Aes.rCon[i/Nk][t];
        }
      } else if (Nk > 6 && i%Nk === 4) {
        temp = Aes.subWord(temp);
      }
      for (let t=0; t<4; t++) w[i][t] = w[i-Nk][t] ^ temp[t];
    }
    return w;
  }

  static subBytes(s, Nb) {
    for (let r=0; r<4; r++) {
      for (let c=0; c<Nb; c++) s[r][c] = Aes.sBox[s[r][c]];
    }
    return s;
  }

  static shiftRows(s, Nb) {
    const t = new Array(4);
    for (let r=1; r<4; r++) {
      for (let c=0; c<4; c++) t[c] = s[r][(c+r)%Nb];
      for (let c=0; c<4; c++) s[r][c] = t[c];
    }
    return s;
  }

  static mixColumns(s, Nb) {
    for (let c=0; c<Nb; c++) {
      const a = new Array(Nb);
      const b = new Array(Nb);
      for (let r=0; r<4; r++) {
        a[r] = s[r][c];
        b[r] = s[r][c]&0x80 ? s[r][c]<<1 ^ 0x011b : s[r][c]<<1;
      }
      s[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
      s[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
      s[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
      s[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];
    }
    return s;
  }

  static addRoundKey(state, w, rnd, Nb) {
    for (let r=0; r<4; r++) {
      for (let c=0; c<Nb; c++) state[r][c] ^= w[rnd*4+c][r];
    }
    return state;
  }

  static subWord(w) {
    for (let i=0; i<4; i++) w[i] = Aes.sBox[w[i]];
    return w;
  }

  static rotWord(w) {
    const tmp = w[0];
    for (let i=0; i<3; i++) w[i] = w[i+1];
    w[3] = tmp;
    return w;
  }
}

Aes.sBox = [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
];

Aes.rCon = [
  [ 0x00, 0x00, 0x00, 0x00 ],
  [ 0x01, 0x00, 0x00, 0x00 ],
  [ 0x02, 0x00, 0x00, 0x00 ],
  [ 0x04, 0x00, 0x00, 0x00 ],
  [ 0x08, 0x00, 0x00, 0x00 ],
  [ 0x10, 0x00, 0x00, 0x00 ],
  [ 0x20, 0x00, 0x00, 0x00 ],
  [ 0x40, 0x00, 0x00, 0x00 ],
  [ 0x80, 0x00, 0x00, 0x00 ],
  [ 0x1b, 0x00, 0x00, 0x00 ],
  [ 0x36, 0x00, 0x00, 0x00 ]
];

class AesCtr extends Aes {
  static encrypt(inBuffer, password, nBits) {
    if (![ 128, 192, 256 ].includes(nBits)) throw new Error('Key size is not 128 / 192 / 256');
    const nBytes = nBits/8;
    const pwBytes = new Array(nBytes);
    for (let i=0; i<nBytes; i++) {
      pwBytes[i] = i<password.length ? password[i] : 0;
    }
    let key = Aes.cipher(pwBytes, Aes.keyExpansion(pwBytes));
    key = key.concat(key.slice(0, nBytes-16));
    const timestamp = (new Date()).getTime();
    const nonceMs = timestamp%1000;
    const nonceSec = Math.floor(timestamp/1000);
    const nonceRnd = Math.floor(Math.random()*0xffff);
    const counterBlock = [
      nonceMs & 0xff,
      nonceMs >>>8 & 0xff,
      nonceRnd & 0xff,
      nonceRnd>>>8 & 0xff,
      nonceSec & 0xff,
      nonceSec>>>8 & 0xff,
      nonceSec>>>16 & 0xff,
      nonceSec>>>24 & 0xff,
      0, 0, 0, 0, 0, 0, 0, 0
    ];
    const nonce = counterBlock.slice(0, 8);
    const ciphertextBytes = AesCtr.nistEncryption(inBuffer, key, counterBlock);
    return buffer.Buffer.concat([buffer.Buffer.from(nonce), buffer.Buffer.from(ciphertextBytes)]);
  }

  static nistEncryption(plaintext, key, counterBlock) {
    const blockSize = 16;
    const keySchedule = Aes.keyExpansion(key);
    const blockCount = Math.ceil(plaintext.length/blockSize);
    const ciphertext = new Array(plaintext.length);
    for (let b=0; b<blockCount; b++) {
      const cipherCntr = Aes.cipher(counterBlock, keySchedule);
      const blockLength = b<blockCount-1 ? blockSize : (plaintext.length-1)%blockSize + 1;
      for (let i=0; i<blockLength; i++) {
        ciphertext[b*blockSize + i] = cipherCntr[i] ^ plaintext[b*blockSize + i];
      }
      counterBlock[blockSize-1]++;
      for (let i=blockSize-1; i>=8; i--) {
        counterBlock[i-1] += counterBlock[i] >> 8;
        counterBlock[i] &= 0xff;
      }
    }
    return ciphertext;
  }

  static decrypt(ciphertext, password, nBits) {
    if (![ 128, 192, 256 ].includes(nBits)) throw new Error('Key size is not 128 / 192 / 256');
    const nBytes = nBits/8;
    const pwBytes = new Array(nBytes);
    for (let i=0; i<nBytes; i++) {
      pwBytes[i] = i<password.length ? password[i] : 0;
    }
    let key = Aes.cipher(pwBytes, Aes.keyExpansion(pwBytes));
    key = key.concat(key.slice(0, nBytes-16));

    const counterBlock = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ];
    for (let i=0; i<8; i++) {
      counterBlock[i] = ciphertext[i];
    }

    const ciphertextBytes = new Array(ciphertext.length-8);
    for (let i=8; i<ciphertext.length; i++) {
      ciphertextBytes[i-8] = ciphertext[i];
    }
    const plaintextBytes = AesCtr.nistDecryption(ciphertextBytes, key, counterBlock);
    return buffer.Buffer.from(plaintextBytes);
  }

  static nistDecryption(ciphertext, key, counterBlock) {
    const blockSize = 16;
    const keySchedule = Aes.keyExpansion(key);
    const blockCount = Math.ceil(ciphertext.length/blockSize);
    const plaintext = new Array(ciphertext.length);

    for (let b=0; b<blockCount; b++) {
      const cipherCntr = Aes.cipher(counterBlock, keySchedule);
      const blockLength = b<blockCount-1 ? blockSize : (ciphertext.length-1)%blockSize + 1;
      for (let i=0; i<blockLength; i++) {
        plaintext[b*blockSize + i] = cipherCntr[i] ^ ciphertext[b*blockSize + i];
      }
      counterBlock[blockSize-1]++;
      for (let i=blockSize-1; i>=8; i--) {
        counterBlock[i-1] += counterBlock[i] >> 8;
        counterBlock[i] &= 0xff;
      }
    }
    return plaintext;
  }
}

//Psudo Random Number Generator -- in hex
const prng = len => Array(len)
  .fill()
  .map(() => parseInt((Math.round(Math.random() * 256))).toString(16));

const tokenSizeMap = {
  256: 232, // 2048 bit RSA
  128: 114, // 1024 bit RSA
  64: 50, // 512 bit
  32: 18, // 256 bit
  16: 2 // 128 bit
};

const defaultOptions = {
  expon: 65537,
  keySize: 64,
  primeCheck: 2
};


class CyphtPublicKey {
  constructor(privateKey) {
    if (typeof privateKey !== 'undefined') {
      this.n = (typeof privateKey === 'undefined' ? null : privateKey.n);
      this.e = (typeof privateKey === 'undefined' ? 0 : privateKey.e);
      this.options = privateKey.options;
    } else {
      this.options = defaultOptions;
      this.options.tokenSize = tokenSizeMap[this.options.keySize];
    }
  }

  isPublic() {
    return true;
  }

  isPrivate() {
    return false;
  }

  crypt(x) {
    return x.modPow(this.e, this.n);
  }

  verify(x, target) {
    const verifyBuffer = buffer.Buffer.from(this.crypt(BigInteger.fromArray([...x], 256)).toArray(256).value);
    const targetBuffer = buffer.Buffer.from(BigInteger(target).toArray(256).value);
    return verifyBuffer.equals(targetBuffer);
  }

  exportRaw() {
    return buffer.Buffer.from(this.n.toArray(256).value);
  }

  importRaw(octetStream, exponent=415031) {
    this.n = BigInteger.fromArray([...octetStream], 256);
    this.e = parseInt(exponent);
  }
}

class CyphtPrivateKey {
  constructor( options = {}) {
    this.options = Object.assign({}, defaultOptions, options);
    this.options.tokenSize = tokenSizeMap[this.options.keySize];
    // TODO expand tokenSize based on keySize
    this.n = null; // Private & Public
    this.e = 0; // Private & Public
    this.d = null; // Private
    this.p = null;
    this.q = null;
    this.dmp1 = null;
    this.dmq1 = null;
    this.coeff = null;
  }

  crypt(x) {
    if(this.p == null || this.q == null) {
      return x.modPow(this.d, this.n);
    }
    let xp = x.mod(this.p).modPow(this.dmp1, this.p);
    let xq = x.mod(this.q).modPow(this.dmq1, this.q);
    while (xp.compareTo(xq) < 0) {
      xp = xp.add(this.p);
    }
    return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
  }

  publicKey() { //Public Key factory
    return new CyphtPublicKey(this);
  }

  isPublic() {
    return false;
  }

  isPrivate() {
    return true;
  }

  sign(x) {
    return buffer.Buffer.from(this.crypt(BigInteger(x)).toArray(256).value);
  }

  importRaw(octetStream, exponent=415031) {
    const firstBuffer = octetStream.slice( 0, Math.ceil(octetStream.length / 2) );
    const secondBuffer = octetStream.slice( Math.ceil(octetStream.length / 2) );
    this.n = BigInteger.fromArray([...firstBuffer], 256);
    this.d = BigInteger.fromArray([...secondBuffer], 256);
    this.e = parseInt(exponent);
  }

  exportRaw() {
    const firstBuffer = buffer.Buffer.from(this.n.toArray(256).value);
    const secondBuffer = buffer.Buffer.from(this.d.toArray(256).value);
    return buffer.Buffer.concat([firstBuffer, secondBuffer]);
  }

  // Key generation
  generate() {
    return new Promise( (resolve, reject) => {
      const qs = this.options.keySize >> 1;
      this.e = parseInt(this.options.expon, 16);
      const ee = new BigInteger(this.options.expon, 16);
      for(;;) {
        for(;;) {
          //Populate a big int with random bytes
          this.p = new BigInteger(prng(this.options.keySize - qs).join(''), 16);
          while(!this.p.isProbablePrime(this.options.primeCheck)) { //Is this random number prime?
            this.p = new BigInteger(prng(this.options.keySize - qs).join(''), 16);
          }
          this.p.subtract(BigInteger.one);
          if (BigInteger.gcd(this.p, ee).compareTo(BigInteger.one) === 0 && this.p.isProbablePrime(this.options.primeCheck)) break;
        }
        for(;;) {
          this.q = new BigInteger(prng(qs).join(''), 16);
          while(!this.q.isProbablePrime(this.options.primeCheck)) {
            this.q = new BigInteger(prng(qs).join(''), 16);
          }
          this.q.subtract(BigInteger.one);
          if (BigInteger.gcd(this.q, ee).compareTo(BigInteger.one) === 0 && this.q.isProbablePrime(this.options.primeCheck)) break;
        }
        if (this.p.compareTo(this.q) <= 0) {
          const t = this.p;
          this.p = this.q;
          this.q = t;
        }
        const p1 = this.p.subtract(BigInteger.one);
        const q1 = this.q.subtract(BigInteger.one);
        const phi = p1.multiply(q1);
        if (BigInteger.gcd(phi, ee).compareTo(BigInteger.one) === 0) {
          this.n = this.p.multiply(this.q);
          this.d = ee.modInv(phi);
          this.dmp1 = this.d.mod(p1);
          this.dmq1 = this.d.mod(q1);
          this.coeff = this.q.modInv(this.p);
          break;
        }
      }
      resolve(
        true
      );
    });
  }
}

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
  return buffer.Buffer.from(ret);
};

// Turns text into an integer
const pkcs1pad2 = (s, n) => {
  if(n < s.length + 11) { // TODO: fix for utf-8
    console.log("Message too long for RSA");
    return null;
  }
  var ba = new Array();
  var i = s.length - 1;
  while(i >= 0 && n > 0) {
    var c = s[i--];
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
};

const PRIVATE_ENCRYPTED = 128; //BitFlag for cyphts encrypted with a private key.

// Encrypt from public/private key
function encrypt(inBuffer, key) {
  let m = pkcs1pad2(inBuffer, (key.n.bitLength()+7) >> 3);
  if(m == null) return null;
  let c = key.crypt(m);
  if(c == null) return null;
  return new buffer.Buffer.from(c.toArray(256).value);
}

// Decrypt from private key
function decrypt(enc, key) {
  let c = new BigInteger.fromArray([...enc], 256);
  let m = key.crypt(c);
  if(m == null) return null;
  return pkcs1unpad2(m, (key.n.bitLength()+7)>>3);
}

const encypht = (original, key) => {
  console.log('Encrypting with token size', key.options.tokenSize);
  const password = buffer.Buffer.from(prng(key.options.tokenSize).map( chr => {
    return chr.toString();
  }));
  const omessage = buffer.Buffer.from(original);
  const encMessage = new buffer.Buffer.from(AesCtr.encrypt(omessage, password, 256));
  const encPassword = encrypt(password, key);
  const outLength = encMessage.length + encPassword.length + 1;
  const lengthToken = key.isPrivate() ? encPassword.length + PRIVATE_ENCRYPTED : encPassword.length;
  return buffer.Buffer.concat([ buffer.Buffer.from([lengthToken]), encPassword, encMessage ], outLength);
};

const isPrivateCypht = cypht => {
  const tokenLength = cypht[0];
  return (tokenLength > PRIVATE_ENCRYPTED);
};

const decypht = (cypht, key) => {
  let tokenLength;
  if (isPrivateCypht(cypht)) {
    tokenLength = (cypht[0] - PRIVATE_ENCRYPTED);
  } else {
    tokenLength = cypht[0];
  }
  const token = cypht.slice( 1, tokenLength+1 );
  const pass = decrypt(token, key);
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

const cypht = {
  generateKeys,
  CyphtPrivateKey,
  CyphtPublicKey,
  encypht,
  decypht,
  isPrivateCypht
};

module.exports = cypht;
