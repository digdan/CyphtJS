import { Buffer } from 'buffer';
import BigInteger from 'big-integer';
import prng from './prng';

class CyphtPublicKey {
  constructor(privateKey) {
    this.n = (typeof privateKey === 'undefined' ? null : privateKey.n);
    this.e = (typeof privateKey === 'undefined' ? 0 : privateKey.e);
    this.options = privateKey.options;
  }

  crypt(x) {
    return x.modPow(this.e, this.n);
  }

  export() {
    return Buffer.from(this.n.toArray(256).value);
  }

  import(baseNotation, exponent=65537) {
    this.n = BigInteger(baseNotation);
    this.e = parseInt(exponent);
  }
}

class CyphtPrivateKey {
  constructor( options = {}) {
    const defaultOptions = {
      expon: 65537,
      keySize: 64,
      primeCheck: 3,
      tokenSize: 32
    };
    this.options = Object.assign({}, defaultOptions, options);
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

export {
  CyphtPrivateKey,
  CyphtPublicKey
};
