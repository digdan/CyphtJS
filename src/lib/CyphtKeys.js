//import baseConverter from './baseConverter';
import { Buffer } from 'buffer';
import BigInteger from 'big-integer';

class CyphtPublicKey {
  constructor(privateKey) {
    this.n = (typeof privateKey === 'undefined' ? null : privateKey.n);
    this.e = (typeof privateKey === 'undefined' ? 0 : privateKey.e);
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
  constructor() {
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
    while(xp.compareTo(xq) < 0)
      xp = xp.add(this.p);
    return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
  }

  publicKey() { //Public Key factory
    return new CyphtPublicKey(this);
  }

}

export {
  CyphtPrivateKey,
  CyphtPublicKey
}
