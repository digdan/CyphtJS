import BigInteger from 'big-integer';
import { Buffer } from 'buffer';
import prng from './prng';

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
  return Buffer.from(ret);
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
}

export {
  pkcs1pad2,
  pkcs1unpad2
}
