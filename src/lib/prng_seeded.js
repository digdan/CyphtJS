const prng_seed = str => {
  for(var i = 0, h = 1779033703 ^ str.length; i < str.length; i++) {
      h = Math.imul(h ^ str.charCodeAt(i), 3432918353);
      h = h << 13 | h >>> 19;
  }
  return function() {
    h = Math.imul(h ^ h >>> 16, 2246822507);
    h = Math.imul(h ^ h >>> 13, 3266489909);
    return (h ^= h >>> 16) >>> 0;
  }
}

const sfc32 = (a, b, c, d) => {
  a >>>= 0; b >>>= 0; c >>>= 0; d >>>= 0; 
  var t = (a + b) | 0;
  a = b ^ b >>> 9;
  b = c + (c << 3) | 0;
  c = (c << 21 | c >>> 11);
  d = d + 1 | 0;
  t = t + d | 0;
  c = c + t | 0;
  return (t >>> 0) / 4294967296;
}

const prng_seeded = (seed, len) => {
  return Array(len)
  .fill()
  .map(() => Math.round(sfc32(seed(), seed(), seed(), seed()) * 255).toString(16));
}

export {
  prng_seeded,
  prng_seed
}