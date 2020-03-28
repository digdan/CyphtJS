//Psudo Random Number Generator -- in hex
const prng = len => {
  const rna = Array(len)
    .fill()
    .map(() => parseInt((Math.round(Math.random() * 256))).toString(16));
  return rna;
}

export {
  prng as default,
}