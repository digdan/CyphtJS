//Psudo Random Number Generator -- in hex
const prng = len => {
  return Array(len)
    .fill()
    .map(() => parseInt((Math.round(Math.random() * 256))).toString(16));
}

export {
  prng as default,
}