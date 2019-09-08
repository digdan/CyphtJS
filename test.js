var cypht = require('./build/index');
console.log('Generating keys');
const started = Date.now();
cypht.generateKeys().then( ({ privateKey, publicKey }) => {
  console.log('Keys generated in', (Date.now() - started), 'ms');
  console.log('Public Key', publicKey.export());
  let message = 'We strike at dawn';
  let crypted = cypht.encypht(message, publicKey);
  let decrypted = cypht.decypht(crypted, privateKey);
  console.log('Message Test #1 ->', crypted,'->',decrypted);
  message = 'The fruit was poisoned';
  crypted = cypht.encypht(message, publicKey);
  decrypted = cypht.decypht(crypted, privateKey);
  console.log('Message Test #2 ->', crypted,'->',decrypted);
  message = 'Go confidently in the direction of your dreams. Live the life you have imagined.';
  crypted = cypht.encypht(message, publicKey);
  decrypted = cypht.decypht(crypted, privateKey);
  console.log('Message Test #3 ->', crypted,'->',decrypted);

});
