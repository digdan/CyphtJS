var cypht = require('./build/index');

let sizeTestCount = 0;

function sizeTest(message, keys) {
  const crypted = cypht.encypht(message, keys.publicKey);
  const decrypted = cypht.decypht(crypted, keys.privateKey).toString();
  sizeTestCount++;
  const change = Math.round((crypted.length / message.length) * 100);
  console.log('Message Size Test #', sizeTestCount ,'From', message.length, 'bytes to', crypted.length,'bytes. A', change,'% change. Message : ',decrypted);
}


console.log('Generating keys');
const started = Date.now();
cypht.generateKeys({
  keySize: 64
}).then( keys => {
  console.log('Keys generated in', (Date.now() - started), 'ms');
  console.log('Export/Import test');
  const publicKey = new cypht.CyphtPublicKey;
  publicKey.importRaw(keys.publicKey.exportRaw());
  const privateKey = new cypht.CyphtPrivateKey;
  privateKey.importRaw(keys.privateKey.exportRaw());
  console.log('orig', JSON.stringify(keys.privateKey, null, 4));
  console.log('impo', JSON.stringify(privateKey, null, 4));
  const signPayload = 1337;
  console.log('Signing test. Payload:', signPayload);
  const signed = privateKey.sign(signPayload);
  console.log('Public key verified:', publicKey.verify(signed, signPayload));
  sizeTest('We strike at dawn', {publicKey, privateKey});
  sizeTest('The fruitsalad was poisoned', {publicKey, privateKey});
});
