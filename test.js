var cypht = require('./build/index');

let sizeTestCount = 0;

function sizeTest(message, keys) {
  cypht.encypht(message, keys.publicKey).then( crypted => {
    cypht.decypht(crypted, keys.privateKey).then( decrypted => {
      sizeTestCount++;
      console.log('Message Size Test #', sizeTestCount ,'Overhead', crypted.length - message.length, 'bytes', 'Message :', decrypted.toString());
    });
  });
}

let keySize = process.argv[2] ? parseInt(process.argv[2]) : 128;

console.log('Generating', keySize*8,'bit RSA keys');
const started = Date.now();
cypht.generateKeys({
  keySize
}).then( keys => {
  console.log('Keys generated in', (Date.now() - started), 'ms');
  console.log('Prime iterations p=', keys.privateKey.generationIterations[0],'q=',keys.privateKey.generationIterations[1]);
  console.log('Export/Import test');
  const publicKey = new cypht.CyphtPublicKey;
  publicKey.importRaw(keys.publicKey.exportRaw());
  const privateKey = new cypht.CyphtPrivateKey;
  privateKey.importRaw(keys.privateKey.exportRaw());
  const signPayload = publicKey.randomToken();
  console.log('Signing test. Payload Size:', signPayload.length);
  const signed = privateKey.sign(signPayload);
  console.log('Public key verified:', publicKey.verify(signed, signPayload));
  sizeTest('We strike at dawn', {publicKey, privateKey});
  sizeTest('The size of the message should not change the overhead when cyphting a message. That all depends on the key size used', {publicKey, privateKey});
  sizeTest('Reverse key test', {publicKey:privateKey, privateKey:publicKey});
});
