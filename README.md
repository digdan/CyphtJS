# CyphtJS

Cypht is a cryptographic library that uses a AES-CRT Cipher, defaulting to RSA-155 key encryption. This library was built from scratch without using any core libraries. Without use of core libraries, this encryption library is considered highly portable and can be used in any javascript platforms form Web, NodeJS CLI, to ReactNative. With high portability, speed was sacrificed and thats why the RSA bit encryption is defaulted so low. The main feature of the library is RSA Encryption on a random token that matches the RSA key size up to 256 bits. The token is also used to AES-CRT cipher a payload. A cypht message is the RSA encrypted token, plus the AES ciphered payload. This is all returned as a single buffer, called a `Cypht` (crypt + cipher).

## How to use
The basics is to create a key pair using the `generateKeys` function. This will return an a promise that results in an object with two keys, a `publicKey` and a `privateKey`. You can encypht, and decypht using either key, but you must use the corresponding key to read the cypht.

## Encoding
Public key exports, and cyphts are both returned as a Buffer. You can choose to use which ever encoding you would like. For ReactNative, due to the JS Bridge its recommended to use Base64. For all other instances you can use raw binary.

## Code Examples
### Basic Use
```
import cypht from 'cyphtjs';
cypht.generateKeys().then( keys => {
  cypht.encypht('We attack at dawn', keys.publicKey).then( encMessage => {
    cypht.decrypt(encMessage, keys.privateKey).then( decMessage => {
      console.log('Public to Private Decyphting', encMessage,'->',decMessage);
    });
  });
});
```
### Two way cyphting
```
import cypht from 'cyphtjs';
cypht.generateKeys().then( keys => {
  cypht.encypht('We attack at dawn', keys.privateKey).then( encMessage => {
    cypht.decrypt(encMessage, keys.publicKey).then( decMessage => {
      console.log('Private to Public Decyphting', encMessage,'->',decMessage);
    });
  });
});
```


### Signing and verifying with 2048-bit RSA
```
import cypht from 'cyphtjs';
cypht.generateKeys({
  keySize: 256
}).then( keys => {
  const message = 'testing';
  const signature = keys.privateKey.sign(message);
  console.log('Private signing verified?', keys.publicKey.verify(signature, message));
})
```

## Security
The library is meant to be fast and lightweight and only provides very basic security. The default keys are equivalent to 512bit RSA Encryption also known as RSA-155. A RSA-155 key was cracked in 1999 after 6 months of heavy computing on pretty advanced hardware, on average it would take 6,000 MIPs a full year to crack. This would mean it would take a standard Raspberry Pi 3 around 12 years to crack, and an Intel Xeon E5-2697 v2 around 42 days to crack. The concept is that the keys are crackable, but it would take a lot of computing power and time to crack a single key and is not worth it for most hackers. The added bonus of Cypht messages, is when attempting to crack a key, it will need to be tested against an AES ciphered payload. This makes for higher complexity than normal RSA cracking.

The AES-CRT token used to cipher tops out at 256-bits. This means cyphts with RSA key strengths over 256-bits only gain security from the RSA keys, and not the AES-CRT ciphering. Also, the control byte on a cypht can not handle tokens larger than 256.

DISCLAIMER: Use are your own risk.

## Looking forward
There is a lot of functionality that can be put into this library. At this time I would like to keep it slim and simple as possible. No need to import/export private keys, or allow tweaking the key/token sizes.
