# CyphtJS

Cypht is a cryptographic library that uses a AES-CRT Cipher, and RSA-155 key encryption. This library was built from scratch without using any core libraries. Without use of core libraries, this encryption library  is  considered highly portable and can be used in any javascript environments form Web to NodeJS CLI to ReactNative. With high portability, speed was sacrificed and thats why the RSA bit encryption is so low. The main feature of the library is RSA Encryption on a random token. The token is also used to AES cipher a payload. A cypht message is the RSA encrypted token, plus the AES ciphered payload. This is all returned as a single buffer, called a `Cypht` (crypt + cipher).

## How to use
The basics is to create a key pair using the `generateKeys` function. This will return an a promise that results in an object with two keys, a `publicKey` and a `privateKey`. The public key is given out to the mass public and others will use it to encrypt messages to send to you. Only the person with the corrisponding private key can read these messages. You encrypt using the `encypht` function, and decrypt using the `decypht` function.

## Encoding
Public key exports, and cyphts are both returned as a Buffer. You can choose to use which ever encoding you would like. For ReactNative, due to the JS Bridge its recommended to use Base64. For all other instances you can use raw binary. A Cypht contains an ciphered message, and the RSA encrypted token to decipher the message.

## Code Examples
### Basic Use
```
import cypht from 'cyphtjs';
cypht.generateKeys().then( keys => {
  const encMessage = cypht.encypht('We attack at dawn', keys.publicKey);
  const decMessage = cypht.decrypt(encMessage, keys.privateKey);
  console.log('Public to Private Decyphting', encMessage,'->',decMessage);
});
```
### Two way cyphting
```
import cypht from 'cyphtjs';
cypht.generateKeys().then( keys => {
  const encMessage = cypht.encypht('We attack at dawn', keys.privateKey);
  const decMessage = cypht.decrypt(encMessage, keys.publicKey);
  console.log('Private to Public Decyphting', encMessage,'->',decMessage);
});
```


## Security
The library is meant to be fast and lightweight and only provides very basic security. The keys are equivalent to 512bit RSA Encryption also known as RSA-155. A RSA-155 key was cracked in 1999 after 6 months of heavy computing on pretty advanced hardware, on average it would take 6,000 MIPs a full year to crack. This would mean it would take a standard Raspberry Pi 3 around 12 years to crack, and an Intel Xeon E5-2697 v2 around 42 days to crack. The concept is that the keys are crackable, but it would take a lot of computing power and time to crack a single key and is not worth it for most hackers. The added bonus of Cypht messages, is when attempting to crack a key, it will need to be tested against an AES ciphered payload. This makes for higher complexity than normal RSA cracking.

DISCLAIMER: Use are your own risk.

## Looking forward
There is a lot of functionality that can be put into this library. At this time I would like to keep it slim and simple as possible. No need to import/export private keys, or allow tweaking the key/token sizes.
