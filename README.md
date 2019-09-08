# CyphtJS

Cypht is a cryptographic library that uses AES Cipher, and RSA key encryption. This library was built from scratch without using any core libraries from NodeJS/Browserfy/React etc. This means its a highly portable ( but slow ) cryptographic library. The main feature of the library is RSA Encryption on a random token. The token is also used to AES cipher a payload. 

## How to use
The basics is to create a key pair using the `generateKeys` function. This will return an object with two keys, a `publicKey` and a `privateKey`. The public key is given out to the mass public and they will use it to encrypt messages to send to you. Only the person with the corrisponding private key can read these messages. You encrypt using the `encypht` function, and decrypt using the `decypht` function.

## Encoding
The library uses a different type of encoding than normal. URL Safe binary encoding was used by converting binary data to 75 url safe characters to create a base75 encoding system.

## Code Examples
```
import cypht from 'cyphtjs';
const keys = cypht.generateKeys();
const encMessage = cypht.encypht('We attack at dawn', keys.publicKey);
const decMessage = cypht.decrypt(encMessage, keys.privateKey);
console.log(encMessage,'->',decMessage);
```
