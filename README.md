# CyphtJS

Cypht is a cryptographic library that uses AES Cipher, and RSA key encryption. This library was built from scratch without using any core libraries from NodeJS/Browserfy/React etc. This means its a highly portable ( but slow ) cryptographic library. The main feature of the library is RSA Encryption on a random token. The token is also used to AES cipher a payload. 

## How to use
The basics is to create a key pair using the `generateKeys` function. This will return an object with two keys, a `publicKey` and a `privateKey`. The public key is given out to the mass public and they will use it to encrypt messages to send to you. Only the person with the corrisponding private key can read these messages. You encrypt using the `encypht` function, and decrypt using the `decypht` function.

## Encoding
The library uses a different type of encoding than normal. URL Safe binary encoding was used by converting binary data to 75 url safe characters to create a base75 encoding system. Cyphted messages and exported public keys both use this base75 encoding.

Example of Cypht Message : 
`xzj1kq:8ypvHWgrlx1-qgW6jVu_msKkvJQH~nPLZ-t2lojwwKVlA!uGZ0eyIr9bmJ6yk8WPI1nn6JF5*G.BLe_iwar8_kLs*'Evum,8oDQ7Gsk@qlh-H*JvO,y:u`

Example of a Public Key : 
`BXvRsE'cYQrQp3XVVh8HK5n(;*uFdqi:2Oc~4nEi7Z(j!YM,3GF'!G(63U2Rf,L)*VVAZO-1*b0H~eh-1p`

## Code Examples
```
import cypht from 'cyphtjs';
const keys = cypht.generateKeys();
const encMessage = cypht.encypht('We attack at dawn', keys.publicKey);
const decMessage = cypht.decrypt(encMessage, keys.privateKey);
console.log('Public Key', keys.publicKey.export());
console.log('Decyphting', encMessage,'->',decMessage);
```

## Looking forward
There is a lot of functionality that can be put into this library. At this time I would like to keep it slim and simple as possible. No need to import/export private keys, or allow tweaking the key/token sizes.
