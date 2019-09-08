# CyphtJS

Cypht is a cryptographic library that uses a AES-CRT Cipher, and RSA-155 key encryption. This library was built from scratch without using any core libraries from NodeJS/Browserfy/React etc. Without depending on any core library referencing, this library is considered highly portable and can be used in any javascript environments form Web to NodeJS CLI to ReactNative. With high portablility speed was sacrificed and thats why the RSA bit encryption is so low. The main feature of the library is RSA Encryption on a random token. The token is also used to AES cipher a payload. A cypht message is the RSA encrypted token, plus the AES ciphered payload.

## How to use
The basics is to create a key pair using the `generateKeys` function. This will return an object with two keys, a `publicKey` and a `privateKey`. The public key is given out to the mass public and others will use it to encrypt messages to send to you. Only the person with the corrisponding private key can read these messages. You encrypt using the `encypht` function, and decrypt using the `decypht` function.

## Encoding
This library uses a different type of encoding than normal. URL Safe binary encoding was used by converting binary data to 75 url safe characters to create a base75 encoding system. Cyphted messages and exported public keys both use this base75 encoding.

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

## Security
The library is ment to be fast and lightweight and only provides very basic security. The keys are equiveland to 512bit RSA Encryption also known as RSA-155. A RSA-155 key was cracked in 1999 after 6 months of heavy computing on pretty advanced hardware. The concept is that the keys are crackable, but it would take a lot of computing power and time to crack a single key and is not worth it for most hackers. The added bonus of Cypht messages, is when attempting to crack a key, it will need to be tested against an AES ciphered payload. This makes for higher complexity than normal RSA cracking.

## Looking forward
There is a lot of functionality that can be put into this library. At this time I would like to keep it slim and simple as possible. No need to import/export private keys, or allow tweaking the key/token sizes.
