# CyphtJS

Cypht is a cryptographic library that uses AES Cipher, and RSA key encryption. This library was built from scratch without using any core libraries from NodeJS/Browserfy/React etc. This means its a highly portable ( but slow ) cryptographic library. The main feature of the library is RSA Encryption on a random token. The token is also used to AES cipher a payload. 

## How to use
The basics is to create a key pair using the `generateKeys` function. This will return an object with two keys, a `publicKey` and a `privateKey`. The public key is given out to the mass public and they will use it to encrypt messages to send to you. Only the person with the corrisponding private key can read these messages. You encrypt using the `encypht` function, and decrypt using the `decypht` function.

## Encoding
The library uses a different type of encoding than normal. URL Safe binary encoding was used by converting binary data to 75 url safe characters to create a base75 encoding system. Cyphted messages and exported public keys both use this base75 encoding.

Example of Cypht Message : 
`BS59U;H_q':9Tu-e@E7NFv6Qrw~efe4wl1S8nuM(gb2DfVMHlVdMG3_tZ0T0C:J(JLJ;qphcRp9D*w69fH:P~EGl1LMi'lUby-)lgL@UGo6wUEVL7TUrDDG78!e,bW4M4t0VDv408u(jcC@fIBM-arhd225*-7c@YHB.HC4;f5'g_u~gA8sF1oal3M!(y-DD@~3~17,_P'hbsrP`

Example of a Public Key : 
`Bpxf5WN')LeL@sZKDYI5MbimgY!6ko@)V~X1n~Q4:QCzchGHeARM(i!f9rFSSTPD5RR@U!rpd93iNcPuDqVWQQsap1KA28TnXkKby,wAI4dbAXO4yzW16;-EIHPtZaI:g_UNkzBQ,VBcheP*WX~5u40GfGif5VxPb4v`

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
