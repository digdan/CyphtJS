import {
  generateKeys,
  encypht,
  decypht,
  CyphtPrivateKey,
  CyphtPublicKey
} from './lib/cypht';

const cypht = {
  generateKeys,
  CyphtPrivateKey,
  CyphtPublicKey,
  encypht,
  decypht
};

export {
  cypht as default
};
