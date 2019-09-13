import {
  generateKeys,
  encypht,
  decypht,
  isPrivateCypht,
  CyphtPrivateKey,
  CyphtPublicKey
} from './lib/cypht';

const cypht = {
  generateKeys,
  CyphtPrivateKey,
  CyphtPublicKey,
  encypht,
  decypht,
  isPrivateCypht
};

export {
  cypht as default
};
