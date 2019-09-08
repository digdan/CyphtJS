import basex from 'base-x';

// URL Safe Characters - Also safe for messaging
const BASE75 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_~()\'!*:@,;';
const baseConverter = basex(BASE75);

export {
  baseConverter as default
}
