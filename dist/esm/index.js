import { registerPlugin } from '@capacitor/core';

const WebAuthn = registerPlugin('WebAuthn', {
  web: () => import('./web').then(m => new m.WebAuthnWeb()),
});

export { WebAuthn };