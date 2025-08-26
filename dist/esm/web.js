import { WebPlugin } from '@capacitor/core';
import { 
  startRegistration as webStartRegistration,
  startAuthentication as webStartAuthentication 
} from '@simplewebauthn/browser';

export class WebAuthnWeb extends WebPlugin {
  async isWebAuthnAvailable() {
    return { 
      isWebAuthnAvailable: Boolean(window.PublicKeyCredential)
    };
  }
  
  async isWebAuthnAutoFillAvailable() {
    return { 
      isWebAuthnAutoFillAvailable: false 
    };
  }
  
  async startRegistration(options) {
    return webStartRegistration(options);
  }
  
  async startAuthentication(options) {
    return webStartAuthentication(options);
  }
}