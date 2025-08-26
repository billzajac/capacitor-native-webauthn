export interface WebAuthnPlugin {
  isWebAuthnAvailable(): Promise<{ isWebAuthnAvailable: boolean }>;
  isWebAuthnAutoFillAvailable(): Promise<{ isWebAuthnAutoFillAvailable: boolean }>;
  startRegistration(options: any): Promise<any>;
  startAuthentication(options: any): Promise<any>;
}

export declare const WebAuthn: WebAuthnPlugin;