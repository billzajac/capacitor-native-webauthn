import { WebPlugin } from '@capacitor/core';
import type { WebAuthnPlugin } from './index';

export declare class WebAuthnWeb extends WebPlugin implements WebAuthnPlugin {
  isWebAuthnAvailable(): Promise<{ isWebAuthnAvailable: boolean }>;
  isWebAuthnAutoFillAvailable(): Promise<{ isWebAuthnAutoFillAvailable: boolean }>;
  startRegistration(options: any): Promise<any>;
  startAuthentication(options: any): Promise<any>;
}