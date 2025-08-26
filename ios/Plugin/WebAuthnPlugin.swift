import Foundation
import Capacitor
import AuthenticationServices

// Base64URL encoding/decoding extension
extension Data {
    init?(base64urlEncoded: String) {
        var base64 = base64urlEncoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        
        // Add padding if needed
        while base64.count % 4 != 0 {
            base64.append("=")
        }
        
        self.init(base64Encoded: base64)
    }
    
    func base64urlEncodedString() -> String {
        return self.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

enum Attachment: String {
    case CROSSPLATFORM = "crossplatform"
    case PLATFORM = "platform"
}

enum PasskeyError: String {
    case MISSING_ATTESTATION_OBJECT_ERROR = "MISSING_ATTESTATION_OBJECT"
    case USER_CANCELED_ERROR = "USER_CANCELED"
    case INVALID_RESPONSE_ERROR = "INVALID_RESPONSE"
    case NOT_HANDLED_ERROR = "NOT_HANDLED"
    case FAILED_ERROR = "FAILED"
    case NOT_INTERACTIVE_ERROR = "NOT_INTERACTIVE"
    case UNKNOWN = "UKNOWN"
}

class GetAppleSignInHandler: NSObject, ASAuthorizationControllerDelegate {
    var call: CAPPluginCall
    var window : UIWindow;
    
    init(call: CAPPluginCall, window:UIWindow) {
        self.call = call
        self.window = window
        super.init()
    }
    
    func register() {
        let _challenge: String = call.getString("challenge")!
        let _userid: String = call.getObject("user")?["id"] as! String
        let _username: String = call.getObject("user")?["name"] as! String
        var _rp: String = call.getObject("rp")?["id"] as! String
        
        // For local development, if the RP ID contains localhost or dev domain,
        // use the app bundle identifier instead to avoid domain association issues
        if _rp.contains("localhost") || _rp.contains("dev.komyun") || _rp.contains("192.168") {
            // Use the main bundle identifier without the team prefix
            if let bundleId = Bundle.main.bundleIdentifier {
                // Extract just the app ID part (e.g., "co.komyun.app" from "FT574Q62GF.co.komyun.app")
                let components = bundleId.components(separatedBy: ".")
                if components.count > 2 {
                    _rp = components.suffix(3).joined(separator: ".")
                } else {
                    _rp = bundleId
                }
                print("WebAuthn Register - Using bundle ID for local dev: \(_rp)")
            }
        }
        
        print("WebAuthn Register - RP: \(_rp), User: \(_username), UserID: \(_userid)")
        
        let challengeData = Data(base64urlEncoded: _challenge)!
        // User ID is base64url encoded, decode it
        let useridData = Data(base64urlEncoded: _userid) ?? Data(_userid.utf8)
        
        print("WebAuthn Register - Challenge size: \(challengeData.count), UserID size: \(useridData.count)")
        
        let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: _rp)
        let platformKeyRequest = platformProvider.createCredentialRegistrationRequest(
            challenge: challengeData,
            name: _username,
            userID: useridData
        )
        let authController = ASAuthorizationController(authorizationRequests: [platformKeyRequest])
        authController.delegate = self
        authController.presentationContextProvider = self
        authController.performRequests()
    }
    
    func authenticate() {
        let _challenge: String = call.getString("challenge")!
        var _rp: String = call.getString("rpId")!
        
        // For local development, if the RP ID contains localhost or dev domain,
        // use the app bundle identifier instead to avoid domain association issues
        if _rp.contains("localhost") || _rp.contains("dev.komyun") || _rp.contains("192.168") {
            // Use the main bundle identifier without the team prefix
            if let bundleId = Bundle.main.bundleIdentifier {
                // Extract just the app ID part (e.g., "co.komyun.app" from "FT574Q62GF.co.komyun.app")
                let components = bundleId.components(separatedBy: ".")
                if components.count > 2 {
                    _rp = components.suffix(3).joined(separator: ".")
                } else {
                    _rp = bundleId
                }
                print("WebAuthn Authenticate - Using bundle ID for local dev: \(_rp)")
            }
        }
        
        let challengeData = Data(base64urlEncoded: _challenge)!
        
        let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: _rp)
        let platformKeyRequest = platformProvider.createCredentialAssertionRequest(challenge: challengeData)
        let authController = ASAuthorizationController(authorizationRequests: [platformKeyRequest])
        authController.delegate = self
        authController.presentationContextProvider = self
        authController.performRequests()
    }
    
    func getAuthenticatorAttachment(attachment: ASAuthorizationPublicKeyCredentialAttachment) -> String {
        var type = Attachment.PLATFORM.rawValue
        if attachment.rawValue == 1 {
            type = Attachment.CROSSPLATFORM.rawValue
        }
        return type
            
      }
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        switch authorization.credential {
        case let credentialRegistration as ASAuthorizationPlatformPublicKeyCredentialRegistration:
            let id = credentialRegistration.credentialID.base64urlEncodedString()
            let rawId = credentialRegistration.credentialID.base64urlEncodedString()
            let attestationObject = credentialRegistration.rawAttestationObject!.base64urlEncodedString()
            let authenticatorAttachment = getAuthenticatorAttachment(attachment: credentialRegistration.attachment)
            let type = "public-key"
            let clientDataJSON = credentialRegistration.rawClientDataJSON.base64urlEncodedString()
            let transports: [String] = ["internal"]
            call.resolve([
                "rawId": rawId,
                "authenticatorAttachment": authenticatorAttachment,
                "type": type,
                "id": id,
                "response": [
                    "transports": transports,
                    "clientDataJSON": clientDataJSON,
                    "attestationObject": attestationObject
                ]
            ])
        case let credentialAssertion as ASAuthorizationPlatformPublicKeyCredentialAssertion:
            let id = credentialAssertion.credentialID.base64urlEncodedString()
            let rawId = credentialAssertion.credentialID.base64urlEncodedString()
            let type = "public-key"
            let authenticatorAttachment = getAuthenticatorAttachment(attachment: credentialAssertion.attachment)
            let clientDataJSON = credentialAssertion.rawClientDataJSON.base64urlEncodedString()
            let authenticatorData = credentialAssertion.rawAuthenticatorData.base64urlEncodedString()
            let signature = credentialAssertion.signature.base64urlEncodedString()
            let userHandle = credentialAssertion.userID.base64urlEncodedString()
            // After the server verifies the assertion, sign in the user.
            call.resolve([
                "rawId": rawId,
                "authenticatorAttachment": authenticatorAttachment,
                "type": type,
                "id": id,
                "response": [
                    "clientDataJSON": clientDataJSON,
                    "authenticatorData": authenticatorData,
                    "signature": signature,
                    "userHandle": userHandle
                ]
            ])
        default:
            call.reject(PasskeyError.UNKNOWN.rawValue)
        }
    }
    
    func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        print("WebAuthn Error: \(error)")
        guard let authorizationError = error as? ASAuthorizationError else {
            call.reject(PasskeyError.UNKNOWN.rawValue, error.localizedDescription)
            return
        }
        var errorDescription: String =
            switch authorizationError.code {
                case .notInteractive:
                    PasskeyError.USER_CANCELED_ERROR.rawValue
                case .failed:
                   PasskeyError.FAILED_ERROR.rawValue
                case .invalidResponse:
                     PasskeyError.INVALID_RESPONSE_ERROR.rawValue
                case .notHandled:
                    PasskeyError.NOT_HANDLED_ERROR.rawValue
                case .canceled:
                    PasskeyError.USER_CANCELED_ERROR.rawValue
                case .unknown:
                    PasskeyError.UNKNOWN.rawValue
                default:
                    PasskeyError.UNKNOWN.rawValue
            }
        print("WebAuthn Error Code: \(authorizationError.code.rawValue), Description: \(errorDescription)")
        call.reject(errorDescription, authorizationError.localizedDescription)
    }
}

/**
 * Please read the Capacitor iOS Plugin Development Guide
 * here: https://capacitorjs.com/docs/plugins/ios
 */
@objc(WebAuthnPlugin)
public class WebAuthnPlugin: CAPPlugin {
    private let implementation = WebAuthn()
    var signInHandler: GetAppleSignInHandler?
    
    override public func load() {
        implementation.setCredentialManager("hello");
    }
    
    @objc func isWebAuthnAvailable(_ call: CAPPluginCall) {
        call.resolve([
            "isWebAuthnAvailable": implementation.isWebAuthnAvailable()
        ])
    }
    
    @objc func isWebAuthnAutoFillAvailable(_ call: CAPPluginCall) {
        call.resolve([
            "isWebAuthnAutoFillAvailable": implementation.isWebAuthnAutoFillAvailable()
        ])
    }
    
    @objc func startRegistration(_ call: CAPPluginCall) {
        DispatchQueue.main.async {
            self.signInHandler = GetAppleSignInHandler(call: call, window: (self.bridge?.webView?.window)!)
            self.signInHandler?.register()
        }
    }
    
    @objc func startAuthentication(_ call: CAPPluginCall) {
        DispatchQueue.main.async {
            self.signInHandler = GetAppleSignInHandler(call: call, window: (self.bridge?.webView?.window)!)
            self.signInHandler?.authenticate()
        }
    }

}

extension GetAppleSignInHandler: ASAuthorizationControllerPresentationContextProviding {
    public func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
        return self.window
  }
}

