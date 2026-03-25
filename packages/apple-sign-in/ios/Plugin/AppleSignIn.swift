import Foundation
import AuthenticationServices

@objc public class AppleSignIn: NSObject {

    private var completion: ((_ result: SignInResult?, _ error: Error?) -> Void)?

    @objc public func signIn(_ options: SignInOptions, presentationContextProvider: ASAuthorizationControllerPresentationContextProviding, completion: @escaping (_ result: SignInResult?, _ error: Error?) -> Void) {
        NSLog("[AppleSignIn] signIn called with scopes: \(options.scopes), nonce: \(options.nonce != nil ? "present" : "nil")")
        self.completion = completion

        let provider = ASAuthorizationAppleIDProvider()
        let request = provider.createRequest()
        if !options.scopes.isEmpty {
            request.requestedScopes = options.scopes
        }
        if let nonce = options.nonce {
            request.nonce = nonce
        }

        NSLog("[AppleSignIn] Presenting authorization controller...")
        let controller = ASAuthorizationController(authorizationRequests: [request])
        controller.delegate = self
        controller.presentationContextProvider = presentationContextProvider
        controller.performRequests()
    }
}

extension AppleSignIn: ASAuthorizationControllerDelegate {
    public func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        NSLog("[AppleSignIn] Authorization completed successfully")
        guard let credential = authorization.credential as? ASAuthorizationAppleIDCredential else {
            NSLog("[AppleSignIn] ERROR: Failed to cast credential to ASAuthorizationAppleIDCredential")
            completion?(nil, CustomError.signInFailed)
            completion = nil
            return
        }
        NSLog("[AppleSignIn] Credential received, user ID: \(credential.user)")
        let result = SignInResult(credential: credential)
        completion?(result, nil)
        completion = nil
    }

    public func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        NSLog("[AppleSignIn] Authorization failed with error: \(error.localizedDescription)")
        let asError = error as? ASAuthorizationError
        if asError?.code == .canceled {
            NSLog("[AppleSignIn] User canceled")
            completion?(nil, CustomError.signInCanceled)
        } else {
            NSLog("[AppleSignIn] Sign in failed: \(error)")
            completion?(nil, CustomError.signInFailed)
        }
        completion = nil
    }
}
