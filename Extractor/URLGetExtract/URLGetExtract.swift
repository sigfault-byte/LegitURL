//
//  URLGetExtract.swift
//  LegitURL
//
//  Created by Chief Hakka on 14/03/2025.
//
import Foundation
import ASN1Decoder

class URLGetExtract: NSObject, URLSessionDelegate {
    
    static func extract(urlInfo: URLInfo, completion: @escaping (OnlineURLInfo) -> Void) {
        guard let url = URL(string: urlInfo.components.fullURL ?? "") else {
            print("❌ Invalid URL for GET request:", urlInfo.components.fullURL ?? "nil")
            return
        }
        
        let config = URLSessionConfiguration.default
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        print("config: ", config)
        let session = URLSession(configuration: config)
        
        // Prepare request with stripped tracking headers
        // Prepare request with stripped tracking headers but keep iOS-like behavior
        var request = URLRequest(url: url)
        let defaultUserAgent = "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)"
        request.httpMethod = "GET"
        request.setValue("*/*", forHTTPHeaderField: "Accept")  // Accept all response types
        request.setValue("no-cache", forHTTPHeaderField: "Cache-Control")  // Prevent caching
        request.setValue(defaultUserAgent, forHTTPHeaderField: "User-Agent")  // Use a normal iOS User-Agent
        request.setValue(nil, forHTTPHeaderField: "Authorization")  // Remove authentication tracking
        request.setValue("en-US,en;q=0.9", forHTTPHeaderField: "Accept-Language")
        
        
        let task = session.dataTask(with: request) { data, response, error in
            var onlineInfo = OnlineURLInfo(from: urlInfo)
            if let httpResponse = response as? HTTPURLResponse {
            
                // ✅ Extract headers
                let headers = httpResponse.allHeaderFields as? [String: String] ?? [:]
                
                // ✅ Extract final redirect URL (if any)
                let finalURL = httpResponse.url?.absoluteString
                
                // ✅ Update OnlineURLInfo
                onlineInfo.serverResponseCode = httpResponse.statusCode
                onlineInfo.responseHeaders = headers
                onlineInfo.finalRedirectURL = finalURL
            } else {
                print("⚠️ Failed to fetch \(url)")
            }
            DispatchQueue.main.async {
                completion(onlineInfo)
            }
        }
        task.resume()
    }

    /// ✅ Handle SSL challenges & extract certificate details
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        if let serverTrust = challenge.protectionSpace.serverTrust {
            print("🔍 SSL Challenge received for:", challenge.protectionSpace.host)

            // ✅ Extract SSL certificate details
            let certDetails = SSLExtract(trust: serverTrust)

            print("🔐 SSL Certificate Details:", certDetails)
            
            // ✅ Allow the request if SSL is valid
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            print("❌ No server trust available.")
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
    
    /// ✅ Extract SSL certificate details
    func SSLExtract(trust: SecTrust) -> [String: Any] {
        var extractedDetails: [String: Any] = [:]
        
        guard let certs = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let certData = SecCertificateCopyData(certs.first!) as Data? else {
            print("❌ Failed to retrieve certificate data.")
            return extractedDetails
        }
        
        do {
            // ✅ Decode using X509Certificate
            let decodedCertificate = try X509Certificate(data: certData)
//            print("🔍 Decoded SSL Certificate:", decodedCertificate)
            
            // ✅ Extract useful fields
            extractedDetails["Issuer"] = decodedCertificate.issuerDistinguishedName
            extractedDetails["Subject"] = decodedCertificate.subjectDistinguishedName
            extractedDetails["Validity"] = [
                "Not Before": decodedCertificate.notBefore,
                "Not After": decodedCertificate.notAfter
            ]
            extractedDetails["Public Key Info"] = decodedCertificate.publicKey
            
//            print("✅ Extracted Certificate Details:", extractedDetails)
            
        } catch {
            print("❌ Failed to decode X.509 Certificate:", error)
        }
        
        return extractedDetails
    }
}
