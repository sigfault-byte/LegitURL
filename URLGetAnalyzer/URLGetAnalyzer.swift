//
//  URLGetAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 14/03/2025.
//
import Foundation
import ASN1Decoder

class URLGetAnalyzer: NSObject, URLSessionDelegate {
    
    static func analyze(urlInfo: URLInfo, completion: @escaping (OnlineURLInfo) -> Void) {
        guard let url = URL(string: urlInfo.components.fullURL ?? "") else {
            print("❌ Invalid URL for GET request:", urlInfo.components.fullURL ?? "nil")
            return
        }
        
        let delegateInstance = URLGetAnalyzer()
        let session = URLSession(configuration: .default, delegate: delegateInstance, delegateQueue: nil)
        let task = session.dataTask(with: url) { data, response, error in
            var onlineInfo = OnlineURLInfo(from: urlInfo)
            if let httpResponse = response as? HTTPURLResponse {
                print("✅ Fetched \(url) → Status:", httpResponse.statusCode)
                
                // ✅ Extract headers
                let headers = httpResponse.allHeaderFields as? [String: String] ?? [:]
                print("📝 Response Headers:", headers)
                
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
            print("🔍 Decoded SSL Certificate:", decodedCertificate)
            
            // ✅ Extract useful fields
            extractedDetails["Issuer"] = decodedCertificate.issuerDistinguishedName
            extractedDetails["Subject"] = decodedCertificate.subjectDistinguishedName
            extractedDetails["Validity"] = [
                "Not Before": decodedCertificate.notBefore,
                "Not After": decodedCertificate.notAfter
            ]
            extractedDetails["Public Key Info"] = decodedCertificate.publicKey
            
            print("✅ Extracted Certificate Details:", extractedDetails)
            
        } catch {
            print("❌ Failed to decode X.509 Certificate:", error)
        }
        
        return extractedDetails
    }
}
