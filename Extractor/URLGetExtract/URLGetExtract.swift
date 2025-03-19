//
//  URLGetExtract.swift
//  LegitURL
//
//  Created by Chief Hakka on 14/03/2025.
//
import Foundation
import ASN1Decoder

class URLGetExtract: NSObject, URLSessionDelegate {
    
    static var sharedSession: URLSession?

    static func extract(urlInfo: URLInfo, completion: @escaping (OnlineURLInfo) -> Void) {
        guard let url = URL(string: urlInfo.components.fullURL ?? "") else {
            print("❌ Invalid URL for GET request:", urlInfo.components.fullURL ?? "nil")
            return
        }

        print("🚀 Starting MINIMAL GET request for:", url)

        // ✅ Minimal config
        let config = URLSessionConfiguration.default
        config.httpShouldSetCookies = false
        config.httpShouldUsePipelining = false
        config.httpMaximumConnectionsPerHost = 1
        config.timeoutIntervalForRequest = 10
        config.timeoutIntervalForResource = 15
        config.httpCookieAcceptPolicy = .never

        // ✅ Keep a reference to the session so the delegate remains alive
        let instance = URLGetExtract()
        sharedSession = URLSession(configuration: config, delegate: instance, delegateQueue: nil)

        var request = URLRequest(url: url)
        request.setValue("Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/537.36", forHTTPHeaderField: "User-Agent")
        request.httpMethod = "GET"

        print("🔍 Sending raw request to:", url)

        let task = sharedSession!.dataTask(with: request) { data, response, error in
            if let error = error {
                print("❌ Request failed:", error.localizedDescription)
                return
            }

            guard let httpResponse = response as? HTTPURLResponse else {
                print("⚠️ No valid response received.")
                return
            }

            print("✅ Response Received: \(httpResponse.statusCode)")
            print("📡 Response Headers:", httpResponse.allHeaderFields)
        }

        task.resume()
    }
    
    /// ✅ Handle SSL challenges & extract certificate details
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        print("✅ Created URLSession with delegate:", session)
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
    
    /// ✅ Extract SSL certificate details even if handshake fails
    func SSLExtract(trust: SecTrust) -> [String: Any] {
        var extractedDetails: [String: Any] = [:]

        // ✅ Get certificate chain
        var certChain: [SecCertificate] = []
        if #available(iOS 15.0, *) {
            if let certs = SecTrustCopyCertificateChain(trust) as? [SecCertificate] {
                certChain = certs
            }
        } else {
            let certCount = SecTrustGetCertificateCount(trust)
            for i in 0..<certCount {
                if let cert = SecTrustGetCertificateAtIndex(trust, i) {
                    certChain.append(cert)
                }
            }
        }

        if certChain.isEmpty {
            print("❌ No certificates found in trust chain.")
            extractedDetails["Error"] = "No SSL certificate found."
            return extractedDetails
        }

        // ✅ Process first certificate (leaf certificate)
        guard let cert = certChain.first else {
            print("❌ Failed to retrieve leaf certificate.")
            extractedDetails["Error"] = "Certificate retrieval failed."
            return extractedDetails
        }

        // ✅ Convert to Data
        guard let certData = SecCertificateCopyData(cert) as Data? else {
            print("❌ Failed to extract certificate data.")
            extractedDetails["Error"] = "Could not convert certificate."
            return extractedDetails
        }

        do {
            // ✅ Use `X509Certificate` to decode everything at once
            let decodedCertificate = try X509Certificate(data: certData)
            
            extractedDetails["Subject"] = decodedCertificate.subjectDistinguishedName
            extractedDetails["Issuer"] = decodedCertificate.issuerDistinguishedName
            extractedDetails["Serial Number"] = decodedCertificate.serialNumber
            extractedDetails["Public Key Algorithm"] = decodedCertificate.publicKey
            extractedDetails["Validity"] = [
                "Not Before": decodedCertificate.notBefore,
                "Not After": decodedCertificate.notAfter
            ]

            // ✅ Check if certificate is expired
            if let expirationDate = decodedCertificate.notAfter, expirationDate < Date() {
                extractedDetails["Warning"] = "⚠️ Certificate is expired!"
            }

            print("🔐 Parsed Certificate Details:", extractedDetails)

        } catch {
            print("❌ Failed to decode certificate:", error.localizedDescription)
            extractedDetails["Error"] = "X509 parsing failed."
        }

        return extractedDetails
    }
}
