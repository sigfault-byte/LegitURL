//
//  URLGetExtract.swift
//  LegitURL
//
//  Created by Chief Hakka on 14/03/2025.
//
import Foundation
import ASN1Decoder
import ObjectiveC

// This class is responsible for making a GET request to a URL constructed from URLInfo.
// It cancels any HTTP redirection, so you receive the original response (e.g., a 301) instead of following the redirect.
// It also handles SSL challenges by simply accepting the provided certificate.
class URLGetExtract: NSObject, URLSessionDelegate, URLSessionTaskDelegate {
    
    // Shared instance used as the delegate for URLSession tasks.
    static let sharedInstance = URLGetExtract()
    
    // Store SSL certificate details globally
    static var sslCertificateDetails: [String: Any] = [:]
    
    // It takes a URLInfo object and a completion handler, then returns an OnlineURLInfo and an updated URLInfo.
    static func extract(urlInfo: URLInfo, completion: @escaping (OnlineURLInfo?, Error?) -> Void) {
        
        // Construct the URL from the URLInfo components.
        // Ensure that both scheme (e.g., "https") and host (e.g., "example.com") are available.
        guard let scheme = urlInfo.components.scheme,
              let host = urlInfo.components.host else {
            print("❌ Invalid URL components for GET request:", urlInfo.components.fullURL ?? "nil")
            return
        }
        
        // Use the path provided in URLInfo if available; otherwise, default to "/".
        let path = urlInfo.components.path ?? "/"
        // Construct a sanitized URL string. Lowercased for weird reasons
        let sanitizedURLString = "\(scheme.lowercased())://\(host.lowercased())\(path)"
        // Convert the sanitized URL string into a URL object.
        guard let url = URL(string: sanitizedURLString) else {
            print("❌ Failed to construct valid URL:", sanitizedURLString)
            return
        }
        
        // Create a URLRequest for the URL.
        var request = URLRequest(url: url)
        request.httpMethod = "GET" // Specify the HTTP method.
        // Set the User-Agent header to mimic a browser.
        request.setValue("Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
                         forHTTPHeaderField: "User-Agent")
        request.setValue("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", forHTTPHeaderField: "Accept")
        request.setValue("gzip, deflate, br", forHTTPHeaderField: "Accept-Encoding")
        request.timeoutInterval = 10
        
        // Configure a dedicated URLSession for this request.
        let config = URLSessionConfiguration.default
        // Ignore any locally cached data.
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        // Disable cookie storage and caching.
        config.httpCookieStorage = nil
        config.urlCache = nil
        config.httpShouldSetCookies = false
        // Disable HTTP pipelining.
        config.httpShouldUsePipelining = false
        // Limit connections to one per host.
        config.httpMaximumConnectionsPerHost = 1
        // Set timeout intervals.
        config.timeoutIntervalForRequest = 10
        config.timeoutIntervalForResource = 15
        // Never accept cookies.
        config.httpCookieAcceptPolicy = .never
        // Create a new URLSession using the configuration and set the delegate to the shared instance.
        let session = URLSession(configuration: config, delegate: sharedInstance, delegateQueue: nil)
        
        // Create a data task with the request.
        let task = session.dataTask(with: request) { data, response, error in
            // Handle any errors that occur during the request.
            if let error = error as NSError? {
                if error.code == NSURLErrorCancelled {
                    // Task was cancelled manually (likely due to our timeout)
                    completion(nil, NSError(domain: NSURLErrorDomain, code: NSURLErrorTimedOut, userInfo: [NSLocalizedDescriptionKey: "Request timed out"]))
                } else {
                    completion(nil, error)
                }
                return
            }
            
            // Ensure that the response is a valid HTTP response.
            guard let httpResponse = response as? HTTPURLResponse else {
                let error = NSError(domain: "URLGetExtract", code: -1, userInfo: [NSLocalizedDescriptionKey: "❌ No valid HTTP response received."])
                completion(nil, error)
                return
            }
            
            // Extract relevant response details: status code, status text, and headers.
            let statusCode = httpResponse.statusCode
            let statusText = HTTPURLResponse.localizedString(forStatusCode: statusCode)
            var normalizedHeaders: [String: String] = [:]
            //            let normalizedHeaders = Dictionary(uniqueKeysWithValues: httpResponse.allHeaderFields.compactMap {
            //                guard let key = $0.key as? String, let value = $0.value as? String else { return nil }
            //                return (key.lowercased(), value)
            //            })
            // One liner is horrible this is more readable
            for (key, value) in httpResponse.allHeaderFields {
                if let keyString = key as? String, let valueString = value as? String {
                    normalizedHeaders[keyString.lowercased()] = valueString
                }
            }
            let parsedHeaders = parseHeaders(httpResponse.allHeaderFields)
            
            
            let sslCertificateDetails = URLGetExtract.sslCertificateDetails
            
            // Create an OnlineURLInfo object that encapsulates the response details.
            var onlineInfo = OnlineURLInfo(
                from: urlInfo,
                responseCode: statusCode,
                statusText: statusText,
                normalizedHeaders: normalizedHeaders, // Keep raw headers
                parsedHeaders: parsedHeaders,
                body: data,
                certificateAuthority: sslCertificateDetails["Issuer"] as? String,
                sslValidity: !(sslCertificateDetails["Warning"] != nil),
                finalRedirectURL: parsedHeaders.otherHeaders["location"]
            )
            let parsedCert = sslCertificateDetails["ParsedCertificate"] as? ParsedCertificate
            onlineInfo.parsedCertificate = parsedCert
            
            if let bodyData = data, let bodyText = String(data: bodyData, encoding: .utf8) {
                onlineInfo.humanBodySize = bodyData.count
                onlineInfo.humanReadableBody = bodyText
            } else {
                onlineInfo.humanReadableBody = "⚠️ Unable to decode body"
            }
            
            // Pass the response and updated URLInfo to the completion handler.
            if let error = error {
                completion(nil, error)
            } else {
                completion(onlineInfo, nil)
            }
        }
        // Start the data task.
        task.resume()
        
        
        Task.detached {
            try? await Task.sleep(nanoseconds: 10 * 1_000_000_000)
            if task.state == .running {
                task.cancel()
            }
        }
    }
    
    // New async version of the extract function
    static func extractAsync(urlInfo: URLInfo) async throws -> OnlineURLInfo {
        try await withCheckedThrowingContinuation { continuation in
            extract(urlInfo: urlInfo) { onlineInfo, error in
                if let error = error {
                    continuation.resume(throwing: error)
                } else if let info = onlineInfo {
                    continuation.resume(returning: info)
                } else {
                    let unknownError = NSError(domain: "URLGetExtract", code: -999, userInfo: [NSLocalizedDescriptionKey: "Unknown error occurred during extract."])
                    continuation.resume(throwing: unknownError)
                }
            }
        }
    }
    
    
    
    // URLSessionTaskDelegate method:
    // This method is called when a redirect response is received.
    // By calling completionHandler(nil), we cancel the redirect so that the URLSession returns the original response.
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        print("🔄 Redirect cancelled. Returning original response.")
        completionHandler(nil)
    }
    
    // URLSessionDelegate method for handling SSL challenges.
    // When an SSL challenge is received, this method simply accepts the server's certificate.
    // It logs the host for which the SSL challenge is being processed.
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            print("❌ No valid server trust found.")
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        var sslCertificateDetails: [String: Any] = [:]
        
        // ✅ Extract certificate details using ASN1Decoder
        if let certificateChain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate],
           let firstCertificate = certificateChain.first {
            
            let certificateData = SecCertificateCopyData(firstCertificate) as Data
            
            if let decodedCertificate = try? X509Certificate(data: certificateData){
                
                sslCertificateDetails["Issuer"] = decodedCertificate.issuerDistinguishedName
                sslCertificateDetails["Issuer Organization"] = decodedCertificate.issuer(oid: .organizationName)
                sslCertificateDetails["Validity"] = [
                    "Not Before": decodedCertificate.notBefore,
                    "Not After": decodedCertificate.notAfter
                ]
                
                let parsedCert = ParsedCertificate(
                    commonName: decodedCertificate.subject(oid: .commonName)?.first,
                    organization: decodedCertificate.subject(oid: .organizationName)?.first,
                    issuerCommonName: decodedCertificate.issuer(oid: .commonName),
                    issuerOrganization: decodedCertificate.issuer(oid: .organizationName),
                    notBefore: decodedCertificate.notBefore,
                    notAfter: decodedCertificate.notAfter,
                    publicKeyAlgorithm: {
                        if let oid = decodedCertificate.publicKey?.algOid,
                           let named = OID(rawValue: oid) {
                            return "\(named)"
                        }
                        return decodedCertificate.publicKey?.algOid
                    }(),
                    keyUsage: decodedCertificate.keyUsage.enumerated().compactMap { index, isSet in
                        isSet ? ["Digital Signature", "Non-Repudiation", "Key Encipherment", "Data Encipherment", "Key Agreement", "Cert Sign", "CRL Sign", "Encipher Only", "Decipher Only"][index] : nil
                    }.joined(separator: ", "),  // Convert Key Usage Bits
                    publicKeyBits: inferredPublicKeyBits(from: decodedCertificate),
                    extendedKeyUsageOID: decodedCertificate.extendedKeyUsage.joined(separator: ", "),
                    extendedKeyUsageString: parseEKUs(from: decodedCertificate.extendedKeyUsage.joined(separator: ", ")),
                    certificatePolicyOIDs: extractCertificatePolicyOIDs(from: decodedCertificate),
                    isSelfSigned: decodedCertificate.subjectDistinguishedName == decodedCertificate.issuerDistinguishedName,
                    subjectAlternativeNames: decodedCertificate.subjectAlternativeNames
                )
                print(parsedCert.certificatePolicyOIDs)
                sslCertificateDetails["ParsedCertificate"] = parsedCert
            } else {
                print("❌ Failed to decode certificate using ASN1Decoder")
            }
        }
        
        // ✅ Store extracted details globally
        URLGetExtract.sslCertificateDetails = sslCertificateDetails
        
        // Accept the SSL certificate, this is terrible but necessary
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }
    
    private static func parseHeaders(_ responseHeaders: [AnyHashable: Any]) -> ParsedHeaders {
        var normalizedHeaders: [String: String] = [:]
        
        // ✅ Convert headers to lowercase for case-insensitivity
        for (key, value) in responseHeaders {
            if let keyString = key as? String, let valueString = value as? String {
                normalizedHeaders[keyString.lowercased()] = valueString
            }
        }
        
        // ✅ Categorize headers
        var parsedHeaders = ParsedHeaders()
        
        for (key, value) in normalizedHeaders {
            if ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy"].contains(key) {
                parsedHeaders.securityHeaders[key] = value
            } else if ["set-cookie", "etag", "permissions-policy"].contains(key) {
                parsedHeaders.trackingHeaders[key] = value
            } else if ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"].contains(key) {
                parsedHeaders.serverHeaders[key] = value
            } else {
                parsedHeaders.otherHeaders[key] = value
            }
        }
        
        return parsedHeaders
    }
    
    func inferredPublicKeyBits(from cert: X509Certificate) -> Int? {
        guard let algOID = cert.publicKey?.algOid,
              let keyOID = OID(rawValue: algOID) else { return nil }
        
        switch keyOID {
        case .rsaEncryption:
            if let keyByteCount = cert.publicKey?.key?.count {
                return keyByteCount * 8
            }
        case .ecPublicKey:
            guard let curveOID = cert.publicKey?.algParams else { return nil }
            switch curveOID {
            case OID.prime256v1.rawValue: return 256
                // coudnt find ECC alg in the library
            case "1.3.132.0.34": return 384  // secp384r1
            case "1.3.132.0.35": return 521  // secp521r1
            default: return nil
            }
        default:
            return nil
        }
        
        return nil
    }
    
    // Helper function to extract certificate policy OIDs from a decoded certificate
    func extractCertificatePolicyOIDs(from decodedCertificate: X509Certificate) -> String {
        guard let certPoliciesExt = decodedCertificate.extensionObject(oid: OID.certificatePolicies)
                as? X509Certificate.CertificatePoliciesExtension else {
            return ""
        }
        
        for policy in certPoliciesExt.policies ?? [] {
            print("Policy OID: \(policy.oid)")
            for qualifier in policy.qualifiers ?? [] {
                print("  ↪ Qualifier OID: \(qualifier.oid)")
                print("  ↪ Qualifier Value: \(qualifier.value ?? "No value")")
            }
        }
        
        return certPoliciesExt.policies?.map { $0.oid }.joined(separator: ", ") ?? ""
    }
    
}
