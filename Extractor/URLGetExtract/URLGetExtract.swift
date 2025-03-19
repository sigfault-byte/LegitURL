//
//  URLGetExtract.swift
//  LegitURL
//
//  Created by Chief Hakka on 14/03/2025.
//
import Foundation
import ASN1Decoder

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
        // Copy the original URLInfo to update it if needed.
        var updatedURLInfo = urlInfo
        
        // Construct the URL from the URLInfo components.
        // Ensure that both scheme (e.g., "https") and host (e.g., "example.com") are available.
        guard let scheme = urlInfo.components.scheme,
              let host = urlInfo.components.host else {
            print("❌ Invalid URL components for GET request:", urlInfo.components.fullURL ?? "nil")
            return
        }
        
        // Use the path provided in URLInfo if available; otherwise, default to "/".
        let path = urlInfo.components.path ?? "/"
        // Construct a sanitized URL string.
        let sanitizedURLString = "\(scheme)://\(host)\(path)"
        // Convert the sanitized URL string into a URL object.
        guard let url = URL(string: sanitizedURLString) else {
            print("❌ Failed to construct valid URL:", sanitizedURLString)
            return
        }
        
        // Log the URL we are probing and starting a GET request for.
        print("🚀 Probing:", sanitizedURLString)
        print("🚀 Starting GET request for:", url)
        
        // Create a URLRequest for the URL.
        var request = URLRequest(url: url)
        request.httpMethod = "GET" // Specify the HTTP method.
        // Set the User-Agent header to mimic a browser.
        request.setValue("Mozilla/5.0", forHTTPHeaderField: "User-Agent")
        // Accept any content type.
        request.setValue("*/*", forHTTPHeaderField: "Accept")
        // Set the Connection header to "close" to prevent persistent connections.
        request.setValue("close", forHTTPHeaderField: "Connection")
        
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
            if let error = error {
                completion(nil, error)
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
            let headers = httpResponse.allHeaderFields as? [String: String] ?? [:]
            
            let sslCertificateDetails = URLGetExtract.sslCertificateDetails
            
            // Create an OnlineURLInfo object that encapsulates the response details.
            let onlineInfo = OnlineURLInfo(
                from: urlInfo,
                responseCode: statusCode,
                statusText: statusText,
                headers: headers,
                body: data,
                certificateAuthority: sslCertificateDetails["Issuer"] as? String,
                sslValidity: !(sslCertificateDetails["Warning"] != nil),
                finalRedirectURL: httpResponse.url?.absoluteString
            )
            
            // Pass the response and updated URLInfo to the completion handler.
            if let error = error {
                completion(nil, error)
            } else {
                completion(onlineInfo, nil)
            }
        }
        // Start the data task.
        task.resume()
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
        
        print("🔍 SSL Challenge received for:", challenge.protectionSpace.host)
        
        var sslCertificateDetails: [String: Any] = [:]
        
        // ✅ Extract certificate details using ASN1Decoder
        if let certificateChain = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate],
           let firstCertificate = certificateChain.first {
            
            // ✅ Convert SecCertificate to raw Data
            let certificateData = SecCertificateCopyData(firstCertificate) as Data
            
            // ✅ Decode the certificate using ASN1Decoder
            if let decodedCertificate = try? X509Certificate(data: certificateData) {
                print("✅ Successfully decoded certificate", decodedCertificate)
                
                sslCertificateDetails["Issuer"] = decodedCertificate.issuerDistinguishedName
                sslCertificateDetails["Issuer Organization"] = decodedCertificate.issuer(oid: .organizationName)
                sslCertificateDetails["Validity"] = [
                    "Not Before": decodedCertificate.notBefore,
                    "Not After": decodedCertificate.notAfter
                ]
            } else {
                print("❌ Failed to decode certificate using ASN1Decoder")
            }
        }
        
        // ✅ Store extracted details globally
        URLGetExtract.sslCertificateDetails = sslCertificateDetails
        
        // Accept the SSL certificate
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    }
}
