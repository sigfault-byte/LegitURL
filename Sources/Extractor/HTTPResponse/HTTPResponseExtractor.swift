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
// TODO: Need another delegate, low levelish, to intercept the body len it s decompressed by urlsession to compare to the header's value
class HTTPResponseExtractor: NSObject, URLSessionDelegate, URLSessionTaskDelegate {
    
    // Shared instance used as the delegate for URLSession tasks.
    static let sharedInstance = HTTPResponseExtractor()
    
    // Store SSL certificate details globally
    var sslCertificateDetails: [String: Any] = [:]
    
    // It takes a URLInfo object and a completion handler, then returns an OnlineURLInfo and an updated URLInfo.
    static func extract(urlInfo: URLInfo, completion: @escaping (OnlineURLInfo?, Error?) -> Void) {
        
        // Construct the URL from the URLInfo components.
        // Ensure that both scheme (e.g., "https") and host (e.g., "example.com") are available.
        guard let scheme = urlInfo.components.scheme,
              let host = urlInfo.components.host else {
//            print("Invalid URL components for GET request:", urlInfo.components.fullURL ?? "nil")
            return
        }
        
        // Use the path provided in URLInfo if available; otherwise, default to "/".
        let path = urlInfo.components.path ?? "/"
        // Construct a sanitized URL string. Lowercased for weird reasons
        let sanitizedURLString = "\(scheme.lowercased())://\(host.lowercased())\(path)"
        // Convert the sanitized URL string into a URL object.
        guard let url = URL(string: sanitizedURLString) else {
//            print("Failed to construct valid URL:", sanitizedURLString)
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
            
            let sslCertificateDetails = sharedInstance.sslCertificateDetails
            let parsedCert = sslCertificateDetails["ParsedCertificate"] as? ParsedCertificate
            
//            let maxSafeBodySize = 4_000_000 // ~ 4MB
            

            // Now, create your OnlineURLInfo using the processed data:
            var onlineInfo = OnlineURLInfo(
                from: urlInfo,
                responseCode: statusCode,
                statusText: statusText,
                normalizedHeaders: normalizedHeaders,
                parsedHeaders: nil,
                rawBody: data,
                certificateAuthority: sslCertificateDetails["Issuer"] as? String,
                sslValidity: !(sslCertificateDetails["Warning"] != nil),
                parsedCertificate: parsedCert,
                finalRedirectURL: httpResponse.value(forHTTPHeaderField: "location")
            )
            
            // Very terrible cookie parser on a flatten Header response.... Works but a print output is really weird
            var extractedCookies: [HTTPCookie] = []
            if let url = httpResponse.url {
                let headerFields: [String: String] = httpResponse.allHeaderFields.reduce(into: [:]) { result, pair in
                    if let key = pair.key as? String {
                        result[key] = "\(pair.value)"
                    }
                }
                extractedCookies = HTTPCookie.cookies(withResponseHeaderFields: headerFields, for: url)
                onlineInfo.extractedCookies = extractedCookies
            }
//            print (extractedCookies)
            
            // TODO: Detect and respect encoding using BOM or <meta charset="..."> in the first 500 bytes
            // Example: <!DOCTYPE html><html lang="fr"><head><meta charset="iso-8859-1"> -> french website living in 1980
            // NO BOM most fo the time :((((
            // TODO: This block may still be assigning the full body even when humanReadableBody was already truncated earlier.
            // Need to rework this logic to prevent overwriting the preview with the full body unintentionally.
//            if processedBody.count <= 1_000_000 {
//                let fullBodyText: String? =
//                    String(data: processedBody, encoding: .utf8) ??
//                    String(data: processedBody, encoding: .isoLatin1) ??
//                    String(data: processedBody, encoding: .utf16)
//                if let fullBodyText = fullBodyText {
//                    onlineInfo.humanReadableBody = fullBodyText
//                } else {
//                    onlineInfo.humanReadableBody = "Unable to decode body"
//                }
//            }
//            onlineInfo.humanBodySize = processedBody.count
            
            // Pass the response and updated URLInfo to the completion handler.
            completion(onlineInfo, nil)
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
        
//    TODO: Delegate to limit html size
//    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
//        totalBytesReceived += data.count
//        if totalBytesReceived > maxSafeSize {
//            dataTask.cancel()
//        } else {
//            buffer.append(data)
//        }
//    }
    
    // URLSessionTaskDelegate method:
    // This method is called when a redirect response is received.
    // By calling completionHandler(nil), we cancel the redirect so that the URLSession returns the original response.
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
//        print("🔄 Redirect cancelled. Returning original response.")
        completionHandler(nil)
    }
    
    /// Delegate to save the TLS and check its content
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @Sendable @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        TLSExtractor().extract(session, didReceive: challenge, completionHandler: completionHandler)
    }
    
    // TODO: This could be cross-checked with headers to help infer server types and behavior
    // logic commented for future analysis and debugging
//    func urlSession(_ session: URLSession, task: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) {
//        for transaction in metrics.transactionMetrics {
//            print("DNS : \(transaction.domainLookupStartDate ?? .distantPast) to \(transaction.domainLookupEndDate ?? .distantFuture)")
//            print("Remote IP: \(transaction.remoteAddress ?? "unknown")")
//            print("Protocol: \(transaction.networkProtocolName ?? "unknown")")
//            print("TTFB: \(transaction.responseStartDate?.timeIntervalSince(transaction.requestStartDate ?? Date()) ?? -1) seconds")
//            print("TLS Duration: \(transaction.secureConnectionEndDate?.timeIntervalSince(transaction.secureConnectionStartDate ?? Date()) ?? -1) seconds")
//        }
//    }
        
    
 
    
}
