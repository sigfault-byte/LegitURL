import Foundation
import PlaygroundSupport

PlaygroundPage.current.needsIndefiniteExecution = true

let url = URL(string: "https://www.ratp.fr")!

var receivedCookies: [HTTPCookie] = []

// MARK: - Step 1: Initial Request to get cookies
var initialRequest = URLRequest(url: url)
initialRequest.httpMethod = "GET"

let session = URLSession(configuration: .default)

let task1 = session.dataTask(with: initialRequest) { data, response, _ in
    guard let httpResponse = response as? HTTPURLResponse else {
        print("Failed to get HTTP response.")
        return
    }
    
    print("First request status: \(httpResponse.statusCode)")
    
    if let headers = httpResponse.allHeaderFields as? [String: String],
       let url = response?.url {
        let cookies = HTTPCookie.cookies(withResponseHeaderFields: headers, for: url)
        receivedCookies = cookies
        
        for cookie in cookies {
            print("🍪 🍪 🍪 🍪 🍪 Cookie received: \(cookie.name)=\(cookie.value)")
        }
    }
    
    // MARK: - Step 2: Second request with cookies
    var secondRequest = URLRequest(url: url)
    secondRequest.httpMethod = "GET"
    
    let cookieHeader = HTTPCookie.requestHeaderFields(with: receivedCookies)
    secondRequest.allHTTPHeaderFields = cookieHeader
    
    let task2 = session.dataTask(with: secondRequest) { data, response, _ in
        guard let httpResponse2 = response as? HTTPURLResponse else {
            print("Second request failed.")
            return
        }
        
        print("Second request status: \(httpResponse2.statusCode)")
        if let data = data, let html = String(data: data, encoding: .utf8) {
            print("Body contains: \(html.prefix(200))...\n")
        }
        
        PlaygroundPage.current.finishExecution()
    }
    
    task2.resume()
}

task1.resume()


// Funny but useless
//if headers["server"]?.contains("cloudflare") == true,
//   headers["cf-ray"] != nil,
//   responseCode == 403,
//   cookies.contains(where: { $0.name == "__cf_bm" }),
//   let bodySize = body?.utf8.count, bodySize < 9000
//{
//    let rawFingerprint = """
//    CF-RAY:\(headers["cf-ray"]!)
//    COOKIE:\(__cf_bm.value)
//    BODY_SIZE:\(bodySize)
//    MESSAGE: HOTDOGWATER
//    """
//    let rotated = rot13(rawFingerprint)
//    let encoded = Data(rotated.utf8).base64EncodedString()
//    let botProofToken = "ANTI_CF_BAD_" + encoded
//
//
//    print(botProofToken)
//    
//    // Return as synthetic cookie with the custom value
//    response.setCookie(name: "CF_BF", value: botProofToken)
//}
