import Foundation
import CryptoKit
//let's try to mimic curl -s https://github.githubassets.com/assets/global-banner-disable-f988792be49f.js | shasum
//let scriptURL = URL(string: "https://github.githubassets.com/assets/global-banner-disable-f988792be49f.js")!
//
//<script integrity="sha256-w1TMG8bx+vw+BuOfT7Dh2avfdjByyjlNYGyp9vJB5oo=" data-source-attribution="shopify.loadfeatures" defer="defer" src="//hiutdenim.co.uk/cdn/shopifycloud/shopify/assets/storefront/load_feature-c354cc1bc6f1fafc3e06e39f4fb0e1d9abdf763072ca394d606ca9f6f241e68a.js" crossorigin="anonymous"></script>

let scriptURL = URL(string: "https://hiutdenim.co.uk/cdn/shopifycloud/shopify/assets/storefront/load_feature-c354cc1bc6f1fafc3e06e39f4fb0e1d9abdf763072ca394d606ca9f6f241e68a.js")!

let task = URLSession.shared.dataTask(with: scriptURL) { data, response, error in
    guard let data = data, error == nil else {
        print("Download error:", error ?? "Unknown error")
        return
    }

    if let httpResponse = response as? HTTPURLResponse {
        print("Status code:", httpResponse.statusCode)
        print("Headers:")
        for (key, value) in httpResponse.allHeaderFields {
            print("\(key): \(value)")
        }
    }
    
    //  SHA256 hash
    let hash = SHA256.hash(data: data)
    
    // Convert to base64
    let sriBase64 = Data(hash).base64EncodedString()
    
    let human = String(data: data, encoding: .utf8)

    
    print("data :", human ?? "nothing to see here")
    print("SRI hash:")
    print("sha256-\(sriBase64)")
}

task.resume()
