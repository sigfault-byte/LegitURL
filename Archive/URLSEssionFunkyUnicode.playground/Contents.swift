import Foundation
import PlaygroundSupport

PlaygroundPage.current.needsIndefiniteExecution = true

let url = URL(string: "https://dravinom.xn--6frz82g/")! // cursed link,
//("Location"): https://dravinom.ç§»å¨/index.html -> respond with broken unicode that a browser resolves with dark sith magic
//

let config = URLSessionConfiguration.default
let session = URLSession(configuration: config, delegate: nil, delegateQueue: nil)

let task = session.dataTask(with: url) { data, response, error in
    if let error = error {
        print("Error: \(error.localizedDescription)")
        PlaygroundPage.current.finishExecution()
    }

    if let httpResponse = response as? HTTPURLResponse {
        print("Initial Status Code: \(httpResponse.statusCode)")
        print("Location Header:", httpResponse.allHeaderFields["Location"] ?? "No redirect")
    } else {
        print("No valid HTTP response")
    }

    PlaygroundPage.current.finishExecution()
}

task.resume()
