import Foundation

let paths = [
    "/_next/static/chunks/fd9d1056-c07a78c5d535bea4.js",
    "/_next/static/chunks/main-app-6f0b34eb81b2baab.js",
    "/_next/static/chunks/8b9c1878-e0950841cd716641.js",
    "/_next/static/runtime/webpack.js"
]

// base path
func basePath(_ path: String) -> String {
    let components = path.split(separator: "/")
    return components.prefix(4).joined(separator: "/")
}

//  filename
func fileName(_ path: String) -> String {
    return path.split(separator: "/").last.map(String.init) ?? ""
}

// Simple n-gram similarity 3G
func ngrams(_ word: String, n: Int = 3) -> Set<String> {
    guard word.count >= n else { return [word] }
    return Set((0...(word.count - n)).map {
        let start = word.index(word.startIndex, offsetBy: $0)
        let end = word.index(start, offsetBy: n)
        return String(word[start..<end])
    })
}

func jaccard(_ a: Set<String>, _ b: Set<String>) -> Double {
    let intersection = a.intersection(b).count
    let union = a.union(b).count
    return union == 0 ? 0 : Double(intersection) / Double(union)
}

// Cluster by filename similarity
let filenames = paths.map(fileName)
var clusters: [[String]] = []

for file in filenames {
    let gramsA = ngrams(file)
    var matched = false

    for i in 0..<clusters.count {
        if let first = clusters[i].first, jaccard(gramsA, ngrams(first)) > 0.5 {
            clusters[i].append(file)
            matched = true
            break
        }
    }

    if !matched {
        clusters.append([file])
    }
}

for group in clusters {
    print("Group of \(group.count):", group)
}
