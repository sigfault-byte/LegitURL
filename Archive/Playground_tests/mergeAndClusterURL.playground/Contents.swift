import Foundation

func findCommonCore(paths: [String]) -> String? {
    guard let firstPath = paths.first else { return nil }
    var commonPrefix = firstPath

    for path in paths.dropFirst() {
        var currentPrefix = ""
        for (char1, char2) in zip(commonPrefix, path) {
            if char1 == char2 {
                currentPrefix.append(char1)
            } else {
                break
            }
        }
        commonPrefix = currentPrefix
        if commonPrefix.isEmpty {
            return nil // No common prefix found
        }
    }

    // the last slash in the common prefix as the end of the core
    if let lastSlashIndex = commonPrefix.lastIndex(of: "/") {
        return String(commonPrefix[...lastSlashIndex])
    } else if !commonPrefix.isEmpty {
        // common prefix but no slash
        if let url = URL(string: paths.first ?? ""), let host = url.host {
            if commonPrefix.hasPrefix(host) {
                return host
            }
        }
        return commonPrefix
    }

    return nil
}

func ngrams(_ string: String, n: Int) -> Set<String> {
    guard string.count >= n else { return [] }
    var result = Set<String>()
    let chars = Array(string)
    for i in 0...(chars.count - n) {
        let slice = chars[i..<i+n]
        result.insert(String(slice))
    }
    return result
}

func jaccardIndex(_ a: Set<String>, _ b: Set<String>) -> Double {
    let intersection = a.intersection(b)
    let union = a.union(b)
    return union.isEmpty ? 0 : Double(intersection.count) / Double(union.count)
}
// Thereshold both ngram and threshold for jaccard. But  missing precisious on the "maximum similarity
//3gram + 0.3 seems to be the best, but still not good enough, i works for the exxample, but its linked to the structure. So it would require to dynamically tune the values?
func processScriptsForModel(scripts: [String], ngramSize: Int = 3, threshold: Double = 0.3) -> [String: [String]] {
    var normalizedScripts = scripts.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
    var clusters: [[String]] = []

    for script in normalizedScripts {
        var fail = true
        let scriptNGrams = ngrams(script, n: ngramSize)
        
        for i in 0..<clusters.count {
            if let representative = clusters[i].first {
                let repNGrams = ngrams(representative, n: ngramSize)
                if jaccardIndex(scriptNGrams, repNGrams) >= threshold {
                    clusters[i].append(script)
                    fail = false
                    break
                }
            }
        }

        if fail {
            clusters.append([script])
        }
    }

    var result: [String: [String]] = [:]

    for cluster in clusters {
        if let core = findCommonCore(paths: cluster) {
            let diffs = cluster.map { $0.hasPrefix(core) ? String($0.dropFirst(core.count)) : $0 }
            result["group: \(core)"] = diffs
        } else {
            for item in cluster {
                result["group: \(item)"] = []
            }
        }
    }

    return result
}

let scriptSources = [
    "Example.com/path/2737.js",
    "Example.com/path/123/we.js",
    "Example.com/path/other/file.css",
    "Example.com/another/thing.html",
    "Example.com/another/stuff.php",
    "Different.org/page.html",
    "Example.com/path/image.png",
    "Example.com/index.html",
    "AnotherExample.com/script.js",
    "AnotherExample.com/utils/helper.js",
    "/_next/static/chunks/fd9d1056-c07a78c5d535bea4.js",
    "/_next/static/chunks/main-app-6f0b34eb81b2baab.js",
    "/_next/static/chunks/8b9c1878-e0950841cd716641.js",
    "/_next/static/runtime/webpack.js"
]

let processedDataForModel = processScriptsForModel(scripts: scriptSources)

for (core, diffs) in processedDataForModel {
    print("\"\(core)\" diff: \(diffs)")
}
