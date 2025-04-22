func levenshtein(_ a: String, _ b: String) -> Int {
    let aChars = Array(a)
    let bChars = Array(b)
    let (m, n) = (aChars.count, bChars.count)
    var dp = Array(repeating: Array(repeating: 0, count: n+1), count: m+1)

    for i in 0...m { dp[i][0] = i }
    for j in 0...n { dp[0][j] = j }

    for i in 1...m {
        for j in 1...n {
            if aChars[i-1] == bChars[j-1] {
                dp[i][j] = dp[i-1][j-1]
            } else {
                dp[i][j] = 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
            }
        }
    }

    return dp[m][n]
}


func nGrams(_ str: String, n: Int) -> Set<String> {
    guard str.count >= n else { return [] }
    var result = Set<String>()
    let chars = Array(str)
    for i in 0...(chars.count - n) {
        result.insert(String(chars[i..<i+n]))
    }
    return result
}

func nGramSimilarity(_ a: String, _ b: String, n: Int) -> Double {
    let aNGrams = nGrams(a.lowercased(), n: n)
    let bNGrams = nGrams(b.lowercased(), n: n)
    let intersection = aNGrams.intersection(bNGrams)
    let union = aNGrams.union(bNGrams)
    return union.isEmpty ? 0.0 : Double(intersection.count) / Double(union.count)
}

func byteLevenshtein(_ a: String, _ b: String) -> Int {
    let aBytes = [UInt8](a.utf8)
    let bBytes = [UInt8](b.utf8)
    let (m, n) = (aBytes.count, bBytes.count)
    var dp = Array(repeating: Array(repeating: 0, count: n+1), count: m+1)

    for i in 0...m { dp[i][0] = i }
    for j in 0...n { dp[0][j] = j }

    for i in 1...m {
        for j in 1...n {
            if aBytes[i-1] == bBytes[j-1] {
                dp[i][j] = dp[i-1][j-1]
            } else {
                dp[i][j] = 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
            }
        }
    }

    return dp[m][n]
}

func byteNGrams(_ str: String, n: Int) -> Set<[UInt8]> {
    let bytes = [UInt8](str.utf8)
    guard bytes.count >= n else { return [] }

    var result = Set<[UInt8]>()
    for i in 0...(bytes.count - n) {
        result.insert(Array(bytes[i..<i+n]))
    }
    return result
}

func byteNGramSimilarity(_ a: String, _ b: String, n: Int) -> Double {
    let aGrams = byteNGrams(a, n: n)
    let bGrams = byteNGrams(b, n: n)
    let intersection = aGrams.intersection(bGrams)
    let union = aGrams.union(bGrams)
    return union.isEmpty ? 0.0 : Double(intersection.count) / Double(union.count)
}

func scalarLevenshtein(_ a: String, _ b: String) -> Int {
    let aScalars = Array(a.unicodeScalars)
    let bScalars = Array(b.unicodeScalars)
    let (m, n) = (aScalars.count, bScalars.count)
    var dp = Array(repeating: Array(repeating: 0, count: n+1), count: m+1)

    for i in 0...m { dp[i][0] = i }
    for j in 0...n { dp[0][j] = j }

    for i in 1...m {
        for j in 1...n {
            if aScalars[i-1] == bScalars[j-1] {
                dp[i][j] = dp[i-1][j-1]
            } else {
                dp[i][j] = 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
            }
        }
    }

    return dp[m][n]
}

func scalarNGrams(_ str: String, n: Int) -> Set<String> {
    let scalars = Array(str.unicodeScalars)
    guard scalars.count >= n else { return [] }

    var result = Set<String>()
    for i in 0...(scalars.count - n) {
        result.insert(String(String.UnicodeScalarView(scalars[i..<i+n])))
    }
    return result
}

func scalarNGramSimilarity(_ a: String, _ b: String, n: Int) -> Double {
    let aNGrams = scalarNGrams(a, n: n)
    let bNGrams = scalarNGrams(b, n: n)
    let intersection = aNGrams.intersection(bNGrams)
    let union = aNGrams.union(bNGrams)
    return union.isEmpty ? 0.0 : Double(intersection.count) / Double(union.count)
}

let a = "apple-business-secure"
let b = "apple"
let c = "apple.com"
let d = "pleap.com"
let e = "bak"
let f = "bac"

print("--------\(a)---------NORMAL------\(b)----------------------------------------")
print("Levenshtein Distance between '\(a)' and '\(b)': \(levenshtein(a, b))")
print("2-Gram Similarity between '\(a)' and '\(b)': \(nGramSimilarity(a, b, n: 2))")
print("3-Gram Similarity between '\(a)' and '\(b)': \(nGramSimilarity(a, b, n: 3))")
print("-----------\(a)------SCALAR-----------------------------------------------")
print("Scalar Levenshtein Distance between '\(a)' and '\(b)': \(scalarLevenshtein(a, b))")
print("Scalar 2-Gram Similarity between '\(a)' and '\(b)': \(scalarNGramSimilarity(a, b, n: 2))")
print("Scalar 3-Gram Similarity between '\(a)' and '\(b)': \(scalarNGramSimilarity(a, b, n: 3))")
print("------------------BYTES-----------------------------------------------")
print("Byte Levenshtein Distance between '\(a)' and '\(b)': \(byteLevenshtein(a, b))")
print("Byte 2-Gram Similarity between '\(a)' and '\(b)': \(byteNGramSimilarity(a, b, n: 2))")
print("Byte 3-Gram Similarity between '\(a)' and '\(b)': \(byteNGramSimilarity(a, b, n: 3))")
print("------------------NORMAL-----------------------------------------------")
print("Levenshtein Distance between '\(c)' and '\(d)': \(levenshtein(c, d))")
print("2-Gram Similarity between '\(c)' and '\(d)': \(nGramSimilarity(c, d, n: 2))")
print("3-Gram Similarity between '\(c)' and '\(d)': \(nGramSimilarity(c, d, n: 3))")
print("------------------SCALAR-----------------------------------------------")
print("Scalar Levenshtein Distance between '\(c)' and '\(d)': \(scalarLevenshtein(c, d))")
print("Scalar 2-Gram Similarity between '\(c)' and '\(d)': \(scalarNGramSimilarity(c, d, n: 2))")
print("Scalar 3-Gram Similarity between '\(c)' and '\(d)': \(scalarNGramSimilarity(c, d, n: 3))")
print("------------------BYTES-----------------------------------------------")
print("Byte Levenshtein Distance between '\(c)' and '\(d)': \(byteLevenshtein(c, d))")
print("Byte 2-Gram Similarity between '\(c)' and '\(d)': \(byteNGramSimilarity(c, d, n: 2))")
print("Byte 3-Gram Similarity between '\(c)' and '\(d)': \(byteNGramSimilarity(c, d, n: 3))")
print("------------------NORMAL-----------------------------------------------")
print("Levenshtein Distance between '\(e)' and '\(f)': \(levenshtein(e, f))")
print("2-Gram Similarity between '\(e)' and '\(f)': \(nGramSimilarity(e, f, n: 2))")
print("3-Gram Similarity between '\(e)' and '\(f)': \(nGramSimilarity(e, f, n: 3))")
print("------------------SCALAR-----------------------------------------------")
print("Scalar Levenshtein Distance between '\(e)' and '\(f)': \(scalarLevenshtein(e, f))")
print("Scalar 2-Gram Similarity between '\(e)' and '\(f)': \(scalarNGramSimilarity(e, f, n: 2))")
print("Scalar 3-Gram Similarity between '\(e)' and '\(f)': \(scalarNGramSimilarity(e, f, n: 3))")
print("------------------BYTES-----------------------------------------------")
print("Byte Levenshtein Distance between '\(e)' and '\(f)': \(byteLevenshtein(e, f))")
print("Byte 2-Gram Similarity between '\(e)' and '\(f)': \(byteNGramSimilarity(e, f, n: 2))")
print("Byte 3-Gram Similarity between '\(e)' and '\(f)': \(byteNGramSimilarity(e, f, n: 3))")
