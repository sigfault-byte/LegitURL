//
//  LegitURLTools.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.

import UIKit
import Foundation

//TODO : reject anything not compliant to RFC1738

struct LegitURLTools {
    /// **Checks and prepares user input URL before deeper analysis**
    ///
    /// - Ensures input has a valid scheme (`http://` or `https://`).
    /// - If missing, it prepends `https://`.
    /// - Rejects invalid inputs that lack a dot (to avoid parsing nonsense).
    /// - Preserves original user input structure.
    ///
    /// - Parameter input: The raw URL string entered by the user.
    /// - Returns: A sanitized URL or an error message if invalid.
    static func sanitizeInputURL(_ input: String) -> (String?, String?) {
        let trimmedInput = input.trimmingCharacters(in: .whitespacesAndNewlines)

        guard !trimmedInput.isEmpty else {
            return (nil, "❌ Input is empty.")
        }

        var urlString = trimmedInput
        var message: String? = nil

        let schemeRegex = "^[a-zA-Z][a-zA-Z0-9+.-]*://"
        if urlString.range(of: schemeRegex, options: .regularExpression) == nil {
            urlString = "https://" + urlString
            message = "ℹ️ 'https://' scheme was automatically added."
        }

        guard let url = URL(string: urlString),
              let host = url.host,
              host.contains(".") else {
            return (nil, "❌ URL format is invalid.")
        }

        return (urlString, message)
    }
    
    /// **Extracts and splits host into parts**
    public static func explodeURL(host: String) -> [String] {
        // Using split returns non-empty substrings by default
        return host.split(separator: ".").map(String.init)
    }
    
    /// Checks whether a query value appears to be a URL.
    /// This function flags values that start with "http://" or "https://",
    /// or that are valid IPv4/IPv6 addresses.
    /// - Parameter value: The query value to check.
    /// - Returns: True if the value appears to be a URL.
    static func isValueURL(_ value: String) -> Bool {
        let lowerValue = value.lowercased()
        
        // ✅ Step 1: Check for common URL schemes.
        if lowerValue.hasPrefix("http://") || lowerValue.hasPrefix("https://") {
            return true
        }
        
        if URL(string: value) == nil && !value.contains(".") {
            return (false)
        }
        
        // ✅ Step 2: Check for IP addresses (IPv4 or IPv6).
        if LegitURLTools.isIPv4(value) || LegitURLTools.isIPv6(value) {
            return true
        }
        
        // ✅ Step 3: Extract potential TLD and validate it.
        let components = value.split(separator: ".")
        
        // Reject if there are no dots or only one component (e.g., "localhost" or "example")
        guard components.count > 1 else { return false }
        
        if let possibleTLD = components.last?.lowercased(), !possibleTLD.isEmpty {
            if let encodedTLD = possibleTLD.idnaEncoded { // ✅ Unwrap safely
                if !isValidTLD(encodedTLD) {
                    return false
                }
            } else {
                return false // 🚨 If IDNA encoding fails, it's not a valid TLD
            }
        } else {
            return false
        }
        
        // ✅ Step 5: Validate it as a properly formatted URL
        if let _ = URL(string: "https://\(value)") {
            return true
        }
        
        return false
    }
    
    /// Helper function to validate an IPv4 address.
    static func isIPv4(_ host: String) -> Bool {
        let components = host.split(separator: ".")
        // Check that there are exactly 4 parts and all parts are valid numbers between 0 and 255.
        return components.count == 4 && components.allSatisfy {
            if let num = Int($0), num >= 0 && num <= 255 {
                return true
            }
            return false
        }
    }
    
    /// Helper function to validate an IPv6 address.
    /// This implementation uses inet_pton for a robust check.
    static func isIPv6(_ host: String) -> Bool {
        // Remove square brackets if present
        let trimmedHost = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        var sin6 = in6_addr()
        // inet_pton returns 1 if the conversion succeeds
        return trimmedHost.withCString { cstring in
            inet_pton(AF_INET6, cstring, &sin6) == 1
        }
    }
    
    static func isRealWord(_ word: String) -> Bool {
        // Skip check for very long words or strings with symbols (likely gibberish)
        let word = word.lowercased()
        guard word.count <= 24,
              word.range(of: #"[^a-zA-Z\-']"#, options: .regularExpression) == nil else {
            return false
        }

        return UIReferenceLibraryViewController.dictionaryHasDefinition(forTerm: word)
    }
    // Attempt to normlaized non latin to latin. This depends on the char, some are normalized, some arnt.
    static func normalize(_ input: String) -> String {
        return input.applyingTransform(.toLatin, reverse: false)?
                    .folding(options: [.diacriticInsensitive, .caseInsensitive], locale: .current) ?? input
    }
    
    /// Calculates Shannon entropy of a given string.
    /// - Parameters:
    ///   - input: The string to analyze.
    ///   - threshold: The entropy threshold for flagging high entropy.
    /// - Returns: (Bool, Float?) → `true` if entropy exceeds threshold, otherwise `false`, and the entropy value.
    static func isHighEntropy(_ input: String, _ threshold: Float = 3.5) -> (Bool, Float?) {
        guard !input.isEmpty else {
            return (false, nil)
        }
        
        let length = Float(input.utf8.count)
        var frequency: [Character: Float] = [:]
        
        // Count character frequencies
        for char in input {
            frequency[char, default: 0] += 1
        }
        
        // Calculate entropy
        let entropy: Float = frequency.values.reduce(0) { result, count in
            let probability = count / length
            return result - (probability * log2(probability))
        }

        return (entropy >= threshold, entropy)
    }
    
    static func levenshtein(_ aStr: String, _ bStr: String) -> Int {
        let a = Array(aStr)
        let b = Array(bStr)
        let aCount = a.count
        let bCount = b.count
        
        guard aCount != 0 else { return bCount }
        guard bCount != 0 else { return aCount }
        
        var matrix = Array(repeating: Array(repeating: 0, count: bCount + 1), count: aCount + 1)
        
        for i in 0...aCount { matrix[i][0] = i }
        for j in 0...bCount { matrix[0][j] = j }
        
        for i in 1...aCount {
            for j in 1...bCount {
                if a[i - 1] == b[j - 1] {
                    matrix[i][j] = matrix[i - 1][j - 1]
                } else {
                    matrix[i][j] = min(
                        matrix[i - 1][j] + 1,    // Deletion
                        matrix[i][j - 1] + 1,    // Insertion
                        matrix[i - 1][j - 1] + 1 // Substitution
                    )
                }
            }
        }
        
        return matrix[aCount][bCount]
    }
    
    static func twoGramSimilarity(_ aStr: String, _ bStr: String) -> Double {
        func nGrams(_ str: String, size: Int) -> Set<String> {
            let chars = Array(str)
            guard chars.count >= size else { return [] }

            var result = Set<String>()
            for i in 0...(chars.count - size) {
                result.insert(String(chars[i..<i+size]))
            }
            return result
        }

        let aGrams = nGrams(aStr, size: 2)
        let bGrams = nGrams(bStr, size: 2)
        let intersection = aGrams.intersection(bGrams)
        let union = aGrams.union(bGrams)
        return union.isEmpty ? 0.0 : Double(intersection.count) / Double(union.count)
    }
    
    static func detectEmailAddresses(in input: String) -> [String] {
        // Fast fail: skip processing if string doesn't even resemble an email
        let strictEmailRegex = #"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$"#
        guard input.range(of: strictEmailRegex, options: [.regularExpression, .caseInsensitive]) != nil else {
            return []
        }

        do {
            let detector = try NSDataDetector(types: NSTextCheckingResult.CheckingType.link.rawValue)
            let range = NSRange(input.startIndex..<input.endIndex, in: input)
            let matches = detector.matches(in: input, options: [], range: range)

            var emails: [String] = []
            for match in matches {
                if match.resultType == .link,
                   let url = match.url,
                   url.scheme?.lowercased() == "mailto" {
                    
                    // Get the exact substring from the original text
                    let emailRange = match.range
                    let rawEmail = (input as NSString).substring(with: emailRange)
                    
                    // Remove the "mailto:" prefix if present
                    let cleanedEmail = rawEmail
                        .replacingOccurrences(of: "mailto:", with: "", options: .caseInsensitive)

                    emails.append(cleanedEmail)
                }
            }
            return emails
        } catch {
            print("Error detecting email addresses: \(error)")
            return []
        }
    }
    
    /// Calculates Shannon entropy over the byte content of a Data buffer (1-gram).
    /// Useful for detecting randomness or obfuscation in inline scripts or encoded blobs.
    /// - Parameter data: The raw Data to analyze.
    /// - Returns: The entropy value as a Float.
    static func byteEntropy(_ data: Data) -> Float {
        guard !data.isEmpty else { return 0.0 }

        let length = Float(data.count)
        var frequency: [UInt8: Float] = [:]

        for byte in data {
            frequency[byte, default: 0] += 1
        }

        let entropy: Float = frequency.values.reduce(0) { result, count in
            let probability = count / length
            return result - (probability * log2(probability))
        }

        return entropy
    }

    /// Calculates the proportion of structural JavaScript symbols in a script.
    /// Used to differentiate real code from encoded blobs.
    /// - Parameter input: The JS content as a String.
    /// - Returns: Float value representing the density of symbols.
    static func jsSymbolDensity(in input: String) -> Float {
        guard !input.isEmpty else { return 0.0 }

        let structuralSymbols: Set<Character> = ["{", "}", "(", ")", ";", "=", ",", "\"", "'", ".", ":", "[", "]", "\\"]
        let matchCount = input.reduce(0) { count, char in
            structuralSymbols.contains(char) ? count + 1 : count
        }

        return Float(matchCount) / Float(input.count)
    }
}
