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
    static func userInputCheck(_ input: String) -> (String?, String?) {
        // 1️⃣ Trim leading/trailing whitespaces and newlines
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        var message: String?
        
        // 2️⃣ Ensure the input is not empty
        guard !trimmed.isEmpty else {
            return (nil, "❌ Input is empty.")
        }
        
        // 3️⃣ Check if input has a valid scheme in the first 10 characters; if not, prepend "https://"
        var urlString = trimmed
        let schemeRegex = "^[A-Za-z][A-Za-z0-9+.-]*://"
        // Only check the first 10 characters (or the entire string if shorter)
        let prefixToCheck = trimmed.prefix(10)
        if prefixToCheck.range(of: schemeRegex, options: .regularExpression) == nil {
            urlString = "https://" + trimmed // Default to HTTPS
            message = "https:// was automatically added as the scheme"
        }
        
//        print("urlStringCleaned: \(urlString)")
        // ✅ If all checks pass, return the sanitized URL
        return (urlString, message)
    }
    
    /// **Extracts and splits host into parts**
    public static func explodeURL(host: String) -> [String] {
        // Using split returns non-empty substrings by default
        return host.split(separator: ".").map(String.init)
    }
    
    static func findMatchingKeywords(in input: String, keywords: Set<String>) -> [String]? {
        let lowercasedInput = input.lowercased()
        // Precompute lowercased version of each keyword alongside the original
        let lowercasedKeywords = keywords.map { ($0.lowercased(), $0) }
        // Filter keywords if the lowercased input contains the lowercased keyword
        let matches = lowercasedKeywords.compactMap { lowercasedInput.contains($0.0) ? $0.1 : nil }
        return matches.isEmpty ? nil : matches
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
    
    
    /// **Generates spelling correction suggestions using Apple's `UITextChecker`.**
    ///
    /// This function is designed to detect **typosquatting**, **misspellings**, and **obfuscated phishing attempts**
    /// by leveraging Apple's built-in spell checker. It processes the given word and returns a refined list of
    /// alternative spellings based on strict similarity rules.
    ///
    /// **Processing Steps:**
    ///  If the word contains numbers, it is first **"unleeted"** (e.g., `g00gle` → `google`).
    ///  The word is **split** into sub-words based on hyphens (`-`), and each part is processed individually.
    ///  **Spell-checking is performed** on each variation:
    ///     - The original word.
    ///     - A capitalized version (e.g., `paypall` → `PayPal`).
    ///  All suggestions are collected and **filtered to keep only valid matches**:
    ///     - **Only words with the same length as the original** are considered.
    ///     - **Only words with a Damerau-Levenshtein distance ≤ 1** are accepted.
    ///
    /// **Example Use Cases:**
    /// ```
    /// getAllSpellCheckSuggestions("paypl")   // Returns: ["PayPal"]
    /// getAllSpellCheckSuggestions("stean")   // Returns: ["steam", "steal"]
    /// getAllSpellCheckSuggestions("g0ogle")  // Returns: ["google"]
    /// ```
    ///
    /// **- Parameter word:** The input string (typically a domain or subdomain).
    /// **- Returns:** A `Set<String>` containing valid alternative spellings (or an empty set if none exist).
    ///
    /// 🔹 **Note:** This function is optimized for **domain name analysis**, meaning it prioritizes words
    /// that closely resemble the original input, rather than broad corrections.
    static func getAllSpellCheckSuggestions(_ word: String) -> Set<String> {
        let checker = UITextChecker()
        var allSuggestions: Set<String> = []
        
        // Step 1: Unleet the word if it contains numbers.
        let cleanedWord = word.rangeOfCharacter(from: CharacterSet.decimalDigits) != nil ? un1337(word) : word
        // Log for debugging.
//        print("Original cleaned word: ", cleanedWord, "Normalized: ", cleanedWord.normalizedConfusable())
        
        // Step 2: Split the word on hyphens and process each token separately.
        let subWords = cleanedWord.split(separator: "-").map(String.init)
        
        for token in subWords {
            // New: Filter out non-Latin characters from the token.
            guard let filteredToken = filterForSpellChecker(token) else {
                    // If `nil`, skip this token entirely
                    continue
                }
            // 2. Check if it’s empty
                guard !filteredToken.isEmpty else {
                    // If empty, skip this token
                    continue
                }
            
            // Process original (filtered) token.
            let range = NSRange(location: 0, length: filteredToken.utf16.count)
            if let suggestions = checker.guesses(forWordRange: range, in: filteredToken, language: "en") {
                // Filter suggestions based on length difference and Damerau-Levenshtein distance.
                let filteredSuggestions = suggestions.filter { suggestion in
                    return abs(suggestion.count - filteredToken.count) <= 1 &&
                           damerauLevenshtein(suggestion.lowercased(), filteredToken.lowercased()) <= 2
                }
                allSuggestions.formUnion(filteredSuggestions)
            }
            
            // Process the capitalized variant.
            let capitalizedToken = filteredToken.capitalized
            if capitalizedToken != filteredToken {
                let rangeCap = NSRange(location: 0, length: capitalizedToken.utf16.count)
                if let capSuggestions = checker.guesses(forWordRange: rangeCap, in: capitalizedToken, language: "en") {
                    let filteredCapSuggestions = capSuggestions.filter { suggestion in
                        return abs(suggestion.count - capitalizedToken.count) <= 1 &&
                               damerauLevenshtein(suggestion.lowercased(), capitalizedToken.lowercased()) <= 2
                    }
                    allSuggestions.formUnion(filteredCapSuggestions)
                }
            }
        }
//        print("suggestions: ", allSuggestions)
        return allSuggestions
    }
    
    static func un1337(_ word: String) -> String {
        let leetReplacements: [String: String] = [
            "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"
        ]
        var cleanedWord = word
        for (leet, normal) in leetReplacements {
            cleanedWord = cleanedWord.replacingOccurrences(of: leet, with: normal)
        }
        return cleanedWord
    }
    
    static func damerauLevenshtein(_ s1: String, _ s2: String) -> Int {
        let s1 = Array(s1)
        let s2 = Array(s2)
        let len1 = s1.count
        let len2 = s2.count
        
        var d = Array(repeating: Array(repeating: 0, count: len2 + 1), count: len1 + 1)
        
        for i in 0...len1 { d[i][0] = i }
        for j in 0...len2 { d[0][j] = j }
        
        for i in 1...len1 {
            for j in 1...len2 {
                let cost = s1[i-1] == s2[j-1] ? 0 : 1
                d[i][j] = min(
                    d[i-1][j] + 1,     // Deletion
                    d[i][j-1] + 1,     // Insertion
                    d[i-1][j-1] + cost // Substitution
                )
                
                // **Swap Detection (Transposition)**
                if i > 1, j > 1, s1[i-1] == s2[j-2], s1[i-2] == s2[j-1] {
                    d[i][j] = min(d[i][j], d[i-2][j-2] + 1) // Swap detected!
                }
            }
        }
        
        return d[len1][len2]
    }
    
    static func filterForSpellChecker(_ word: String) -> String? {
        var result = ""
        // Iterate through each character with its index.
        for (index, char) in word.enumerated() {
            // Allowed characters: ASCII letters.
            if char.isASCII && char.isLetter {
                result.append(char)
            } else {
                // The character is not allowed.
                // First, try to use the previous allowed letter, if any.
                if !result.isEmpty {
                    // Append the last allowed letter from result.
                    result.append(result.last!)
                } else {
                    // No previous allowed letter; look ahead in the word.
                    let start = word.index(word.startIndex, offsetBy: index + 1)
                    let remainder = word[start...]
                    if let nextAllowed = remainder.first(where: { $0.isASCII && $0.isLetter }) {
                        result.append(nextAllowed)
                    } else {
                        // No allowed character found in the remainder—return nil.
                        return nil
                    }
                }
            }
        }
        return result
    }
    
    static func isRealWord(_ word: String) -> Bool {
        // ✅ Step 1: Try Apple's dictionary (fast and accurate)
        if UIReferenceLibraryViewController.dictionaryHasDefinition(forTerm: word) {
            print("✅ DEBUG: '\(word)' found in Apple dictionary.")
            return true
        }
        
        // ✅ Step 2: Fallback to UITextChecker if dictionary is unavailable
        let checker = UITextChecker()
        let range = NSRange(location: 0, length: word.utf16.count)
        
        let misspelledRange = checker.rangeOfMisspelledWord(in: word, range: range, startingAt: 0, wrap: false, language: "en")
        
        let isLikelyAWord = misspelledRange.location == NSNotFound
        print(isLikelyAWord ? "✅ DEBUG: '\(word)' is a valid word (UITextChecker fallback)."
                            : "❌ DEBUG: '\(word)' is not recognized.")

        return isLikelyAWord
    }
    
    /// Calculates Shannon entropy of a given string.
        /// - Parameters:
        ///   - input: The string to analyze.
        ///   - threshold: The entropy threshold for flagging high entropy.
        /// - Returns: (Bool, Float?) → `true` if entropy exceeds threshold, otherwise `false`, and the entropy value.
        static func isHighEntropy(_ input: String,_ threshold: Float = 3.5) -> (Bool, Float?) {
            guard !input.isEmpty else { return (false, nil) }

            let length = Float(input.count)
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
    
}
