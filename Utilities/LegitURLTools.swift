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
        // 2️⃣b Try parsing it directly as a URL (basic structure check)
        if URL(string: trimmed) == nil && !trimmed.contains(".") {
            return (nil, "❌ Not a valid URL structure.")
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
        guard word.count <= 24,
              word.range(of: #"[^a-zA-Z\-']"#, options: .regularExpression) == nil else {
            return false
        }

        return UIReferenceLibraryViewController.dictionaryHasDefinition(forTerm: word)
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
    
    static func detectEmailAddresses(in input: String) -> [String] {
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
}
