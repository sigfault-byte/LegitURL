

//
//  Extension.swift
//  LegitURL
//
//  Created by Chief Hakka on 08/03/2025.
//

import Foundation
import SwiftUI

extension String {
    /// Transliterates the string by converting non-Latin characters into their Latin approximations
    /// and stripping any diacritical marks. This helps detect confusable characters in domains.
    func normalizedConfusable() -> String {
        let mutable = NSMutableString(string: self) as CFMutableString
        // Convert non-Latin characters to their Latin representation.
        CFStringTransform(mutable, nil, kCFStringTransformToLatin, false)
        // Remove diacritical marks.
        CFStringTransform(mutable, nil, kCFStringTransformStripCombiningMarks, false)
        return mutable as String
    }
    
    /// Returns the Shannon entropy of the string.
    func entropy() -> Double {
        let frequency = self.reduce(into: [:]) { counts, char in
            counts[char, default: 0] += 1
        }
        let length = Double(self.count)
        return frequency.values.reduce(0.0) { total, count in
            let probability = Double(count) / length
            return total - (probability * log2(probability))
        }
    }
    
    /// Add regex extension for strings
    func matches(regex: String) -> Bool {
            return self.range(of: regex, options: .regularExpression) != nil
        }
}


