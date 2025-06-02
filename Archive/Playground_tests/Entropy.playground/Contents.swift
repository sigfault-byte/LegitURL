import Foundation
func isHighEntropy(_ input: String, _ threshold: Float = 3.5) -> (Bool, Float?) {
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

let NonceValue = "jrS0NHoepuuSOUSsjZCrKQ"

let (isEntropy, value) = isHighEntropy(NonceValue)
print(isEntropy, value)
