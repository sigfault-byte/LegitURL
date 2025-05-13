//
//  CollectionExtensions.swift
//  LegitURL
//
//  Created by Chief Hakka on 13/05/2025.
//
extension Collection where Element == UInt8 {
    func xor(with mask: UInt8) -> [UInt8] {
        return self.map { $0 ^ mask }
    }
}
//let lowercase = data.xor(with: 0x20) // Not always correct this always needs to receive  azAZ element or the output is garbage 
