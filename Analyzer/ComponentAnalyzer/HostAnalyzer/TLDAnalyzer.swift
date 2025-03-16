//
//  TLDAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//
struct TLDAnalyzer {
    static func getTLDScore(_ tld: String) -> Int {
        let suspiciousTLD = "." + tld
        return PenaltySystem.suspiciousTLDs[suspiciousTLD] ?? 0
    }
}
