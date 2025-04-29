//
//  Headers.swift
//  LegitURL
//
//  Created by Chief Hakka on 27/04/2025.
//
struct HeadersFlags: OptionSet, Hashable {
    let rawValue: Int16
    
    static let isHSTS = HeadersFlags(rawValue: 1 << 0) // https
    static let hasXCTO = HeadersFlags(rawValue: 1 << 1) // x content type option
    static let hasCT = HeadersFlags(rawValue: 1 << 2) // content type
    static let hasXFO = HeadersFlags(rawValue: 1 << 3) // x frame option
    static let hasRP = HeadersFlags(rawValue: 1 << 4)  // Referal policy
    
}
