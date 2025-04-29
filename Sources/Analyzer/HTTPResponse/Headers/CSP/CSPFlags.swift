//
//  CSPFlags.swift
//  LegitURL
//
//  Created by Chief Hakka on 25/04/2025.
//
import Foundation

struct CSPBitFlag: OptionSet, Hashable {
    let rawValue: Int32
    
    static let unsafeInline     = CSPBitFlag(rawValue: 1 << 0)    // 1
    static let unsafeEval       = CSPBitFlag(rawValue: 1 << 1)    // 2
    static let wasmUnsafeEval   = CSPBitFlag(rawValue: 1 << 2)    // 4
    static let strictDynamic    = CSPBitFlag(rawValue: 1 << 3)    // 8
    static let reportSample     = CSPBitFlag(rawValue: 1 << 4)    // 16
    static let wildcard         = CSPBitFlag(rawValue: 1 << 5)    // 32
    static let none             = CSPBitFlag(rawValue: 1 << 6)    // 64
    static let hasNonce         = CSPBitFlag(rawValue: 1 << 7)    // 128
    static let allowsHTTP       = CSPBitFlag(rawValue: 1 << 8)    // 256
    static let allowsHTTPS      = CSPBitFlag(rawValue: 1 << 9)    // 512
    static let allowsBlob       = CSPBitFlag(rawValue: 1 << 10)   // 1024
    static let allowsData       = CSPBitFlag(rawValue: 1 << 11)   // 2048
    static let allowsSelf       = CSPBitFlag(rawValue: 1 << 12)   // 4096
    static let hasHash          = CSPBitFlag(rawValue: 1 << 13)   // 8192
}


func parseCSP(_ structuredCSP: [String: [Data: CSPValueType]]) -> [String: Int32] {
    var directiveBitFlags: [String: Int32] = [:]

    for (directive, values) in structuredCSP {
        var flags: CSPBitFlag = []

        for (value, type) in values where type == .keyword || type == .nonce {
            print("Checking CSP directive \(directive) value: [\(String(data: value, encoding: .utf8) ?? "invalid")]")
            if value == dangerousCSPValues.unsafeInline {
                flags.insert(.unsafeInline)
            } else if value == dangerousCSPValues.unsafeEval {
                flags.insert(.unsafeEval)
            } else if value == dangerousCSPValues.wasmUnsafeEval {
                flags.insert(.wasmUnsafeEval)
            } else if value == safeCSPValue.strictDynamic {
                flags.insert(.strictDynamic)
            } else if value == safeCSPValue.reportSample {
                flags.insert(.reportSample)
            } else if value == safeCSPValue.none {
                flags.insert(.none)
            } else if value == safeCSPValue.selfCSP {
                flags.insert(.allowsSelf)
            } else if value.starts(with: safeCSPValue.nonce) {
                flags.insert(.hasNonce)
            } else if value.starts(with: safeCSPValue.hash){
                flags.insert(.hasHash)
            } else if value == dangerousCSPValues.wildcard {
                flags.insert(.wildcard)
            } else if value.starts(with: dangerousCSPValues.data) {
                flags.insert(.allowsData)
            } else if value.starts(with: dangerousCSPValues.blob) {
                flags.insert(.allowsBlob)
            } else if value.starts(with: Data("http:".utf8)) {
                flags.insert(.allowsHTTP)
            } else if value.starts(with: Data("https:".utf8)) {
                flags.insert(.allowsHTTPS)
            }
        }

        directiveBitFlags[directive] = flags.rawValue
    }

    return directiveBitFlags
}

extension CSPBitFlag {
    func descriptiveReasons(sourceCount: [CSPBitFlag: Int] = [:]) -> [String] {
        var reasons: [String] = []

        if contains(.unsafeInline)      { reasons.append("allows unsafe inline scripts") }
        if contains(.unsafeEval)        { reasons.append("allows use of eval()") }
        if contains(.wasmUnsafeEval)    { reasons.append("allows WebAssembly eval from strings") }
        if contains(.strictDynamic)     { reasons.append("enables strict-dynamic (trusted scripts only)") }
        if contains(.reportSample)      { reasons.append("enables report-sample for violation reporting") }
        if contains(.wildcard)          { reasons.append("allows wildcard sources (*)") }
        if contains(.none)              { reasons.append("explicitly denies all sources ('none')") }
        if contains(.hasNonce)          { reasons.append("requires a valid nonce for script execution") }
        if contains(.allowsHTTP)        { reasons.append("allows HTTP sources (insecure)") }
        if contains(.allowsHTTPS)       { reasons.append("allows HTTPS sources") }
        if contains(.allowsBlob) {
            let count = sourceCount[.allowsBlob] ?? 0
            reasons.append("allows blob: sources (\(count) matched)")
        }
        if contains(.allowsData) {
            let count = sourceCount[.allowsData] ?? 0
            reasons.append("allows data: URIs (\(count) matched)")
        }
        if contains(.allowsSelf)        { reasons.append("allows content from same origin ('self')") }

        return reasons
    }
}
