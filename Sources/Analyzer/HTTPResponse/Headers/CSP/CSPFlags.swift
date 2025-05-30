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
    static let specificURL      = CSPBitFlag(rawValue: 1 << 14)   //  https://cdn.com
    static let wildcardURL      = CSPBitFlag(rawValue: 1 << 15)   //  *.cdn.com
}

func parseCSP(_ structuredCSP: [String: [Data: CSPValueType]]) -> [String: Int32] {
    var directiveBitFlags: [String: Int32] = [:]

    for (directive, values) in structuredCSP {
        var flags: CSPBitFlag = []

        for (value, type) in values {
            if type == .keyword ||
                type == .nonce ||
                type == .hash{
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
                } else if (value.starts(with: safeCSPValue.sha256Hash) ||
                           value.starts(with: safeCSPValue.sha384Hash) ||
                            value.starts(with: safeCSPValue.sha512Hash))
                             {
                    flags.insert(.hasHash)
                }
            } else if type == .source || type == .wildcard {
                flags.formUnion(evaluateSourceBitFlags(for: value))
                //TODO: add a fallback for unknown
            }
        }

        directiveBitFlags[directive] = flags.rawValue
    }

    return directiveBitFlags
}

private func evaluateSourceBitFlags(for value: Data) -> CSPBitFlag {
    var flags: CSPBitFlag = []

    if value == dangerousCSPValues.wildcard {
        flags.insert(.wildcard)
    } else if value.starts(with: dangerousCSPValues.data) {
        flags.insert(.allowsData)
    } else if value.starts(with: dangerousCSPValues.blob) {
        flags.insert(.allowsBlob)
    } else if value == dangerousCSPValues.http {
        flags.insert(.allowsHTTP)
    } else if value == dangerousCSPValues.https {
        flags.insert(.allowsHTTPS)
    } else if value.first == dangerousCSPValues.wildcard.first {
        let trimmed = value.dropFirst(2)
        if let str = String(data: trimmed, encoding: .utf8),
           let url = URL(string: "https://" + str),
           url.host != nil {
            flags.insert(.wildcardURL)
        }
    } else if let str = String(data: value, encoding: .utf8),
              let url = URL(string: "https://" + str),
              url.host != nil {
        flags.insert(.specificURL)
    }

    return flags
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
        if contains(.hasHash)           { reasons.append("requires a valid hash for script execution")}
        if contains(.allowsHTTP)        { reasons.append("allows HTTP sources (insecure)") }
        if contains(.allowsHTTPS)       { reasons.append("allows HTTPS sources") }
        if contains(.allowsBlob)        { reasons.append("allows blob:")}
        if contains(.allowsData)        { reasons.append("allows data:")}
        if contains(.allowsSelf)        { reasons.append("allows content from same origin ('self')") }
        if contains(.specificURL)       { reasons.append("allows specific external URLs (e.g. https://cdn.example.com)") }
        if contains(.wildcardURL)       { reasons.append("allows wildcard subdomains (e.g. *.example.com)") }

        return reasons
    }
}
