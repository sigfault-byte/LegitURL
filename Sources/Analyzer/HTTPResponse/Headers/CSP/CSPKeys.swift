//
//  CSPKeys.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/04/2025.
//
// MARK: - Core Content Directives
//https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy

//directive-name [source-expression] [source-expression] ... ;

import Foundation
struct contentDirective { // aka fetch directive
    static let requireTrustedTypes: Data = "require-trusted-types-for".data(using: .utf8) ?? Data() // New (? prototype?? ) to prevent xss. Didnt see many,  on m.youtube.com for exemple
    static let defaultSrc: Data = "default-src".data(using: .utf8) ?? Data() // Default policy for fetching any content (fallback if others aren't defined)
    static let scriptSrc: Data = "script-src".data(using: .utf8) ?? Data() // Governs the sources of JavaScript
    static let styleSrc: Data = "style-src".data(using: .utf8) ?? Data() // Governs the sources of CSS styles
    static let imgSrc: Data = "img-src".data(using: .utf8) ?? Data() // Governs the sources of images
    
    static let connectSrc: Data = "connect-src".data(using: .utf8) ?? Data() // Governs network connections like XHR, WebSocket, fetch
    
    static let fontSrc: Data = "font-src".data(using: .utf8) ?? Data() // Governs the sources of fonts
    static let objectSrc: Data = "object-src".data(using: .utf8) ?? Data() // Governs plugins like Flash, deprecated but still supported
    static let mediaSrc: Data = "media-src".data(using: .utf8) ?? Data() // Governs audio and video sources
    static let frameSrc: Data = "frame-src".data(using: .utf8) ?? Data() // Governs embedded frame sources (like iframes)
    static let workerSrc: Data = "worker-src".data(using: .utf8) ?? Data() // Governs Web Workers and Shared Workers
    static let manifestSrc: Data = "manifest-src".data(using: .utf8) ?? Data() // Governs manifest.json file sources
    static let prefetchSrc: Data = "prefetch-src".data(using: .utf8) ?? Data() // Controls prefetch, prerender and similar sources
    static let childSrcDeprecated: Data = "child-src".data(using: .utf8) ?? Data() // Deprecated; was used to control frames and workers
}

// MARK: - Navigation & Behavior Directives
struct behaviorDirective {
    static let formAction: Data = "form-action".data(using: .utf8) ?? Data() // Controls where forms can be submitted to
    static let navigateTo: Data = "navigate-to".data(using: .utf8) ?? Data() // Restricts document navigation (e.g., top.location.href)
    static let baseUri: Data = "base-uri".data(using: .utf8) ?? Data() // Restricts <base> tag's influence on relative URLs
    static let sandbox: Data = "sandbox".data(using: .utf8) ?? Data() // Applies HTML5 iframe sandbox restrictions at the document level
    static let frameAncestors: Data = "frame-ancestors".data(using: .utf8) ?? Data() // Controls which parents (e.g., iframes) can embed this content
}

// MARK: - Reporting & XSS Protections
struct reportingDirective {
    static let reportUri: Data = "report-uri".data(using: .utf8) ?? Data() // Legacy way to send CSP violation reports
    static let reportTo: Data = "report-to".data(using: .utf8) ?? Data() // Modern reporting mechanism via Reporting API
}

// MARK: - Dangerous CSP Values
struct dangerousCSPValues {
    static let unsafeInline: Data = "'unsafe-inline'".data(using: .utf8) ?? Data() // Allows inline scripts or styles — XSS risk
    static let unsafeEval: Data = "'unsafe-eval'".data(using: .utf8) ?? Data() // Allows eval() and similar — code injection risk
    static let wasmUnsafeEval: Data = "'wasm-unsafe-eval'".data(using: .utf8) ?? Data() // Allows WebAssembly compile-time eval — modern risk
    // TODO: ??? Just DO IT
    // Allosws hash expression for event handler : e.g. script-src 'unsafe-hashes' 'sha256-cd9827ad...': -> red flag
    // If the hash value matches the hash of an inline event handler attribute value or of a style attribute value, then the code will be allowed to execute.
    static let unsafeHashes: Data = "'unsafe-hashes'".data(using: .utf8) ?? Data()
    static let data: Data = "data:".data(using: .utf8) ?? Data() // Allows data: URLs — risky, often abused
    static let blob: Data = "blob:".data(using: .utf8) ?? Data() // Allows blob: URLs — often used for dynamic JS payloads
    static let wildcard: Data = "*".data(using: .utf8) ?? Data() // Wildcard — allows everything from everywhere // NO QUOTE ON WILDCARD!!!!
    static let https: Data = "https:".data(using: .utf8) ?? Data()
    static let http: Data = "http:".data(using: .utf8) ?? Data()
}

// MARK: - Common Safe CSP Values
struct safeCSPValue {
    static let selfCSP: Data = "'self'".data(using: .utf8) ?? Data() // Allows resources from the same origin
    static let none: Data = "'none'".data(using: .utf8) ?? Data() // Blocks everything — strongest policy
    static let strictDynamic: Data = "'strict-dynamic'".data(using: .utf8) ?? Data() // Allows dynamic scripts from  parents with a unique value nonce or hash
    static let reportSample: Data = "'report-sample'".data(using: .utf8) ?? Data() // Sends sample of blocked content in CSP reports
    static let nonce: Data = "'nonce-".data(using: .utf8) ?? Data() // nonce usage
    static let hash: Data = "'hash-".data(using: .utf8) ?? Data() //TODO: hash usage -> ? this does not exists ?
    static let sha256Hash: Data = "'sha256-".data(using: .utf8) ?? Data() // sha
    static let sha384Hash: Data = "'sha384-".data(using: .utf8) ?? Data()
    static let sha512Hash: Data = "'sha512-".data(using: .utf8) ?? Data()
    
    static let scriptSrc: Data = "'script'".data(using: .utf8) ?? Data() // Specific to "require-trusted-types-for"
}

struct HeaderByteSignatures {
    
    static let colon: UInt8 = 0x3A // ':'
    static let newline: UInt8 = 0x0A // '\n'
    static let carriageReturn: UInt8 = 0x0D // '\r'
    static let semicolon: UInt8 = 0x3B // ';'
    static let equals: UInt8 = 0x3D // '='
    static let space: UInt8 = 0x20 // ' '
    static let doubleQuote: UInt8 = 0x22 // '"'
    static let singleQuote: UInt8 = 0x27
    static let http: Data = "http:".data(using: .utf8) ?? Data()
    static let https: Data = "https:".data(using: .utf8) ?? Data()
}
