//
//  BadJSFunctions.swift
//  LegitURL
//
//  Created by Chief Hakka on 14/04/2025.
//

import Foundation

struct BadJSFunctions {
    static let suspiciousJsFunction: Set<String> = [
        "eval",
        "atob",
        "btoa",
        "document.write",
        "location.replace",
        "location.assign",
        "location.href",
        "window.open",
        "innerhtml",
        "outerhtml",
        "unescape",
        "escape",
        "sendbeacon",
        "fetch",
        "xmlhttprequest",
        "websocket",
        "import",
        "window[\"eval\"]",
        "document[\"write\"]",
        "console.log",
        "getElementById",
    ]
    
    static let eval: [UInt8] = Array("eval".utf8)
    static let atob: [UInt8] = Array("atob".utf8)
    static let btoa: [UInt8] = Array("btoa".utf8)
    static let documentWrite: [UInt8] = Array("document.write".utf8)
    static let locationReplace: [UInt8] = Array("location.replace".utf8)
    static let locationAssign: [UInt8] = Array("location.assign".utf8)
    static let locationHref: [UInt8] = Array("location.href".utf8)
    static let windowOpen: [UInt8] = Array("window.open".utf8)
    static let innerhtml: [UInt8] = Array("innerhtml".utf8)
    static let outerhtml: [UInt8] = Array("outerhtml".utf8)
    static let unescape: [UInt8] = Array("unescape".utf8)
    static let escape: [UInt8] = Array("escape".utf8)
    static let sendbeacon: [UInt8] = Array("sendbeacon".utf8)
    static let fetch: [UInt8] = Array("fetch".utf8)
    static let xmlhttprequest: [UInt8] = Array("xmlhttprequest".utf8)
    static let websocket: [UInt8] = Array("websocket".utf8)
    static let jsimport: [UInt8] = Array("import".utf8)
    static let windowEval: [UInt8] = Array("window[\"eval\"]".utf8)
    static let documentWriteTrick: [UInt8] = Array("document[\"write\"]".utf8)
    static let consoleLog: [UInt8] = Array("console[\"log\"]".utf8)
    static let getELementById: [UInt8] = Array("getElementById".utf8)
    static let submit: [UInt8] = Array("submit(".utf8)
    
    static var suspiciousLastBytes: Set<UInt8> {
        return [
            eval,
            atob,
            btoa,
            documentWrite,
            locationReplace,
            locationAssign,
            locationHref,
            windowOpen,
            innerhtml,
            outerhtml,
            unescape,
            escape,
            sendbeacon,
            fetch,
            xmlhttprequest,
            websocket,
            jsimport,
            windowEval,
            documentWriteTrick,
            consoleLog,
            getELementById,
        ].compactMap { $0.last }.reduce(into: Set<UInt8>()) { $0.insert($1) }
    }
    
    static var suspiciousSecondLastBytes: Set<UInt8> {
        return [
            eval,
            atob,
            btoa,
            documentWrite,
            locationReplace,
            locationAssign,
            locationHref,
            windowOpen,
            innerhtml,
            outerhtml,
            unescape,
            escape,
            sendbeacon,
            fetch,
            xmlhttprequest,
            websocket,
            jsimport,
            windowEval,
            documentWriteTrick,
            consoleLog,
            getELementById,
        ].compactMap { $0.dropLast().last }.reduce(into: Set<UInt8>()) { $0.insert($1) }
    }
}

struct SuspiciousJSAccessors {
    static let dotCookie: [UInt8] = Array("cookie".utf8)
    static let dotLocalStorage: [UInt8] = Array("localStorage".utf8)
    static let dotSetItem: [UInt8] = Array("setItem".utf8)
    static let dotWebAssembly: [UInt8] = Array("WebAssembly".utf8)

    static let all: [(name: String, bytes: [UInt8])] = [
        ("cookie", dotCookie),
        ("localStorage", dotLocalStorage),
        ("setItem", dotSetItem),
        ("WebAssembly", dotWebAssembly),
    ]
    
    static let accessorsFirstBytes: Set<UInt8> = [
        UInt8(ascii: "c"), // cookie
        UInt8(ascii: "l"), // localStorage
        UInt8(ascii: "s"), // setItem
        UInt8(ascii: "W"), // WebAssembly
    ]

    static let accessorsSecondBytes: Set<UInt8> = [
        UInt8(ascii: "o"), // co
        UInt8(ascii: "o"), // lo
        UInt8(ascii: "e"), // se
        UInt8(ascii: "e"), // We
    ]
    
    static let accessorsThirdBytes: Set<UInt8> = [
        UInt8(ascii: "o"), // co
        UInt8(ascii: "c"), // lo
        UInt8(ascii: "t"), // se
        UInt8(ascii: "b"), // We
    ]
    
//    TODO: add all these too, but need more tinkering for the byte parser
//    // Obfuscation & Encoding Tricks
//    static let obfuscationAndEncodingTricks: Set<String> = [
//        "encodeURIComponent(", "decodeURIComponent(",
//        "fromCharCode(", "String.fromCharCode",
//        "charCodeAt(", "replace(/", "match(/", "split(", "join(",
//        "rot13", "hex_encode", "base64_encode", "base64_decode",
//        "urlencode", "urldecode", "xor", "aes_encrypt", "des_encrypt",
//        "md5", "sha1", "sha256", "crc32", "hmac", "ciphertext",
//        "pkcs7", "pbkdf2", "bcrypt", "scrypt", "jwt="
//    ]
//    
//    static let trackingAndMonitoring: Set<String> = [
//        "ga(", "fbq(", "ym(", "insightly(", "mixpanel(", "amplitude(",
//        "keen(", "matomo(", "clickid", "hotjar(", "clarity(", "snowplow(",
//        "segment(", "fullstory(", "luckyorange(", "heap(", "adroll(",
//        "pixel.fire", "doubleclick.net", "googletagmanager(", "gtm(",
//        "google-analytics.com", "facebook.com/tr", "fbclid", "utm_",
//        "trk", "trkId", "trkRef", "trackEvent", "trackPageview",
//        "trackConversion", "visitorId", "sessionId", "userId",
//        "datadome", "akamai-mpulse", "cloudflare_insights", "newrelic(",
//        "optimizely(", "braze(", "webtrends(", "quantcast(", "pardot("
//    ]
}

