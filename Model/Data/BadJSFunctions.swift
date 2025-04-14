//
//  BadJSFunctions.swift
//  URLChecker
//
//  Created by Chief Hakka on 14/04/2025.
//

import Foundation

struct BadJSFunctions {
    static let suspiciousJsFunction: Set<String> = [
        "eval",
        "atob",
        "btoa",
        "settimeout",
        "setinterval",
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
    static let settimeout: [UInt8] = Array("settimeout".utf8)
    static let setinterval: [UInt8] = Array("setinterval".utf8)
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
            settimeout,
            setinterval,
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
            settimeout,
            setinterval,
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
