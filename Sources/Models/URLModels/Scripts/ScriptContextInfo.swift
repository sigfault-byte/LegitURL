//
//  URLScripts.swift
//  LegitURL
//
//  Created by Chief Hakka on 14/04/2025.
//
enum ScriptOrigin: String, Hashable {
    case relative = "Relative"
    case protocolRelative = "Protocol Relative"
    case dataURI = "Data URI"
    case httpExternal = "http External"
    case httpsExternal = "https External"
    case unknown = "Unknown"
    case malformed = "Malformed"
    case inline = "Inline"
}

struct ScriptScanTarget {
    let start: Int
    var end: Int?   /*End like <scritp content here>*/
    var endTagPos: Int? // End of the like <script>content here</script>
    var flag: Bool?
    var findings: ScanFlag?
    var context: ScriptContext?
    var srcPos: Int?
    var origin: ScriptOrigin?
    var extractedSrc: String? // Added property to store the full detected script source URL
    var isSelfClosing: Bool = false // Added property to determine if the script tag is self-closing
    var noncePos: Int? // Changed property to store the position of the nonce attribute
    var nonceValue: String? // Store the nonce value
    var findings4UI: [(message: String, severity: SecurityWarning.SeverityLevel)]? = nil
    var integrityPos: Int?
    var integrityValue: String?
    
    enum ScriptContext: String {
        case inHead = "In Head"
        case inBody = "In Body"
        case unknown = "Unknown"
    }
}

enum ScanFlag {
    case script
    case inlineJS
    case suspectedObfuscation
    case dataScript
}

struct ScriptExtractionResult {
    var scripts: [ScriptScanTarget]
    let htmlRange: Range<Int>
}

struct ScriptOriginSecurityKey: Hashable {
    let origin: ScriptOrigin
    let isSecure: Bool
}

//var originSecurityCounts: [ScriptOriginSecurityKey: Int] = [:]
//
//for script in scripts.scripts {
//    guard let origin = script.origin else { continue }
//
//    let isSecure: Bool = {
//        switch origin {
//        case .dataURI:
//            return script.nonceValue != nil && !script.nonceValue!.isEmpty
//        case .protocolRelative, .httpsExternal:
//            return script.integrityValue != nil && !script.integrityValue!.isEmpty
//        case .inline:
//            return script.nonceValue != nil && !script.nonceValue!.isEmpty
//        default:
//            return false
//        }
//    }()
//
//    let key = ScriptOriginSecurityKey(origin: origin, isSecure: isSecure)
//    originSecurityCounts[key, default: 0] += 1
//}
