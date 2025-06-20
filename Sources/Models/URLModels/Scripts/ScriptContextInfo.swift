//
//  URLScripts.swift
//  LegitURL
//
//  Created by Chief Hakka on 14/04/2025.
//
import Foundation
enum ScriptOrigin: String, Hashable {
    case relative = "Relative"
    case protocolRelative = "Protocol Relative"
    case dataURI = "Data URI"
    case httpExternal = "http External"
    case httpsExternal = "https External"
    case unknown = "Unknown"
    case malformed = "Malformed"
    case inline = "Inline"
    case dataScript = "Data Script"
    case moduleInline = "Module Inline"
    case moduleExternal = "Module External"
    case moduleRelative = "Module Relative"
}

struct ScriptScanTarget: Identifiable {
    let id: UUID = UUID()
    let start: Int
    var end: Int?   /*End like <scritp content here>*/
    var endTagPos: Int? // End of the like <script>content here</script>
    var flag: Bool?
    var findings: ScanFlag?
    var context: ScriptContext?
    var srcPos: Int?
    var typePos: Int?
    var origin: ScriptOrigin?
    var extractedSrc: String? // Added property to store the full detected script source URL
    var isSelfClosing: Bool = false // Added property to determine if the script tag is self-closing
    var noncePos: Int? // Changed property to store the position of the nonce attribute
    var nonceValue: String? // Store the nonce value
    var findings4UI: [(message: String, severity: SecurityWarning.SeverityLevel, pos: Int?)]? = nil
    var integrityPos: Int?
    var integrityValue: String?
    var isModule: Bool = false //module script with their own sets of rules...
    var crossOriginValue: String? = nil //crossorigin value, can be "anonymous" / "use-credentials" / ""
    
    var adjustedOrigin: ScriptOrigin? {
        guard isModule else { return origin }
        switch origin {
            case .inline: return .moduleInline
            case .httpsExternal, .httpExternal, .protocolRelative:
                return .moduleExternal
            case .relative:
                return .moduleRelative
            default:
                return origin
        }
    }

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
