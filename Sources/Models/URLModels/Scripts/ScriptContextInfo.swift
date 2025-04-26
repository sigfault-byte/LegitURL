//
//  URLScripts.swift
//  URLChecker
//
//  Created by Chief Hakka on 14/04/2025.
//
enum ScriptOrigin: String {
    case relative = "relative"
    case protocolRelative = "protocolRelative"
    case dataURI = "dataURI"
    case httpExternal = "http protocol"
    case httpsExternal = "https External"
    case unknown = "unknown"
    case malformed = "malformed"
    case inline = "inline"
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
