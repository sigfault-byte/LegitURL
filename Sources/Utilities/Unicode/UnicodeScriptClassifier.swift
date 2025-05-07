//
//  UnicodeScriptClassifier.swift
//  LegitURL
//
//  Created by Chief Hakka on 22/03/2025.
//
enum ScriptCategory {
    case ascii, latinExtended, cyrillic, greek, other
}

func classifyUnicodeScript(_ scalar: UnicodeScalar) -> ScriptCategory {
    switch scalar.value {
    case 0x0020...0x007F:
        return .ascii
    case 0x00A0...0x024F:
        return .latinExtended
    case 0x0370...0x03FF:
        return .greek
    case 0x0400...0x04FF:
        return .cyrillic
    default:
        return .other
    }
}

func analyzeUnicodeScripts(in string: String) -> Set<ScriptCategory> {
    let scalars = string.unicodeScalars
    let categories = scalars.map { classifyUnicodeScript($0) }
    return Set(categories)
}

