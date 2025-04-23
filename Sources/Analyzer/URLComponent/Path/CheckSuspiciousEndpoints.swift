//
//  CheckSuspiciousEndpoints.swift
//  LegitURL
//
//  Created by Chief Hakka on 23/04/2025.
//
import Foundation
struct CheckSuspiciousEndpoints {
    public static func check(path: String, origin: String, urlInfo: inout URLInfo){
        let lowerPath = path.lowercased()
        guard let dotIndex = lowerPath.lastIndex(of: "."), lowerPath.distance(from: dotIndex, to: lowerPath.endIndex) < 8 else {
            return
        }
        
        let ext = String(lowerPath[dotIndex...])
            .trimmingCharacters(in: CharacterSet(charactersIn: "./?&"))
            .split(separator: ".")
            .last.map(String.init) ?? ""
        
        if !WhiteList.supposelySafeEndpoints.contains(ext) && !ext.isEmpty {
            urlInfo.warnings.append(SecurityWarning(message: "String Suspicious or uncommon file extension in path: .\(ext)",
                                                    severity: .suspicious,
                                                    penalty: PenaltySystem.Penalty.pathHasExecutable,
                                                    url: origin,
                                                    source: .path,
                                                    bitFlags: [.PATH_EXECUTABLE_FILE_TYPE]))
            
        }
    }
}
