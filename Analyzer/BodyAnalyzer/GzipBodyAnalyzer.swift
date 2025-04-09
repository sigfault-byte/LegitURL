////
////  GzipBodyAnalyzer.swift
////  URLChecker
////
////  Created by Chief Hakka on 03/04/2025.
////
//
//
///// Needs more tinkering. This is only assumption don t use for now
//import Foundation
//
//struct GzipBodyAnalyzer {
//    static func rawdoggingTheGzip(_ compressedData: Data, urlOrigin: String) -> [SecurityWarning] {
//        var warnings = [SecurityWarning]()
//
//        // Ensure it's a gzip with deflate compression (method 0x08)
//        guard compressedData.count >= 10,
//              compressedData[0] == 0x1F,
//              compressedData[1] == 0x8B,
//              compressedData[2] == 0x08 else {
//            return warnings
//        }
//
//        // Get the original uncompressed size from the footer (ISIZE)
//        let isize = compressedData.suffix(4).withUnsafeBytes {
//            $0.load(as: UInt32.self)
//        }
//
//        if isize < 1500 {
//            let prefix = compressedData.prefix(256)
//            if !prefix.containsBytesCaseInsensitive(of: HTMLEntities.htmlOpen) {
//                warnings.append(SecurityWarning(
//                    message: "GZIP (DEFLATE) payload is small but contains no visible <html tag. Likely cloaked shell or scam kit.",
//                    severity: .suspicious,
//                    url: urlOrigin,
//                    source: .onlineAnalysis
//                ))
//            }
//        }
//
//        return warnings
//    }
//}
