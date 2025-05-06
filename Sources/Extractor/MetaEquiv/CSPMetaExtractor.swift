//
//  CSPMetaExtractor.swift
//  LegitURL
//
//  Created by Chief Hakka on 06/05/2025.
//
// TODO: Expand to detect other http-equiv meta types (refresh, content-type, etc.)
// loading the meta in the header is terrible practice?
import Foundation

struct CSPMetaExtractor {
    static func extract(from html: Data, tags: [Int], range: Range<Int>) -> Data? {
        
        var metaDataSCP: Data?
        //filter whats before </head>
        //...and after<head> !!
        let tagCandidates = tags.filter { $0 > range.lowerBound && $0 < range.upperBound }
        //exit if its empty
        guard !tagCandidates.isEmpty else { return nil }
        //grab the first
        let maxCandidate = tagCandidates.count
        
        let metaCSPCandidate1 = tagCandidates[0]
        let metaCSPCandidate2: Int? = 1 > maxCandidate ? nil : tagCandidates[1]
        let metaCSPCandidate3: Int? = 2 > maxCandidate ? nil : tagCandidates[2]
        
        let candidates = [metaCSPCandidate1, metaCSPCandidate2, metaCSPCandidate3].compactMap { $0 }
        var maxEnd: Int = 0
        
        for candidate in candidates {
            if DataSignatures.matchesAsciiTag(at: candidate, in: html, asciiToCompare: interestingPrefix.meta),
               DataSignatures.matchesAsciiTag(at: candidate + 5, in: html, asciiToCompare: interestingPrefix.httpEquivCSP, lookAheadWindow: 55) {
                
                //Useless fun optimization
                let start = DataSignatures.extractAllTagMarkers(in: html, within: candidate+40..<candidate+100, tag: byteLetters.equalSign)
                if candidate == metaCSPCandidate1 { maxEnd = metaCSPCandidate2 != nil ? metaCSPCandidate2! : range.upperBound }
                if candidate == metaCSPCandidate2 { maxEnd = metaCSPCandidate3 != nil ? metaCSPCandidate3! : range.upperBound }
                if candidate == metaCSPCandidate3 { maxEnd = range.upperBound }
                
                let end = DataSignatures.extractAllTagMarkers(in: html, within: start[0] + 1..<maxEnd, tag: byteLetters.endTag)
                metaDataSCP = html[start[0] + 1..<end[0]]
                
            }
        }
        
        return metaDataSCP
    }
}
