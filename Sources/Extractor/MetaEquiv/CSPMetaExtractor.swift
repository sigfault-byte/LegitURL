//
//  CSPMetaExtractor.swift
//  LegitURL
//
//  Created by Chief Hakka on 06/05/2025.
//
// TODO: Expand to detect other http-equiv meta types (refresh, content-type, etc.)
// t.co shortener -> 200 ok but -> meta name ok to catch.The script logic is different...
// Might o nly check this when the html is small ?
//<head><meta name="referrer" content="always"><noscript><META http-equiv="refresh" content="0;URL=http://www.100x-mindset.com"></noscript><title>http://www.100x-mindset.com</title></head><script>window.opener = null; location.replace("http:\/\/www.100x-mindset.com")</script>
//
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
        
        let candidates: [Int]
        
        switch maxCandidate {
        case 1:
            candidates = [tagCandidates[0]]
        case 2:
            candidates = [tagCandidates[0], tagCandidates[1]]
        default:
            candidates = Array(tagCandidates.prefix(3))
        }
        
        var maxEnd: Int = 0
        
        for candidate in candidates {
            if DataSignatures.matchesAsciiTag(at: candidate, in: html, asciiToCompare: InterestingPrefix.meta),
               DataSignatures.matchesAsciiTag(at: candidate + 5, in: html, asciiToCompare: InterestingPrefix.httpEquivCSP, lookAheadWindow: 55) {
                
                //Useless fun optimization
                let start = DataSignatures.extractAllTagMarkers(in: html, within: candidate+40..<candidate+100, tag: byteLetters.equalSign)
                if candidate == candidates.first { maxEnd = candidates.count > 1 ? candidates[1] : range.upperBound }
                else if candidate == candidates.dropFirst().first { maxEnd = candidates.count > 2 ? candidates[2] : range.upperBound }
                else if candidate == candidates.dropFirst(2).first { maxEnd = range.upperBound }
                
                let end = DataSignatures.extractAllTagMarkers(in: html, within: start[0] + 1..<maxEnd, tag: byteLetters.endTag)
                metaDataSCP = html[start[0] + 1..<end[0]]
                
            }
        }
        
        return metaDataSCP
    }
}
