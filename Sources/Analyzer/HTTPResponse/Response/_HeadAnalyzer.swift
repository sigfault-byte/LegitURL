//
//  HTMLHeadAnalyzer.swift
//  LegitURL
//
//  Created by Chief Hakka on 16/04/2025.
//
//              UNUSED
//TODO: To Finish this need some meta refreh exemple. The logic to match the title to the domain is nasty
import Foundation
struct HeadAnalyzer {
    static func analyze(headContent: Data,
                        tagPos: [Int],
                        tagPosToDismiss: [Int],
                        warnings: inout [SecurityWarning], origin: String) -> HeadHTMLFindings {
        
        let candidate = filterTagsToDismiss(tagPosToDismiss, from: tagPos, endOfEnd: headContent.count)
        let candidate2 = filterCandidateForTitleAndMeta(candidate, headcontent: headContent)
        for candidate in candidate2 {
            let localCandidate = candidate - headContent.startIndex
            guard localCandidate + 20 <= headContent.count else { continue }
            
            let previewRange = localCandidate..<(localCandidate + 20)
            let previewData = headContent[previewRange]
            if let previewString = String(data: previewData, encoding: .utf8) {
                print("Preview of candidate at \(candidate): \(previewString)")
            } else {
                print("Unable to decode preview at \(candidate)")
            }
        }
        
     
        return HeadHTMLFindings()
    }
    
    private static func filterTagsToDismiss(_ tagsToDismiss: [Int],
                                    from tagPos: [Int], endOfEnd: Int) -> [Int] {
        let tagSetToDismiss = Set(tagsToDismiss)
        return tagPos.filter { position in
            position < endOfEnd && !tagSetToDismiss.contains(position)
        }
    }
    
    private static func filterCandidateForTitleAndMeta(_ candidate: [Int], headcontent: Data) -> [Int] {
        var prefilterCandidate: [Int] = []
        for i in candidate {
            let pos = i
            guard pos + 1 < headcontent.count else { continue }
            if DataSignatures.matchesAsciiTag(at: pos, in: headcontent, asciiToCompare: interestingPrefix.title) {
                prefilterCandidate.append(i)
            } else if DataSignatures.matchesAsciiTag(at: pos, in: headcontent, asciiToCompare: interestingPrefix.meta) {
                prefilterCandidate.append(i)
            }
        }
        return prefilterCandidate
    }
}



struct HeadHTMLFindings {
    var metaCSP: String?
    var charset: String?
}






//HeadHTMLFindings {
//    var title: String?
//    var metaRefreshURL: String?
//    var metaCSP: String?
//    var charset: String?
//}
//<meta http-equiv="Content-Security-Policy" content="...">
//<meta charset="utf-7"> (or anything weird)
//<meta http-equiv="refresh">
