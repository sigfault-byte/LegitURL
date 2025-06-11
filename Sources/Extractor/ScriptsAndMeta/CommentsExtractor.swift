//
//  CommentsExtractor.swift
//  LegitURL
//
//  Created by Chief Hakka on 11/06/2025.
//
import Foundation

struct CommentsExtractor {
    static func extract(from body: Data, tagPos: [Int], withing range: Range<Int>) -> [Int] {
        var tagPosWithoutComment = [Int]()
        var commentsOpenTag = [Int]()
        var commentsClosedTag = [Int]()
        
        body.withUnsafeBytes { (rawBuffer: UnsafeRawBufferPointer) -> Void in
            guard let base = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {return}
                        
            for pos in tagPos {
                if pos + 4 <= body.count {
                    let ptr = base + pos
                    if ptr[1] == uniqueByte.exclamationMark {
                        if ptr[2] == uniqueByte.dash, ptr[3] == uniqueByte.dash {
                            commentsOpenTag.append(pos)
                        }
                    }
                }
            }
        }
        
        let closedTags = DataSignatures.extractAllTagMarkers(in: body, within: range, tag: uniqueByte.endTag)
        
        
        body.withUnsafeBytes { (rawBuffer: UnsafeRawBufferPointer) -> Void in
            guard let base = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {return}
                        
            for pos in closedTags {
                if pos >= 2 && pos + 1 < body.count {
                    let ptr = base + pos
                    if ptr[-1] == uniqueByte.dash {
                        if ptr[-2] == uniqueByte.dash {
                            commentsClosedTag.append(pos)
                        }
                    }
                }
            }
        }
        
//        print("-----------COMMENT CONTENT------------")
//        var closeIndex = 0
//        for open in commentsOpenTag {
//            while closeIndex < commentsClosedTag.count && commentsClosedTag[closeIndex] <= open {
//                closeIndex += 1
//            }
//            if closeIndex < commentsClosedTag.count {
//                let close = commentsClosedTag[closeIndex]
//                if close < body.count {
//                    let previewRange = body[open...close]
//                    if let previewString = String(data: previewRange, encoding: .utf8) {
//                        print(previewString + "\n")
//                    }
//                    closeIndex += 1 // advance to next closing tag after this one
//                }
//            }
//        }
//        print("-----------END-----COMMENT CONTENT------------")
        
        var commentRanges: [Range<Int>] = []
        for (start, end) in zip(commentsOpenTag, commentsClosedTag) {
            if start < end {
                commentRanges.append(start..<end) // end is the exact pos of ">"
            }
        }
        tagPosWithoutComment = tagPos.filter { tagPos in
            !commentRanges.contains { $0.contains(tagPos) }
        }
        
        return tagPosWithoutComment
    }
}
