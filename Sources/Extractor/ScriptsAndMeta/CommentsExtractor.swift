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
        
        
        
        // Build comment ranges with a single forward scan that ignores nested
        // “<-!--” sequences until the first matching “-->”.
        // "downlevel-revealed conditional comment" Relic from the passed for IE ...
        var commentRanges: [Range<Int>] = []
        var openIdx = 0
        var closeIdx = 0
        var stack: [Int] = []

        while openIdx < commentsOpenTag.count || closeIdx < commentsClosedTag.count {
            let nextOpen = openIdx < commentsOpenTag.count ? commentsOpenTag[openIdx] : Int.max
            let nextClose = closeIdx < commentsClosedTag.count ? commentsClosedTag[closeIdx] : Int.max

            if nextOpen < nextClose {
                // Encountered an opening <!--  before the next--> ...
                if stack.isEmpty {
                    stack.append(nextOpen)         // track only the outer mots open
                }
                // Nested are ignored only the first matters
                openIdx += 1
            } else if nextClose < Int.max {
                // Encountered a closing --> before the next <!--
                if let start = stack.popLast(), stack.isEmpty {
                    commentRanges.append(start..<nextClose)
                }
                closeIdx += 1
            } else {
                break
            }
        }
        
        tagPosWithoutComment = tagPos.filter { pos in
            !commentRanges.contains { $0.contains(pos) }
        }
        
        return tagPosWithoutComment
    }
}
