import Foundation

///windows.location!!! and other tricks to add
struct ScamByteSignatures {
    static let documentGetElementById: [UInt8] = Array("document.getElementById(".utf8)
//    static let clientJS: [UInt8] = Array("ClientJS(".utf8)
    static let metaRefresh: [UInt8] = Array("<meta http-equiv=\"refresh\"".utf8)
    static let metaRefreshURLStart: [UInt8] = Array("content=\"".utf8) // Added for URL extraction
    
    static let evalCall: [UInt8] = Array("eval(".utf8)
    static let atobCall: [UInt8] = Array("atob(".utf8)
    static let unescapeCall: [UInt8] = Array("unescape(".utf8)
    static let scriptSrc: [UInt8] = Array("script src=".utf8)
    static let clientMinJS: [UInt8] = Array("client.min.js".utf8)
    
//    js specific
    static let windowLocation: [UInt8] = Array("window.location".utf8)
    static let href: [UInt8] = Array(".href".utf8)
    static let replace: [UInt8] = Array(".replace".utf8)
    static let assign: [UInt8] = Array(".assign".utf8)
}

struct HTMLEntities {
    static let htmlOpen: [UInt8] = Array("<html".utf8)
    static let htmlClose: [UInt8] = Array("</html>".utf8)
    static let scriptOpen: [UInt8] = Array("<script".utf8)
    static let scriptClose: [UInt8] = Array("</script>".utf8)
}

extension Data {
    func containsBytes(of pattern: [UInt8]) -> Bool {
        guard pattern.count > 0, self.count >= pattern.count else { return false }

        return self.withUnsafeBytes { dataPtr in
            for i in 0...(self.count - pattern.count) {
                let window = dataPtr[i..<i + pattern.count]
                if window.elementsEqual(pattern) {
                    return true
                }
            }
            return false
        }
    }

    func containsBytesCaseInsensitive(of pattern: [UInt8]) -> Bool {
        guard pattern.count > 0, self.count >= pattern.count else { return false }

        return self.withUnsafeBytes { dataPtr in
            for i in 0...(self.count - pattern.count) {
                let window = dataPtr[i..<i + pattern.count]
                let windowLower = window.map { ($0 >= 65 && $0 <= 90) ? $0 + 32 : $0 }
                if windowLower.elementsEqual(pattern) {
                    return true
                }
            }
            return false
        }
    }
}


