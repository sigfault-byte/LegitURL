import Foundation

struct ScamByteSignatures {
    static let documentGetElementById: [UInt8] = Array("document.getElementById(".utf8)
    static let submitPattern: [UInt8] = Array(".submit".utf8)
    //    static let clientJS: [UInt8] = Array("ClientJS(".utf8)
    static let metaRefresh: [UInt8] = Array("<meta http-equiv=\"refresh\"".utf8)
    // TODO Added for URL extraction but its a bit complicated. Lots of clocking can happen. We could catch explicit one. But lets just flag and bail depedning on other signals for now
    static let metaRefreshURLStart: [UInt8] = Array("content=\"".utf8)
    
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

struct interestingPrefix {
    static let http: [UInt8] = Array("http/".utf8)
    static let https: [UInt8] = Array("https/".utf8)
    static let slash: [UInt8] = Array("/".utf8)
    static let script: [UInt8] = Array("script".utf8)
    static let head: [UInt8] = Array("head".utf8)
    static let body: [UInt8] = Array("body".utf8)
    static let src: [UInt8] = Array("src=".utf8)
    static let title: [UInt8] = Array("title".utf8)
    static let httpEquiv: [UInt8] = Array("meta http-equiv=".utf8)
}

struct byteLetters {
    static let s: UInt8 = 115
    static let S: UInt8 = 83
    static let r: UInt8 = 114
    static let endTag: UInt8 = 62
    static let openTag: UInt8 = 60
    static let t: UInt8 = 116
    static let m: UInt8 = 109
    static let equalSign: UInt8 = 61
}

// Helper function to convert a string to Data (bytes)
func convertToBytes(of string: String) -> Data {
    return Data(string.utf8)
}

// Helper function to extract and convert domain.tld to Data
func convertToDomainTldBytes(of urlString: String) -> Data? {
    if let url = URL(string: urlString), let host = url.host {
        let components = host.split(separator: ".")
        if components.count >= 2 {
            let domainTld = components.suffix(2).joined(separator: ".")
            return Data(domainTld.utf8)
        }
    }
    return nil
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
    
    func containsBytesCaseInsensitive(of pattern: [UInt8]) -> (found: Bool, position: Int?) {
        guard pattern.count > 0, self.count >= pattern.count else { return (false, nil) }
        
        return self.withUnsafeBytes { dataPtr in
            for i in 0...(self.count - pattern.count) {
                let window = dataPtr[i..<i + pattern.count]
                let windowLower = window.map { ($0 >= 65 && $0 <= 90) ? $0 + 32 : $0 }
                if windowLower.elementsEqual(pattern) {
                    return (true, i)
                }
            }
            return (false, nil)
        }
    }
    
    func containsBytesCaseInsensitive(of pattern: [UInt8], startIndex: Int = 0) -> (found: Bool, position: Int?) {
        guard pattern.count > 0, self.count >= startIndex + pattern.count else { return (false, nil) }
        
        return self.withUnsafeBytes { dataPtr in
            for i in startIndex...(self.count - pattern.count) {
                let window = dataPtr[i..<i + pattern.count]
                let windowLower = window.map { ($0 >= 65 && $0 <= 90) ? $0 + 32 : $0 }
                if windowLower.elementsEqual(pattern) {
                    return (true, i)
                }
            }
            return (false, nil)
        }
    }
}
