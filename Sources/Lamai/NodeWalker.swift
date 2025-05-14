

struct NodeWalker {
    
    static func analyze(node: DecodedNode, urlInfo: inout URLInfo, comp: String = "query", label: String) -> String? {
        var foundURLs: [String] = []
        let urlOrigin = urlInfo.components.coreURL ?? ""
        var didWarnForDepth = false
        var source = SecurityWarning.SourceType.query
        if comp != "query" {
            if comp == "fragment" {
                source = SecurityWarning.SourceType.fragment
            } else {
                source = SecurityWarning.SourceType.path
            }
        }
        
        func walk(_ node: DecodedNode) {
            //Warn in the view that lamai find some "things"
            if !didWarnForDepth && node.depth >= 1 {
                urlInfo.warnings.append(SecurityWarning(
                    message: "Decoded value detected by Lamai in \(comp) \(label). Check the URLComponent tree for the decoding layers.",
                    severity: .info,
                    penalty: 0,
                    url: urlOrigin,
                    source: (comp == "path" ? .pathSub(label: label) : source)
                ))
                didWarnForDepth = true
            }
            if node.wasRelevant {
                let fromDecodedmessage: String? = decodingOrigin(for: node)

                for finding in node.findings {
                    switch finding {
                    case .url(let url):
                            if url.contains("https://") {
                                foundURLs.append(url)
                                urlInfo.warnings.append(SecurityWarning(
                                    message: "Found URL in \(comp) \(label): \(url)\(fromDecodedmessage.map { "\n\($0)" } ?? "")",
                                    severity: .dangerous,
                                    penalty: PenaltySystem.Penalty.hiddenRedirectQuery,
                                    url: urlOrigin,
                                    source: (comp == "path" ? .pathSub(label: label) : source),
                                    bitFlags: WarningFlags.QUERY_URL
                                ))
                            } else {
                                urlInfo.warnings.append(SecurityWarning(
                                    message: "Found partial URL in \(comp) \(label): \(url)\(fromDecodedmessage.map { "\n\($0)" } ?? "")",
                                    severity: .info,
                                    penalty: PenaltySystem.Penalty.informational,
                                    url: urlOrigin,
                                    source: (comp == "path" ? .pathSub(label: label) : source),
                                    bitFlags: WarningFlags.QUERY_URL
                                ))
                            }
                        
                    case .uuid(let result):
                        let uuidText = result.formatted ?? result.original
                        urlInfo.warnings.append(SecurityWarning(
                            message: "UUID in \(comp) \(label): \(uuidText) \(result.classification)\(fromDecodedmessage.map { "\n\($0)" } ?? "")",
                            severity: .tracking,
                            penalty: PenaltySystem.Penalty.uuidInQuery,
                            url: urlOrigin,
                            source: (comp == "path" ? .pathSub(label: label) : source),
                            bitFlags: WarningFlags.QUERY_UUID
                        ))
                        
                    case .scamWord(let word):
                        urlInfo.warnings.append(SecurityWarning(
                            message: "Scam keyword in \(comp) \(label): \(word)\(fromDecodedmessage.map { "\n\($0)" } ?? "")",
                            severity: .scam,
                            penalty: PenaltySystem.Penalty.scamWordsInQuery,
                            url: urlOrigin,
                            source: (comp == "path" ? .pathSub(label: label) : source),
                            bitFlags: WarningFlags.QUERY_SCAM_PHISHYNG
                        ))

                    case .phishingWord(let word):
                        urlInfo.warnings.append(SecurityWarning(
                            message: "Phishing keyword in \(comp) \(label): \(word)\(fromDecodedmessage.map { "\n\($0)" } ?? "")",
                            severity: .scam,
                            penalty: PenaltySystem.Penalty.phishingWordsInQuery,
                            url: urlOrigin,
                            source: (comp == "path" ? .pathSub(label: label) : source),
                            bitFlags: WarningFlags.QUERY_SCAM_PHISHYNG
                        ))

//                        Might duplicate key penalty, this is intended
                    case .entropy(let score, let value):
                        urlInfo.warnings.append(SecurityWarning(
                            message: "High entropy in \(comp) \(label): '\(value)' (≈ \(String(format: "%.2f", score))\(fromDecodedmessage.map { "\n\($0)" } ?? "")",
                            severity: .suspicious,
                            penalty: PenaltySystem.Penalty.highEntropyQuery,
                            url: urlOrigin,
                            source: (comp == "path" ? .pathSub(label: label) : source),
                            bitFlags: WarningFlags.QUERY_HIGH_ENTROPY
                            
                        ))
//TODO:                        double check if this is still running
                    case .longEntropyLike(let value):
                        urlInfo.warnings.append(SecurityWarning(
                            message: "Suspicious long query value in \(comp) \(label): '\(value)'\(fromDecodedmessage.map { "\n\($0)" } ?? "")",
                            severity: .suspicious,
                            penalty: PenaltySystem.Penalty.highEntropyQuery,
                            url: urlOrigin,
                            source: (comp == "path" ? .pathSub(label: label) : source)
                        ))
                        
                    case .isIPv4(let value):
                        urlInfo.warnings.append(SecurityWarning(
                            message: "IPv4 address in \(comp) \(label): '\(value)'\(fromDecodedmessage.map { "\n\($0)" } ?? "")",
                            severity: .dangerous,
                            penalty: PenaltySystem.Penalty.IpAddressInQuery,
                            url: urlOrigin,
                            source: (comp == "path" ? .pathSub(label: label) : source)
                        ))
                        
                    case .isIPv6(let value):
                        urlInfo.warnings.append(SecurityWarning(
                            message: "IPv6 address in \(comp) \(label): '\(value)'\(fromDecodedmessage.map { "\n\($0)" } ?? "")",
                            severity: .dangerous,
                            penalty: PenaltySystem.Penalty.IpAddressInQuery,
                            url: urlOrigin,
                            source: (comp == "path" ? .pathSub(label: label) : source)
                        ))
                        
                    case .email(let value):
                        urlInfo.warnings.append(SecurityWarning(
                            message: "Email address in \(comp) \(label): '\(value)'\(fromDecodedmessage.map { "\n\($0)" } ?? "")",
                            severity: .dangerous,
                            penalty: PenaltySystem.Penalty.emailInQuery,
                            url: urlOrigin,
                            source: (comp == "path" ? .pathSub(label: label) : source)
                        ))
                        //                    // TODO: This should be decode again to see what its carrying
                        //                        like so, need to give lamai a better interface, create a new datamodel to store the finding that were also decoded in the findings. findingception. Plus adapt the view!
                        //                        let node = LamaiDecoding.decode(value, maxDepth: 3)
                        //                                WalkTheNode.analyze(node: node, urlInfo: &urlInfo, comp: comp, label: "JSON[\(key)]")
                    case .json(let keys):
                        urlInfo.warnings.append(SecurityWarning(
                            message: "JSON structure in \(comp) \(label) with keys: \(keys.joined(separator: ", "))\(fromDecodedmessage.map { "\n\($0)" } ?? "")",
                            severity: .info,
                            penalty: PenaltySystem.Penalty.jsonInQuery,
                            url: urlOrigin,
                            source: (comp == "path" ? .pathSub(label: label) : source)
                        ))
                        
                    case .brandExact(let brand):
                        urlInfo.warnings.append(SecurityWarning(
                            message: "Brand exact match in \(comp) \(label): \(brand)\(fromDecodedmessage.map { "\n\($0)" } ?? "")",
                            severity: .suspicious,
                            penalty: PenaltySystem.Penalty.exactBrandInQuery,
                            url: urlOrigin,
                            source: (comp == "path" ? .pathSub(label: label) : source),
                            bitFlags: WarningFlags.QUERY_CONTAINS_BRAND
                        ))

                    case .brandContained(let brand):
                        urlInfo.warnings.append(SecurityWarning(
                            message: "Brand contained in string from \(comp) \(label): \(brand)\(fromDecodedmessage.map { "\n\($0)" } ?? "")",
                            severity: .suspicious,
                            penalty: PenaltySystem.Penalty.queryContainsBrand,
                            url: urlOrigin,
                            source: (comp == "path" ? .pathSub(label: label) : source),
                            bitFlags: WarningFlags.QUERY_CONTAINS_BRAND
                        ))

                    case .brandSimilar(let brand):
                        urlInfo.warnings.append(SecurityWarning(
                            message: "Brand similar match in \(comp) \(label): \(brand)\(fromDecodedmessage.map { "\n\($0)" } ?? "")",
                            severity: .suspicious,
                            penalty: PenaltySystem.Penalty.brandLookAlikeInQuery,
                            url: urlOrigin,
                            source: (comp == "path" ? .pathSub(label: label) : source),
                            bitFlags: WarningFlags.QUERY_LOOKALIKE_BRAND
                        ))
                    }
                }
            }
            for child in node.children {
                walk(child)
            }
        }
        
        walk(node)
        
        if checkMultipleURLs(foundURLs, urlInfo: &urlInfo, comp: comp) {
            return nil
        }
        
        if foundURLs.count == 1 {
            return foundURLs.first
        }
        
        return nil
    }
    
}

private func checkMultipleURLs(_ foundURLs: [String?], urlInfo: inout URLInfo, comp: String) -> Bool {
    var source = SecurityWarning.SourceType.query
    if comp != "query" {
        source = SecurityWarning.SourceType.fragment
    }
    let urlOrigin = urlInfo.components.coreURL ?? ""
    let nonNilURLs = foundURLs.compactMap { $0 } // Remove nil values
    if nonNilURLs.count > 1 {
        let urlList = nonNilURLs.joined(separator: "\n") // Format URLs on new lines
        urlInfo.warnings.append(SecurityWarning(
            message: "Multiple URLs detected in \(comp) parameters. This is highly suspicious:\n\(urlList)",
            severity: .critical,
            penalty: -100,
            url: urlOrigin,
            source: source
        ))
        return true  // Indicate that analysis should halt
    }
    return false  // Continue normally
}

func decodingOrigin(for node: DecodedNode) -> String? {
    let meaningfulMethods = ["percent", "base64", "hex", "mime", "unicode"]
    
    var current: DecodedNode? = node
    while let this = current {
        if this.decoded != nil, let method = this.method, meaningfulMethods.contains(method) {
            return "Found after decoding from \(method.capitalized)"
        }
        current = this.parent
    }
    return nil
}
