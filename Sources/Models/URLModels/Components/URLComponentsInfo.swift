//
//  URLComponentsInfo.swift
//  LegitURL
//
//  Created by Chief Hakka on 08/04/2025.
//
import Foundation

struct URLComponentsInfo {
    var fullURL: String?
    var coreURL: String?
    var scheme: String?
    var userinfo: String?
    var userPassword: String?
    var host: String?
    var punycodeHostDecoded: String? // Punycode → Unicode
    var punycodeHostEncoded: String? // ASCII → Punycode
    var port: String?
    var path: String?
    var pathEncoded: String? // True path with proper encoding, handled by urlcomponent
    var isPathEndpointLike: Bool = false
    var query: String?
    var rawQuery: String?
    var queryKeys: [String?] = []
    var queryValues: [String?] = []
    var fragment: String?
    var rawFragment: String?
    var fragmentKeys: [String?] = []
    var fragmentValues: [String?] = []
    
    var extractedDomain: String?
    var idnaEncodedExtractedDomain: String?
    var idnaDecodedExtractedDomain: String?
    var extractedTLD: String?
    var punycodeEncodedExtractedTLD: String?
    var subdomain: String?
    
    
    var lamaiTrees: [TreeType: [DecodedNode]] = [:]
    
    enum TreeType: String {
        case queryKey
        case queryValue
        case fragmentKey
        case fragmentValue
        case malformedQuery
        case malformedFragment
        case path
    }
}
