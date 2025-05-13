//  URLOnlineInfo.swift
//  LegitURL
//
//  Created by Chief Hakka on 08/04/2025.
//
import Foundation

struct OnlineURLInfo: Identifiable {
    let id: UUID
    var httpVersion: String? // didnt work.... TODO: find how to make it work!
    var serverResponseCode: Int?
    var statusText: String?
    
    var normalizedHeaders: [String: String]?
    var parsedHeaders: ParsedHeaders?
    
    var rawBody: Data? = nil
    var humanReadableBody: String? = nil
    var isBodyTooLarge: Bool = false
    var humanBodySize: Int? = 0
    
    var normalizedCertificate: [String:String] = [:]
    
    var parsedCertificate: ParsedCertificate?
    var certificateAuthority: String?
    var sslValidity: Bool = false
    
    var finalRedirectURL: String?
    
    var extractedCookies: [HTTPCookie]?
    var cookiesForUI: [CookieAnalysisResult?] = []
    var scriptSourcesForCSP: ScriptSourceToMatchCSP? = nil
    var cspOfHeader: ClassifiedCSPResult? = nil
    
    var script4daUI: [ScriptPreview] = []
    
    var cspRecommendation: CSPRecommendation? //Not used 
    
    init(from urlInfo: URLInfo,
         responseCode: Int? = nil,
         statusText: String? = nil,
         
         normalizedHeaders: [String: String]? = nil,
         parsedHeaders: ParsedHeaders? = nil,
         
         rawBody: Data? = nil,
         humanReadableBody: String? = nil,
         humanBodySize: Int? = 0,
         certificateAuthority: String? = nil,
         
         sslValidity: Bool = false,
         parsedCertificate: ParsedCertificate? = nil,
         finalRedirectURL: String? = nil,
         
         cookiesForUI: [CookieAnalysisResult?] = []
    )
    {
        self.id = urlInfo.id
        self.serverResponseCode = responseCode
        self.statusText = statusText
        
        self.normalizedHeaders = normalizedHeaders
        self.parsedHeaders = parsedHeaders
        
        self.rawBody = rawBody
        self.humanReadableBody = humanReadableBody
        self.humanBodySize = humanBodySize
        
        self.certificateAuthority = certificateAuthority
        self.sslValidity = sslValidity
        self.parsedCertificate = parsedCertificate
        
        self.finalRedirectURL = finalRedirectURL
        
        self.cookiesForUI = cookiesForUI
    }
}

struct ParsedHeaders {
    var securityHeaders: [String: String] = [:]
    var trackingHeaders: [String: String] = [:]
    var serverHeaders: [String: String] = [:]
    var otherHeaders: [String: String] = [:]
}

struct ScriptSourceToMatchCSP {
    var nonceList: [String]
    var externalSources: [String]
    
}
