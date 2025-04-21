//
//  WarningFlags.swift
//  URLChecker
//
//  Created by Chief Hakka on 16/04/2025.
//
struct WarningFlags: OptionSet {
    let rawValue: UInt64
    
    // HOST FLAGS
    static let ABNORMAL_URL_STRUCTURE = WarningFlags(rawValue: 1 << 0)
    static let DOMAIN_EXACT_BRAND_MATCH = WarningFlags(rawValue: 1 << 1)
    static let DOMAIN_CONTAINS_BANRD = WarningFlags(rawValue: 1 << 2)
    static let DOMAIN_SCAM_OR_PHISHING = WarningFlags(rawValue: 1 << 3)
    static let DOMAIN_LOOKALIKE_BRAND_MATCH = WarningFlags(rawValue: 1 << 4)
    static let SUBDOMAIN_CONTAINS_BRAND = WarningFlags(rawValue: 1 << 5)
    
    //PATH FLAGS
    static let PATH_EXACT_BRAND_MATCH = WarningFlags(rawValue: 1 << 10)
    static let PATH_CONTAINS_BRAND = WarningFlags(rawValue: 1 << 11)
    static let PATH_LOOKALIKE_BRAND = WarningFlags(rawValue: 1 << 12)
    static let PATH_SCAM_OR_PHISHING = WarningFlags(rawValue: 1 << 13)
    static let PATH_EXECUTABLE_HINT = WarningFlags(rawValue: 1 << 14)
    static let PATH_HIGH_ENTROPY = WarningFlags(rawValue: 1 << 15)
    static let PATH_ENDPOINTLIKE = WarningFlags(rawValue: 1 << 16)
    static let PATH_OBFUSCATED_STRUCTURE = WarningFlags(rawValue: 1 << 17)
    static let PATH_EXECUTABLE_FILE_TYPE = WarningFlags(rawValue: 1 << 18)
    
    //QUERY FLAGS
    static let QUERY_OBFUSCATED_STRUCTURE = WarningFlags(rawValue: 1 << 20)
    static let QUERY_URL = WarningFlags(rawValue: 1 << 21)
    static let QUERY_UUID = WarningFlags(rawValue: 1 << 22)
    static let QUERY_SCAM_PHISHYNG = WarningFlags(rawValue: 1 << 23)
    static let QUERY_HIGH_ENTROPY = WarningFlags(rawValue: 1 << 24)
    static let QUERY_CONTAINS_BRAND = WarningFlags(rawValue: 1 << 25)
    static let QUERY_LOOKALIKE_BRAND = WarningFlags(rawValue: 1 << 26)
    
    //BODY FLAGS
    static let BODY_SCRIPT_END_NOT_FOUND = WarningFlags(rawValue: 1 << 30)
    static let BODY_SCRIPT_DATAURI = WarningFlags(rawValue: 1 << 31)
    static let BODY_SCRIPT_UNKNOWN_ORIGIN = WarningFlags(rawValue: 1 << 32)
    static let BODY_HIGH_JS_RATIO = WarningFlags(rawValue: 1 << 33)
    static let BODY_HIGH_JS_RATIO_SMALL_HTML = WarningFlags(rawValue: 1 << 34)
    static let BODY_HIGH_SCRIPT_DENSITY = WarningFlags(rawValue: 1 << 35)
    static let BODY_JS_SET_EDIT_COOKIE = WarningFlags(rawValue: 1 << 36)
    static let BODY_JS_READ_COOKIE = WarningFlags(rawValue: 1 << 37)
    
    
    //TLS FLAGS
    static let TLS_IS_FRESH = WarningFlags(rawValue: 1 << 40)
    //COOKIE FLAGS
    
    //HEADERS FLAGS
    
    // ... add more
}
    

