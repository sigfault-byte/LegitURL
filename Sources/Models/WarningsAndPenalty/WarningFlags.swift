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
    static let SUBDOMAIN_CONTAINS_SCAMWORDS = WarningFlags(rawValue: 1 << 6)
    static let SUBDOMAIN_CONTAINS_LOOKALIKE_BRANDS = WarningFlags(rawValue: 1 << 7)
    
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
    static let BODY_JS_JSON_ATOB_CHAIN = WarningFlags(rawValue: 1 << 38)
    static let BODY_HIGH_SCRIPT_COUNT_LARGE_PAGE = WarningFlags(rawValue: 1 << 39)
    static let BODY_JS_SCRIPT_PROTOCOL = WarningFlags(rawValue: 1 << 40)
    
    
    //TLS FLAGS
    static let TLS_IS_FRESH = WarningFlags(rawValue: 1 << 41)
    static let TLS_SANS_FLOOD = WarningFlags(rawValue: 1 << 42)
    static let TLS_IS_EV_OR_OV = WarningFlags(rawValue: 1 << 43)
    
    
    //COOKIE FLAGS
    
    
    //HEADERS FLAGS
    static let HEADERS_CSP_MISSING = WarningFlags(rawValue: 1 << 50)
    static let HEADERS_CSP_MALFORMED = WarningFlags(rawValue: 1 << 51)
    static let HEADERS_INCORRECT_LOGIC = WarningFlags(rawValue: 1 << 52)
    static let HEADERS_FAKE_CSP = WarningFlags(rawValue: 1 << 53)
    static let HEADERS_LEAK_SERVER_VERSION = WarningFlags(rawValue: 1 << 54)
    static let HEADERS_CSP_TRUSTED_TYPES = WarningFlags(rawValue: 1 << 55)
    
    
}
    
