//
//  WarningFlags.swift
//  LegitURL
//
//  Created by Chief Hakka on 16/04/2025.
//
struct WarningFlags: OptionSet {
    let rawValue: UInt128

    // HOST FLAGS (0–15)
    static let ABNORMAL_URL_STRUCTURE               = WarningFlags(rawValue: 1 << 0)
    static let DOMAIN_EXACT_BRAND_MATCH             = WarningFlags(rawValue: 1 << 1)
    static let DOMAIN_CONTAINS_BRAND                = WarningFlags(rawValue: 1 << 2)
    static let DOMAIN_SCAM_OR_PHISHING              = WarningFlags(rawValue: 1 << 3)
    static let DOMAIN_LOOKALIKE_BRAND_MATCH         = WarningFlags(rawValue: 1 << 4)
    static let SUBDOMAIN_CONTAINS_BRAND             = WarningFlags(rawValue: 1 << 5)
    static let SUBDOMAIN_CONTAINS_SCAMWORDS         = WarningFlags(rawValue: 1 << 6)
    static let SUBDOMAIN_CONTAINS_LOOKALIKE_BRANDS  = WarningFlags(rawValue: 1 << 7)
    static let DOMAIN_IS_WHITELISTED                = WarningFlags(rawValue: 1 << 8)

    // Reserved: 9–15

    // PATH FLAGS (16–31)
    static let PATH_EXACT_BRAND_MATCH               = WarningFlags(rawValue: 1 << 16)
    static let PATH_CONTAINS_BRAND                  = WarningFlags(rawValue: 1 << 17)
    static let PATH_LOOKALIKE_BRAND                 = WarningFlags(rawValue: 1 << 18)
    static let PATH_SCAM_OR_PHISHING                = WarningFlags(rawValue: 1 << 19)
    static let PATH_EXECUTABLE_HINT                 = WarningFlags(rawValue: 1 << 20)
    static let PATH_HIGH_ENTROPY                    = WarningFlags(rawValue: 1 << 21)
    static let PATH_ENDPOINTLIKE                    = WarningFlags(rawValue: 1 << 22)
    static let PATH_OBFUSCATED_STRUCTURE            = WarningFlags(rawValue: 1 << 23)
    static let PATH_EXECUTABLE_FILE_TYPE            = WarningFlags(rawValue: 1 << 24)

    // Reserved: 25–31

    // QUERY FLAGS (32–47)
    static let QUERY_OBFUSCATED_STRUCTURE           = WarningFlags(rawValue: 1 << 32)
    static let QUERY_URL                            = WarningFlags(rawValue: 1 << 33)
    static let QUERY_UUID                           = WarningFlags(rawValue: 1 << 34)
    static let QUERY_SCAM_PHISHYNG                  = WarningFlags(rawValue: 1 << 35)
    static let QUERY_HIGH_ENTROPY                   = WarningFlags(rawValue: 1 << 36)
    static let QUERY_CONTAINS_BRAND                 = WarningFlags(rawValue: 1 << 37)
    static let QUERY_LOOKALIKE_BRAND                = WarningFlags(rawValue: 1 << 38)
    static let QUERY_PERSONAL_INFORMATION           = WarningFlags(rawValue: 1 << 39)

    // Reserved: 40–46

    //FETCH FAIL
    static let FETCH_FAILED_TO_CONNECT              = WarningFlags(rawValue: 1 << 47)
    
    // BODY FLAGS (48–63)
    static let BODY_SCRIPT_END_NOT_FOUND            = WarningFlags(rawValue: 1 << 48)
    static let BODY_SCRIPT_DATAURI                  = WarningFlags(rawValue: 1 << 49)
    static let BODY_SCRIPT_UNKNOWN_ORIGIN           = WarningFlags(rawValue: 1 << 50)
    static let BODY_HIGH_JS_RATIO                   = WarningFlags(rawValue: 1 << 51)
    static let BODY_HTML_MALFORMED                  = WarningFlags(rawValue: 1 << 52)
    static let BODY_HIGH_SCRIPT_DENSITY             = WarningFlags(rawValue: 1 << 53)
    static let BODY_JS_SET_EDIT_COOKIE              = WarningFlags(rawValue: 1 << 54)
    static let BODY_JS_READ_COOKIE                  = WarningFlags(rawValue: 1 << 55)
    static let BODY_JS_JSON_ATOB_CHAIN              = WarningFlags(rawValue: 1 << 56)
    static let BODY_HIGH_SCRIPT_COUNT_LARGE_PAGE    = WarningFlags(rawValue: 1 << 57)
    static let BODY_JS_SCRIPT_PROTOCOL              = WarningFlags(rawValue: 1 << 58)

    // Reserved: 59–63

    // TLS FLAGS (64–79)
    static let TLS_IS_FRESH                         = WarningFlags(rawValue: 1 << 64)
    static let TLS_SANS_FLOOD                       = WarningFlags(rawValue: 1 << 65)
    static let TLS_IS_EV_OR_OV                      = WarningFlags(rawValue: 1 << 66)

    // Reserved: 67–79

    // COOKIE FLAGS (80–95)
    static let COOKIE_TRACKING                      = WarningFlags(rawValue: 1 << 80)
    static let COOKIE_DANGEROUS                     = WarningFlags(rawValue: 1 << 81)
    static let COOKIE_JS_ACCESS                     = WarningFlags(rawValue: 1 << 82)

    // Reserved: 83–95

    // HEADER FLAGS (96–127)
    static let HEADERS_CSP_MISSING                  = WarningFlags(rawValue: 1 << 96)
    static let HEADERS_CSP_MALFORMED                = WarningFlags(rawValue: 1 << 97)
    static let HEADERS_INCORRECT_LOGIC              = WarningFlags(rawValue: 1 << 98)
    static let HEADERS_FAKE_CSP                     = WarningFlags(rawValue: 1 << 99)
    static let HEADERS_LEAK_SERVER_VERSION          = WarningFlags(rawValue: 1 << 100)
    static let HEADERS_CSP_TRUSTED_TYPES            = WarningFlags(rawValue: 1 << 101)
    static let HEADERS_MISSING_HSTS                 = WarningFlags(rawValue: 1 << 102)
    static let HEADERS_CSP_TOO_MANY_URL_SOURCES     = WarningFlags(rawValue: 1 << 103)
    static let HEADERS_CSP_UNSAFE_EVAL              = WarningFlags(rawValue: 1 << 104)
    static let HEADERS_CSP_UNSAFE_INLINE            = WarningFlags(rawValue: 1 << 105)
    static let HEADERS_CSP_HAS_NONCE_OR_HASH        = WarningFlags(rawValue: 1 << 106)
    static let HEADERS_CSP_WILDCARD                 = WarningFlags(rawValue: 1 << 107)

    // Reserved: 108–127
    static let SLOPPY_DEVELOPMENT                  = WarningFlags(rawValue: 1 << 125)
}
