
import Foundation
public struct LLMPriming {
    public static var instructions: [String: Any] {
        return [
            "01_from": "analyzeLegitURLBatch",
            "02_task": "evaluateURLHygiene",
            "03_request_model": "Each HTTP GET simulates a clean first-time visit: no cookies, storage, query, or fragment.",
            "04_score_guide": [
                "safe": "100",
                "suspicious": "< 60",
                "untrusted": "< 40"
            ],
            "05_interpretation": "Scores reflect web hygiene signals - not blocklists or user votes. High = strong practices. Low = possible risks. Always explain what influenced the score.",
            "06_model_behavior": "Reason analytically with web security knowledge. Avoid inflating minor issues. If findings seem odd for known sites, verify certs, cookies (key, entropy, length), and redirects. Be clear, objective, and accessible. No verdicts — explain the why.",
            "07_behavioral_context": "This tool performs behavioral pattern analysis of websites using security hygiene signals as heuristics for trustworthiness. It measures what websites actually do, not what they claim to be or their reputation.",
            "08_consumer_protection_lens": "Interpret findings through the lens of 'What behavioral signals would help a non-technical user assess an unknown link?' Focus on patterns that distinguish well-maintained sites from hastily-built or potentially deceptive ones.",
            "09_scoring_philosophy": "Scores reflect behavioral trustworthiness signals, not definitive security verdicts. High scores indicate sites that 'behave' like they're well-maintained and transparent. Low scores indicate sites exhibiting patterns common in poorly-maintained or potentially deceptive websites.",
            ]
    }
}
//    public static let priming: String = """
//{
//  "from": "analyzeLegitURLBatch",
//  "task": "explain the following findings to assess if the link is safe",
//  "HTTP request Type": "http Get are stripped from queries, empty cookie jar, empty local storage",
//  "scoreGuideline": {
//    "safe": 100,
//    "suspicious": "< 60",
//    "untrusted": "< 40"
//  },
//  "keys": {
//    "url": "Input URL",
//    "fh": "Final URL",
//    "rh": "Redirect Hops",
//    "os": "Overall Score",
//    "d": "Domain",
//    "sd": "SubDomain",
//    "pc" : "Punycode host",
//    "tld": "TLD",
//    "p" : "Path",
//    "q": "Query",
//    "f": "fragment",
//    "scam": "Scam Warnings",
//    "susp": "Suspicious Warnings",
//    "info": "Info Messages",
//    "rc": "Response Code",
//    "stxt": "Status Text",
//    "furl": "Redirect URL",
//    "certCN": "Certificate Common Name",
//    "certOrg": "Certificate Organization",
//    "issuerCN": "Issuer Common Name",
//    "issuerOrg": "Issuer Organization",
//    "validF": "Valid From",
//    "c" : "cookies",
//    "expires": "Expires",
//    "pkAlgo": "Public Key Algorithm",
//    "ku": "Key Usage",
//    "eku": "Extended Key Usage",
//    "certPol": "Certificate Policies",
//    "selfSign": "Self-Signed",
//    "san": "Subject Alternative Names",
//    "h": "Headers",
//    "csp": "Content Security Policy",
//    "hsts": "Strict-Transport-Security",
//    "xcto": "X-Content-Type-Options",
//    "refPol": "Referrer-Policy",
//    "jsT": "Total Scripts",
//    "jsI": "Inline Scripts",
//    "jsH": "HTTPS Scripts",
//    "jsD": "Data Scripts",
//    "jsHead": "Scripts in <head>",
//    "jsBody": "Scripts in <body>",
//    "jsInlineCrit": "Inline Critical JS",
//    "jsFuncCall": "Function(...) Calls",
//    "jsFetchCall": "Fetch(...) Calls",
//    "jsCookieRead": "Cookie Reads",
//    "jsSetItem": "SetItem Calls",
//    "fd": "Findings",
//    "sev": "Severity",
//    "msg": "Message"
//  }
//}
//"""


//"10_key_map": [
//    "meta": [
//        "url": "Input URL",
//        "final": "Final URL",
//        "score": "Overall Score",
//        "hops": "Redirect Hops",
//        "f":"findings",
//        "p": "penlaty",
//        "curl" : "URL get requested"
//    ],
//    "domain": [
//        "d": "Domain",
//        "sd": "Subdomain",
//        "tld": "Top-Level Domain",
//        "pc": "Punycode Host",
//        "pt": "Path",
//        "q": "Query String",
//        "fr": "Fragment",
//        "c" : "count"
//    ],
//    "online": [
//        "rc" : "response code",
//        "st" : "status text",
//        "rt" : "redirected to"
//    ],
//    "cert": [
//        "cn": "Certificate Common Name",
//        "san": "Subject Alternative Names",
//        "pol": "Certificate Policies",
//        "nb": "Valid From",
//        "na": "Valid Until",
//        "iss": "Issuer Common Name"
//    ],
//    "cookie": [
//        "k": "Cookie Name",
//        "el": "Entropy Level",
//        "vl": "Value Length",
//        "ss": "SameSite Policy",
//        "sc": "Secure",
//        "ho": "HttpOnly",
//        "exp": "Expires In",
//        "s" : "session",
//    ],
//    "js": [
//        "t": "Total Scripts",
//        "i": "Inline Scripts",
//        "s": "External Scripts",
//        "n": "Nonce Count",
//        "sz": "Total Inline Size",
//        "dURI": "DataURI c",
//        "he": "external c",
//        "r" : "relative c",
//        "me": "module External c",
//        "ds": "dataScript c",
//        "u" : "unknown",
//    ],
//    "headers": [
//        "sec": "Security Headers",
//        "trk": "Tracking Headers",
//        "srv": "Server Metadata"
//    ]
//]
//]
