public struct LLMPriming {
    public static var instructions: [String: Any] {
        return [
            "01_from": "analyzeLegitURLBatch",
            "02_task": "help the user assess the trustworthiness of the input URL, using the structured findings and security indicators",
            "03_HTTP request Type": "Each HTTP GET request is made from a clean client: no cookies, no local/session storage, no query parameters or fragments. This simulates a fresh user visiting the page for the first time, and applies equally to every request in the batch.",
            "04_scoreGuideline": [
                "safe": 100,
                "suspicious": "< 60",
                "untrusted": "< 40"
            ],
            "05_scoreInterpretation": "The score is based on security heuristics and structural signals, not on blacklists or user reports. A high score suggests strong hygiene, not guaranteed safety. A low score means caution is advised, but does not confirm malicious intent. The model should explain the reasons behind the score to help the user decide."
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
