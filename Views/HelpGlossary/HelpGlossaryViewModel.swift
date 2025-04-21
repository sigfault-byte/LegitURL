//
//  HelpGlossaryViewModel.swift
//  URLChecker
//
//  Created by Chief Hakka on 21/04/2025.
//
struct GlossaryTerm: Identifiable {
    let id: String        // used for scrollTo
    let term: String
    let description: String
}

struct HelpGlossaryData {
    static let terms: [GlossaryTerm] = [
        .init(
            id: "howItWorks",
            term:"How does LegitURL work?",
            description: "LegitURL analyzes a link in two steps. First, it checks the structure of the URL offline to detect scam words, strange encodings, or impersonations. Then it visits the URL without revealing where you're coming from, and examines the TLS certificate, security headers, cookies, and scripts—without sending any personal data. \nEverything happens on your device to protect your privacy."
        ),
        .init(
            id: "tls",
            term: "TLS Certificate",
            description: "TLS (Transport Layer Security) certificates are digital credentials used to encrypt communication between your browser and a website. They also verify the server's identity, preventing attackers from impersonating secure sites."
        ),
        .init(
            id: "dv",
            term: "DV Certificate",
            description: "Domain Validated (DV) certificates are the most basic type of TLS certificate. They're easy to obtain and only verify domain ownership — not the legitimacy of the organization — which makes them easier to abuse by scammers."
        ),
        .init(
            id: "fingerprint",
            term: "Fingerprint",
            description: "A fingerprint is a unique hash of a TLS certificate used to identify it precisely. It helps detect when the same certificate is reused across multiple domains, which can indicate suspicious infrastructure."
        ),
        .init(
            id: "header",
            term: "Header",
            description: "HTTP headers are pieces of metadata sent by the server to instruct the browser how to handle the page. Some control security behavior, such as content policy or cookie restrictions."
        ),
        .init(
            id: "cookie",
            term: "Cookie",
            description: "Cookies are small data files that websites store in your browser to remember preferences, sessions, or track behavior. Some cookies are essential; others can be used for surveillance and analytics."
        ),
        .init(
            id: "redirect",
            term: "Redirect",
            description: "Redirects are instructions from the server that automatically send a user to a different URL. They can be used legitimately (e.g., 'www' redirection) or maliciously to obscure phishing destinations."
        ),
        .init(
            id: "csp",
            term: "CSP",
            description: "CSP (Content Security Policy) is a security header that tells the browser which scripts, styles, and resources are allowed to load. It’s designed to reduce the risk of XSS (cross-site scripting) attacks."
        )
    ]
    
    static func lookup(id: String) -> String {
        terms.first(where: { $0.id == id })?.description ?? "No description available."
    }
}
