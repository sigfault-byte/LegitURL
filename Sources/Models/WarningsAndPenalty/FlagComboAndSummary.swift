//
//  FlagComboAndSummary.swift
//  LegitURL
//
//  Created by Chief Hakka on 29/04/2025.
//

struct SpecialFlags: OptionSet {
    let rawValue: UInt8

    static let trustedDomain = SpecialFlags(rawValue: 1 << 0)
    static let fetchFailure  = SpecialFlags(rawValue: 1 << 1)
    // Reserve more here
}

struct ComboAlert {
    var flags: UInt128
    var message: String?
    
    static func computeBitFlagAndInfer(from urlInfos: [URLInfo]) -> (ComboAlert, SpecialFlags) {
        let flags = fetchInt(from: urlInfos)
        var comboAlert = ComboAlert(flags: flags, message: nil)
        
        var specialFlags: SpecialFlags = []

        if (flags & (1 << 8)) != 0 {
            specialFlags.insert(.trustedDomain)
        }
        
        inferMessage(for: &comboAlert)
        
        return (comboAlert, specialFlags)
    }
    
    
    
    static func fetchInt(from urlInfos: [URLInfo]) -> UInt128 {
        var combinedFlags: UInt128 = 0
        
        for urlInfo in urlInfos {
            for warning in urlInfo.warnings {
                combinedFlags |= warning.bitFlags.rawValue  // Merge
            }
        }
        return combinedFlags
    }
    
    static func inferMessage(for combo: inout ComboAlert) {
        let f = combo.flags
        
        // 0. Basic security missing (short circuit critical)
        if f & WarningFlags.HEADERS_CSP_MISSING.rawValue != 0 {
            combo.message = "This website is missing basic security protections that help block malicious scripts."
            return
        }
        

        if f & WarningFlags.HEADERS_CSP_MALFORMED.rawValue != 0 {
            combo.message = "This website's security setup is broken or incomplete, which may leave it vulnerable."
            return
        }

        if f & WarningFlags.HEADERS_MISSING_HSTS.rawValue != 0 {
            combo.message = "This website doesn't fully protect your connection from being tampered with."
            return
        }

        if f & WarningFlags.BODY_HTML_MALFORMED.rawValue != 0 || f & WarningFlags.BODY_SCRIPT_END_NOT_FOUND.rawValue != 0 {
            combo.message = "The website's code looks messy or broken, which can be a warning sign of poor security or hidden tricks."
            return
        }

        // 1. Brand impersonation + scam detection
        if (
            (f & WarningFlags.DOMAIN_CONTAINS_BRAND.rawValue != 0 ||
             f & WarningFlags.SUBDOMAIN_CONTAINS_BRAND.rawValue != 0 ||
             f & WarningFlags.PATH_CONTAINS_BRAND.rawValue != 0 ||
             f & WarningFlags.QUERY_CONTAINS_BRAND.rawValue != 0 ||
             f & WarningFlags.DOMAIN_LOOKALIKE_BRAND_MATCH.rawValue != 0 ||
             f & WarningFlags.SUBDOMAIN_CONTAINS_LOOKALIKE_BRANDS.rawValue != 0 ||
             f & WarningFlags.PATH_LOOKALIKE_BRAND.rawValue != 0 ||
             f & WarningFlags.QUERY_LOOKALIKE_BRAND.rawValue != 0
            )
            &&
            (f & WarningFlags.DOMAIN_SCAM_OR_PHISHING.rawValue != 0 ||
             f & WarningFlags.SUBDOMAIN_CONTAINS_SCAMWORDS.rawValue != 0 ||
             f & WarningFlags.PATH_SCAM_OR_PHISHING.rawValue != 0 ||
             f & WarningFlags.QUERY_SCAM_PHISHYNG.rawValue != 0
            )
        ) {
            combo.message = "This website is pretending to be a known brand and shows signs of scams — it is highly dangerous."
            return
        }

        // 2. Aggressive tracking detected
        if (
            (f & WarningFlags.QUERY_UUID.rawValue != 0 ||
             f & WarningFlags.QUERY_HIGH_ENTROPY.rawValue != 0)
            &&
            (f & WarningFlags.COOKIE_TRACKING.rawValue != 0 ||
             f & WarningFlags.COOKIE_DANGEROUS.rawValue != 0)
        ) {
            combo.message = "This website is tracking visitors very aggressively, including hidden IDs in links and tracking cookies."
            return
        }

        // 3. Lying about cookie access
        if f & WarningFlags.COOKIE_JS_ACCESS.rawValue == 0 {
            if (f & WarningFlags.BODY_JS_READ_COOKIE.rawValue != 0 || f & WarningFlags.BODY_JS_SET_EDIT_COOKIE.rawValue != 0) {
                combo.message = "This site header gives cookie not supposed to be read by js, but its code is reading or changing browser cookies."
                URLQueue.shared.legitScore.score += -5
                return
            }
        }

        // 4. Excessive JavaScript and CSP issues
        if (f & WarningFlags.BODY_HIGH_JS_RATIO.rawValue != 0) {
            if f & WarningFlags.HEADERS_CSP_UNSAFE_EVAL.rawValue != 0 {
                combo.message = "This website allows risky scripts to run, which can open the door to hidden attacks."
                return
            }

            if f & WarningFlags.HEADERS_CSP_UNSAFE_INLINE.rawValue != 0 {
                combo.message = "This website allows scripts to be injected directly into the page, which is a serious security risk."
                return
            }

            if f & WarningFlags.HEADERS_CSP_UNSAFE_INLINE.rawValue != 0 && WarningFlags.HEADERS_CSP_HAS_NONCE_OR_HASH.rawValue != 0 {
                combo.message = "This website tries to control risky scripts but still has unsafe behaviors."
                return
            }

            combo.message = "This website uses a very high amount of JavaScript. This can either mean it is a modern web app, or that it may be hiding malicious actions."
            return
        }

        // TODO: --- Fallback ---
        combo.message = ""
    }
}
