import Foundation
public struct LLMPriming {
    
    public static func loadPrimmingInstructions(brief: Bool, locale: String) -> ([String: Any], [String : Any]) {
        let primming : [String: Any] = primingBlock(brief: brief, locale: locale)
        let instruction : [String: Any] = instructions(brief: brief)
        
        return (primming, instruction)
        
    }
    
    public static func primingBlock(brief: Bool, locale: String) -> [String: Any] {
        var block = [String: Any]()
        if !brief {
            block = [
                "00_priming": "You are assessing a URL’s trustworthiness by analyzing its technical behavior, not its reputation. Do not return yes/no answers. Instead, explain observed signals (good or bad) and how they influenced the score. Be clear, neutral, and helpful.",
                "01_user_locale": locale,
                "02_expected_output": "Use clear, accessible language. Avoid excessive jargon. Think like you are helping a cautious user understand why the behavior matters."
                
            ]
            return block
        } else {
            block = [
                "00_priming": "Summarize how the URL behaved based only on the technical findings. Focus on what was observed, not assumptions. Keep it concise and easy to understand. Avoid technical jargon, and explain in plain language how the behavior relates to trust. If the site belongs to a known legitimate entity, you may still describe behavioral concerns clearly — explain why those behaviors could impact trust, even if they likely serve valid purposes.",
                "01_user_locale": locale,
                "02_expected_output": "Give only the final assessment in plain language. No technical details, no findings list - just whether the behavior seems trustworthy and why in 4-5 sentences maximum.",
                "03_output_style": "Use plain language for the user's locale. Avoid acronyms or technical terms unless clearly explained.",
            ]
            return block
        }
    }
    
    public static func instructions(brief: Bool) -> [String: Any] {
        if !brief {
            return [
                "01_request_model": "Each HTTP GET was a clean first-time visit from a mobile phone UA: no cookies, query parameters, fragments, local storage, or referrer are sent. This avoids user info leakage and ensures consistent testing.",
                "02_data_purpose": "The model receives a full set of observed technical behaviors from the target website, including headers, cookies, TLS details, scripts, and redirect chains. These findings are real, not hypothetical.",
                "03_model_behavior": "Use security reasoning to connect multiple findings. You are expected to assess patterns — not just list them. If the site uses known scam tactics, say so clearly. Do not sugarcoat risk when the signals are consistent and obvious",
                "04a_script_inline_reasoning": "If inline JavaScript snippets are present, evaluate whether they contain common UI or analytics logic versus suspicious constructs (e.g., obfuscated code, dynamic script injection, access to cookies, etc.). Inline scripts lacking proper CSP protections (like a nonce) may pose higher risk.",
                "04b_script_external_reasoning": "For external JavaScript, consider indicators like generic or suspicious filenames (e.g., payload.js), hidden or misleading path structures, or unversioned files. These are often signs of phishing kits or cloaking behavior, particularly when paired with weak headers or sketchy domains. Also look for the absence of Subresource Integrity (SRI), especially in third-party or protocol-relative URLs",
                "05_tracking_nuance": "Explain when cookies exhibit fingerprint-style tracking behaviors (e.g. high entropy, persistent values, overly broad scope). Recognize known infrastructure cookies from services like Akamai or Cloudflare as widely used — but still note their potential for profiling.",
                "06_behavioral_context": "This tool evaluates a site's behavior as if it were visited by a cautious, first-time user. Observations are turned into trust heuristics by analyzing structural hygiene and intent. Trust should be earned, not assumed.",
                "07_reasoning_expectation": "Explain combinations of signals: e.g., high-entropy cookies + missing headers + excessive redirects suggest aggressive tracking or poor hygiene. Clarify when technically risky behavior might serve valid purposes — but state the risk plainly. Think critically.",
                "08_consumer_protection_lens": "Frame findings in terms of what would help a non-technical user decide whether to trust the link. Focus on whether the observed behavior aligns with expected patterns for secure, well-maintained sites",
            ]
        } else {
            return [
                "01_request_model": "Each request is an HTTP GET that simulates a clean first-time visit from a mobile phone UA: no cookies, query parameters, fragments, storage, or referrer are sent.",
                "02_reasoning": "This avoids leaking user data and allows the report to reflect the site’s true behavior.",
                "03_model_behavior": "Use security reasoning to connect multiple findings. You are expected to assess patterns — not just list them. If the site uses known scam tactics, say so clearly. Avoid technical jargon — explain clearly how the observed behavior relates to trust. Even if the domain is a known brand, you should still describe behaviors that could impact trust and explain why they appear concerning or acceptable.",
            ]
        }
    }
}
