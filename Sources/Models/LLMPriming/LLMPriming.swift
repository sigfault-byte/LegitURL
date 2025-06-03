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
                "00_description": """
                  You will receive a JSON object with:
                    • meta { priming, instructions },  
                    • reports: [ { url, domain, tld, subdomain, path, script, findings } ],  
                    • scriptPreviews.  
                  Inside each report’s findings array are objects { "signal": string, "source": string }.  
                  Explain what each signal means in context: connect headers, TLS, scripts, cookies, and redirect behavior into a coherent security‐analysis narrative.  
                  Do not just repeat the findings; show how multiple signals combine into a pattern (e.g., “missing HSTS + new certificate + high script density → potential phishing kit”).
                """,
                "01_userLocale": locale,
                "02_expectedOutput": "Use plain, accessible language. Avoid unexplained acronyms. Think like you’re coaching a cautious user who wants to know, “Can I trust this link?”",
                "03_outputStyle": "Be clear and neutral—if you see suspicious behavior, say so; if you see valid reasons (e.g., a known CDN cookie), explain why it may be acceptable."
                
            ]
            return block
        } else {
            block = [
                "00_description": """
                  You will receive a JSON object with:
                    • “Summary” { inputUrl, finalUrl, numberOfRedirect, findings }  
                    • each entry in findings is { “signal”: string, “source”: string }.  
                  Describe only the observed technical behavior in 4–5 sentences. Do not echo the findings list; instead, weave them together into a clear, plain-language assessment of trust/risk (e.g., “the certificate is brand new, scripts lack integrity checks, and cookies look like tracking…”).  
                  Avoid technical jargon. If the site is a known brand, still point out any behaviors that could confuse a cautious visitor.
                """,
                "01_userLocale": locale,
                "02_expectedOutput": """
                  Write a short, plain-language verdict: “Overall, this site looks [trustworthy/risky] because ….” No bullet points, no raw findings list.
                """,
                "03_outputStyle": "Use very simple language (e.g., “new certificate,” “missing security header,” “tracking cookie”)."
            ]
            return block
        }
    }
    
    public static func instructions(brief: Bool) -> [String: Any] {
        if !brief {
            return [
                "01_requestContext": "Each HTTP GET is a clean mobile visit: no cookies, no referrer, no local storage. This ensures you see only the site’s true behavior.",
                "02_dataPurpose": "The model receives real observed behaviors—headers, cookies, TLS details, scripts, redirects. They are not hypothetical; they reflect exactly what the server sent.",
                "03_behavioralContext": "Frame every finding from the perspective of a cautious first-time visitor: what does this signal tell them about trust or risk?",
                "04_modelBehavior": "Connect multiple findings into patterns. If you see “high entropy cookie” + “no CSP” + “Redirect loop,” call out why they matter together.",
                "05_scriptInlineReasoning": "For inline scripts: look for obfuscated code, eval/atob, or missing nonces. Explain if inline JS might hide malicious logic.",
                "06_scriptExternalReasoning": "For external scripts: note missing SRI, generic file names (payload.js), or protocol-relative URLs. These often signal phishing/cloaking.",
                "07_trackingNuance": "When cookies have high entropy or SameSite=None, identify them as potential fingerprinting/tracking. Acknowledge legitimate CDN cookies but still note profiling risk.",
                "08_tlsContext": "Check certificate age—very new certificates can signal throwaway phishing sites. Note if the CA is trustworthy or potentially malicious.",
                "09_headerNuance": "If HSTS is missing on a 200 response, flag it unless the domain is preloaded. Missing X-Content-Type-Options or Referrer-Policy always merit mention.",
                "10_reasoningExpectation": "Go beyond listing. For example: “Although the certificate is domain-validated, it’s only 4 days old; combined with missing security headers, that suggests poor hygiene or a phishing kit.”",
                "11_consumerProtection_lens": "Summarize each section in a way that a non-technical user can understand: explain why each risky behavior (or each safe behavior) matters for everyday browsing."
            ]
        } else {
            return [
                "01_requestContext": """
                  Each request simulates a clean, first-time mobile GET: no cookies, no storage, no referrer. That ensures you see only the site’s true behavior.
                """,
                "02_behavioralContext": """
                  Interpret every finding through a consumer lens: “Would a non-technical visitor be surprised or put off by this?”  
                  Translate technical signals (“HSTS missing,” “eval in JS”) into “why it matters for someone’s trust.”
                """,
                "03_modelBehavior": """
                  Connect multiple signals. If you see both “high script density” and “missing CSP,” say why that combination is bad.  
                  Don’t simply list what you found.
                """
            ]
        }
    }
}
