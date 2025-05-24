//
//  htmlReport.swift
//  LegitURL
//
//  Created by Chief Hakka on 21/05/2025.
//

//TODO:     1.    Render each section (summary, redirect, cert, headers, etc.) in its own WKWebView
//2.    Use .createPDF(...) per section
//3.    Store the Data from each one
//4.    Merge into a single PDFDocument

import Foundation

func generateHTML(from queue: URLQueue) -> String {
    let formatter: ISO8601DateFormatter = {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.formatOptions = [.withInternetDateTime] // outputs full `T` + `Z` format
        return formatter
    }()
    
    let score = queue.legitScore.score
    let scoreClass = score < 40 ? "critical" : score < 70 ? "suspicious" : "ok"
    var html = """
    
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <style>
            body { font-family: -apple-system, Helvetica, Arial, sans-serif; margin: 40px;, max-width: 100vW, overflow-x: hidden }
            .container {
              max-width: 960px;
              margin: 0 auto;
              padding: 20px;
              background-color: #fff;
            }
            table {
              border-collapse: collapse;
              width: 100%;
              margin-bottom: 24px;
              table-layout: fixed;
            }
            th, td {
              border: 1px solid #ddd;
              padding: 8px;
              word-break: break-word;
              word-wrap: break-word;
              overflow-wrap: break-word;
              white-space: normal;
              vertical-align: top;
              max-width: 100% ;
            }
            th { background-color: #f2f2f2; }
            .critical {
              color: #a10000;
              font-weight: bold;
              background-color: #ffe5e5;
              padding: 2px 6px;
              border-radius: 4px;
            }
            .dangerous {
              color: #d00000;
            }
            .suspicious {
              color: #cc7a00;
            }
            .info {
              color: #0066cc;
            }
            .good {
              color: #007700;
            }
            table th { text-align: left; width: 25%; vertical-align: top;}
            table td { width: 75%; }
            table th:first-child,
            table td:first-child {
              width: 25%;
              vertical-align: top;
            }
            table th:last-child,
            table td:last-child {
              width: 75%;
            }
            td:empty::after { content: "-"; color: #999; font-style: italic; }
            td:has(:is(:empty, :contains("-"))) { color: #999; font-style: italic; }
            hr.rounded { border-top: 8px solid #bbb; border-radius: 5px; }
            code {
              font-family: monospace;
              background-color: #f4f4f4;
              padding: 2px 4px;
              border-radius: 4px;
              word-break: break-word;
              white-space: pre-wrap;
              display: block;
              max-width: 100%;
              overflow-wrap: break-word;
              overflow-x: auto;
            }
            h1, h2, h3, h4 { margin-top: 32px; margin-bottom: 8px; }
            h2 {
              font-size: 1.5em;
              margin-top: 36px;
              margin-bottom: 12px;
              border-bottom: 2px solid #ccc;
              padding-bottom: 4px;
            }
            h3 {
              font-size: 1.2em;
              margin-top: 28px;
              margin-bottom: 10px;
              color: #333;
              border-left: 4px solid #0066cc;
              padding-left: 10px;
              background-color: #f9f9f9;
            }
            .url-title {
              word-break: break-word;
              background-color: #f0f4f8;
              padding: 10px;
              border-left: 5px solid #0066cc;
              font-size: 1.3em;
              margin-top: 40px;
              margin-bottom: 16px;
            }
            ul {
              margin-bottom: 16px;
              padding-left: 20px;
            }
            li {
              margin-bottom: 6px;
              word-break: break-word;
            }
            @media print {
              .page-break {
                page-break-before: always !important;
                break-before: page !important;
                display: block !important;
              }
            }
            .page-break {
              page-break-before: always;
              break-before: page;
              display: block;
              height: 1px;
              margin: 0;
            }
            h2, h3, table, ul {
              page-break-inside: avoid;
              break-inside: avoid;
            }
            .report-title {
              font-size: 2em;
              font-weight: bold;
              border-bottom: 3px solid #0066cc;
              padding-bottom: 6px;
              margin-bottom: 4px;
              color: #222;
            }
            .report-date {
              text-align: right;
              font-size: 1em;
              color: #666;
              margin-bottom: 4px;
              font-style: italic;
            }
            .report-disclaimer {
              font-size: 0.95em;
              color: #555;
              margin-top: -10px;
            }
        </style>
    </head>
    <body>
    <div class="container">
        <h1 class="report-title">LegitURL Report</h1>
        <p class="report-date">Generated on \(formatter.string(from: Date()))</p>
        <p class="report-disclaimer">This report uses heuristics.</p>
        <p class="report-disclaimer">A low score does not imply the URL is malicious, only that it lacks strong security hygiene.</p>
    <hr class="rounded">
    """
    
    // Into summary
    html += """
    <h1>Summary</h1>
    <table>
    <tr><th>Input URL</th><td>\(queue.offlineQueue.first?.components.fullURL ?? "")</td></tr>
    <tr><th>Final URL</th><td>\(queue.offlineQueue.last?.components.fullURL ?? "")</td></tr>
    <tr><th>Redirect Hops</th><td>\(queue.offlineQueue.count - 1)</td></tr>
    <tr><th class= \"\(scoreClass)\">Overall Score</th><td>\(score)</td></tr>
    </table>
    <hr class="rounded">
    """
    
    
    // Analysis Report
    for (index, report) in queue.offlineQueue.enumerated() {
        html += "<div class=\"page-break\"></div>"
        let components = report.components
        
        let relevantGetError: [SecurityWarning.SourceType] = [.getError]
        let sectionWarningsGetError = report.warnings.filter { relevantGetError.contains($0.source) }
        if !sectionWarningsGetError.isEmpty {
            html += "<ul>"
            for warning in sectionWarningsGetError {
                html += "<li class=\"\(warning.severity.rawValue.lowercased())\">[\(warning.severity.rawValue.uppercased())] \(warning.message)</li>"
            }
            html += "</ul>"
        }
        
        
        // Open the table
        html += """
        <h2 class="url-title">URL #\(index + 1): \(components.fullURL ?? "-")</h2>
        <table>
        """
        if let subdomain = components.subdomain, !subdomain.isEmpty {
            html += "<tr><th>Subdomain</th><td>\(subdomain)</td></tr>"
        }
        html += """
        <tr><th>Domain</th><td>\(components.extractedDomain ?? "-")</td></tr>
        <tr><th>TLD</th><td>\(components.extractedTLD ?? "-")</td></tr>
        """
        if components.punycodeHostEncoded != components.host {
            html += "<tr><th>Punycode (if any)</th><td>\(components.punycodeHostEncoded ?? "-")</td></tr>"
        }
        if components.query != nil {
            html += "<tr><th>Query</th><td>\(components.query ?? "-")</td></tr>"
        }
        if components.fragment != nil {
            html += "<tr><th>Fragment</th><td>\(components.fragment ?? "-")</td></tr>"
        }
        
        // Close the table
        html += """
        </table>
        """
        
        // Lamai
        if !components.lamaiTrees.isEmpty {
            html += "<h3>Decoded Data</h3>"
            for (tree, values) in components.lamaiTrees {
                html += "<h4>Origin: \(tree)</h4>"
                html += "<ul>"
                for node in values {
                    html += renderNode(node)
                }
                html += "</ul>"
                html += "<hr class=\"rounded\">"
            }
        }
        
        let relevantOffline: [SecurityWarning.SourceType] = [.host, .path, .fragment, .query]
        let sectionWarningsOffline = report.warnings.filter { relevantOffline.contains($0.source) }
        if !sectionWarningsOffline.isEmpty {
            html += "<ul>"
            for warning in sectionWarningsOffline {
                html += "<li class=\"\(warning.severity.rawValue.lowercased())\">[\(warning.severity.rawValue.uppercased())] \(warning.message)</li>"
            }
            html += "</ul>"
        }
        
        
        html += "<div class=\"page-break\"></div>"
        
        // Online info
        let onlineMap = Dictionary(uniqueKeysWithValues: queue.onlineQueue.map { ($0.id, $0) })
        if let online = onlineMap[report.id] {
            html += """
            <h2>Online Information</h2>
            <table>
            <tr><th>Response Code</th><td>\(online.serverResponseCode.map(String.init) ?? "-")</td></tr>
            <tr><th>Status Text</th><td>\(online.statusText ?? "-")</td></tr>
            <tr><th>Final Redirect URL</th><td>\(online.finalRedirectURL ?? "-")</td></tr>
            </table>
            """
            
            if let cert = online.parsedCertificate {
                html += generateHTMLCertificate(from: cert)
            }
            let relevantTLS: [SecurityWarning.SourceType] = [.tls, .redirect, .responseCode]
            let sectionWarningsTLS = report.warnings.filter { relevantTLS.contains($0.source) }
            if !sectionWarningsTLS.isEmpty {
                html += "<ul>"
                for warning in sectionWarningsTLS {
                    html += "<li class=\"\(warning.severity.rawValue.lowercased())\">[\(warning.severity.rawValue.uppercased())] \(warning.message)</li>"
                }
                html += "</ul>"
            }
            
            
            if !online.cookiesForUI.isEmpty {
                html += "<h3>Cookies</h3>"
                
                for cookie in online.cookiesForUI.compactMap({ $0 }) {
                    html += "<h4>Cookie Key: \(cookie.cookie.name)</h4>"
                    html += "<table>"
                    
                    html += "<tr><th>Severity</th><td class=\"\(cookie.severity.rawValue.lowercased())\">\(cookie.severity.rawValue.capitalized)</td></tr>"
                    html += "<tr><th>Value Size</th><td>\(cookie.cookie.value.count) bytes</td></tr>"
                    
                    let expiryDescription = cookie.cookie.expire == nil ? "Session" : "Persistent"
                    html += "<tr><th>Expires In</th><td>\(expiryDescription)</td></tr>"
                    
                    html += "<tr><th>SameSite Policy</th><td>\(cookie.cookie.sameSite)</td></tr>"
                    html += "<tr><th>Secure</th><td>\(cookie.cookie.secure ? "Yes" : "No")</td></tr>"
                    html += "<tr><th>HttpOnly</th><td>\(cookie.cookie.httpOnly ? "Yes" : "No")</td></tr>"
                    html += "<tr><th>Path</th><td>\(cookie.cookie.path)</td></tr>"
                    html += "<tr><th>Domain</th><td>\(cookie.cookie.domain)</td></tr>"
                    html += "<tr><th>Value</th><td><code>\(cookie.cookie.value)</code></td></tr>"
                    
                    html += "</table>"
                }
            }
            let relevantCookie: [SecurityWarning.SourceType] = [.cookie]
            let sectionWarningsCookie = report.warnings.filter { relevantCookie.contains($0.source) }
            if !sectionWarningsCookie.isEmpty {
                html += "<ul>"
                for warning in sectionWarningsCookie {
                    html += "<li class=\"\(warning.severity.rawValue.lowercased())\">[\(warning.severity.rawValue.uppercased())] \(warning.message)</li>"
                }
                html += "</ul>"
            }
            
            html += "<div class=\"page-break\"></div>"
            
            // headers
            if let headers = online.parsedHeaders {
                func renderHeaderGroup(title: String, headers: [String: String]) {
                    if !headers.isEmpty {
                        html += "<h4>\(title)</h4><table>"
                        for (name, value) in headers {
                            html += "<tr><th>\(name)</th><td>\(value)</td></tr>"
                        }
                        html += "</table>"
                    }
                }
                
                html += "<h3>Response Headers</h3>"
                renderHeaderGroup(title: "Security Headers", headers: headers.securityHeaders)
                renderHeaderGroup(title: "Tracking Headers", headers: headers.trackingHeaders)
                renderHeaderGroup(title: "Server Headers", headers: headers.serverHeaders)
                renderHeaderGroup(title: "Other Headers", headers: headers.otherHeaders)
            }
            
            if let csp = online.cspOfHeader {
                let CSPSource = csp.source == "CSP" ? "Content-Security-Policy" : "Content-Security-Policy-Report-Only"
                html += "<h3>\(CSPSource)</h3>"
                html += "<table>"
                html += "<tr><th>Total Directives</th><td>\(csp.directiveBitFlags.count)</td></tr>"
                
                let selfOnlyCount = csp.directiveSourceTraits.values.filter { $0.onlySelf }.count
                let withHTTPCount = csp.directiveSourceTraits.values.filter { $0.hasHTTP }.count
                let hasWildcard = csp.directiveSourceTraits.values.contains { $0.hasWildcard }
                
                html += "<tr><th>Directives with 'self' only</th><td>\(selfOnlyCount)</td></tr>"
                html += "<tr><th>Directives with HTTP</th><td>\(withHTTPCount)</td></tr>"
                html += "<tr><th>Wildcards Found</th><td>\(hasWildcard ? "Yes" : "No")</td></tr>"
                html += "</table>"
                
                html += "<h4>Directive Breakdown</h4>"
                html += "<table><tr><th>Directive</th><th>Values</th></tr>"
                
                for (directive, valueMap) in csp.structuredCSP {
                    let values = valueMap.keys.compactMap { String(data: $0, encoding: .utf8) }
                    let formatted = values.isEmpty ? "-" : values.joined(separator: ", ")
                    html += "<tr><td>\(directive)</td><td>\(formatted)</td></tr>"
                }
                
                html += "</table>"
            }
            let relevantHeaders: [SecurityWarning.SourceType] = [.header]
            let sectionWarningsHeaders = report.warnings.filter { relevantHeaders.contains($0.source) }
            if !sectionWarningsHeaders.isEmpty {
                html += "<ul>"
                for warning in sectionWarningsHeaders {
                    html += "<li class=\"\(warning.severity.rawValue.lowercased())\">[\(warning.severity.rawValue.uppercased())] \(warning.message)</li>"
                }
                html += "</ul>"
            }
            
            
            html += "<div class=\"page-break\"></div>"
            
            let scripts = online.script4daUI
            
            if !scripts.isEmpty {
                html += "<h3>JavaScript Summary</h3>"
                
                let totalCount = scripts.count
                let inlineCount = scripts.filter { $0.origin == .inline || $0.origin == .moduleInline }.count
                let dataCount = scripts.filter { $0.origin == .dataURI }.count
                let httpCount = scripts.filter { $0.origin == .httpExternal || $0.origin == .httpsExternal }.count
                let relativeCount = scripts.filter { $0.origin == .relative || $0.origin == .protocolRelative }.count
                let moduleExternalCount = scripts.filter { $0.origin == .moduleExternal || $0.origin == .moduleRelative }.count
                let dataScriptCount = scripts.filter { $0.origin == .dataScript }.count
                let unknownCount = scripts.filter { $0.origin == .unknown || $0.origin == .malformed }.count
                
                html += "<table>"
                html += "<tr><th>Total Scripts</th><td>\(totalCount)</td></tr>"
                if inlineCount > 0 {
                    html += "<tr><th>Inline Scripts</th><td>\(inlineCount)</td></tr>"
                }
                if dataCount > 0 {
                    html += "<tr><th>Data URI Scripts</th><td>\(dataCount)</td></tr>"
                }
                if httpCount > 0 {
                    html += "<tr><th>HTTP/HTTPS Scripts</th><td>\(httpCount)</td></tr>"
                }
                if relativeCount > 0 {
                    html += "<tr><th>Relative Scripts</th><td>\(relativeCount)</td></tr>"
                }
                if moduleExternalCount > 0 {
                    html += "<tr><th>Module External/Relative Scripts</th><td>\(moduleExternalCount)</td></tr>"
                }
                if dataScriptCount > 0 {
                    html += "<tr><th>Data Scripts</th><td>\(dataScriptCount)</td></tr>"
                }
                if unknownCount > 0 {
                    html += "<tr><th>Unknown or Malformed Scripts</th><td>\(unknownCount)</td></tr>"
                }
                html += "</table>"
                
                let scriptsInHead = scripts.filter { $0.context == .inHead }
                let scriptsInBody = scripts.filter { $0.context == .inBody }
                let scriptsUnknown = scripts.filter { $0.context == .unknown}
                
                var counter: Int = 1
                // --- REPLACEMENT: Scripts in <head> ---
                if !scriptsInHead.isEmpty {
                    html += "<h4>Scripts in &lt;head&gt;</h4><ul>"
                    for script in scriptsInHead {
                        let sizeClass = script.size > 50000 ? "dangerous" : ""
                        let size = CommonTools.humanReadableBytes(script.size)
                        let origin = script.origin
                        let inline = script.isInline
                        html += "<li><strong>#\(String(counter)): </strong>"
                        if !inline &&
                            origin == .httpExternal || origin == .httpsExternal ||
                            origin == .protocolRelative || origin == .moduleExternal ||
                            origin == .moduleRelative || origin == .relative {
                            let originString: String = script.origin?.rawValue ?? "error"
                            html += "<strong>\(originString) Script</strong><ul>"
                            html += "<li><strong>Source:</strong> \(script.extractedSrc ?? "")</li>"
                            let isModule = script.isModule ?? false
                            if isModule {
                                html += "<li><strong>Module:</strong> Yes</li>"
                                html += "<li><strong>Cross-Origin:</strong> \(script.crossOriginValue ?? "empty (defaults to anonymous)")</li>"
                            }
                            if let sri = script.integrity, !sri.isEmpty {
                                html += "<li><strong>Integrity:</strong> <code>\(sri)</code></li>"
                            }
                        } else if origin == .moduleInline || origin == .inline {
                            html += "<strong>Inline Script</strong><ul>"
                            if let nonce = script.nonce, !nonce.isEmpty {
                                html += "<li><strong>Nonce:</strong> <code>\(nonce)</code></li>"
                            }
                        } else if origin == .dataURI {
                            html += "<strong>Data URI Script</strong><ul>"
                        } else if origin == .dataScript {
                            html += "<strong>Data Script</strong><ul>"
                        }else {
                            html += "<strong>\(origin?.rawValue ?? "Unknown") Script</strong><ul>"
                        }
                        html += "<li class=\"\(sizeClass)\"><strong>Size:</strong> \(size)</li>"
                        
                        if script.isInline, let findings = script.findings {
                            var snippetIndex = 0
                            html += "<ul>"
                            for finding in findings {
                                let severityClass = finding.severity.rawValue.lowercased()
                                html += "<li class=\"\(severityClass)\">[\(finding.severity.rawValue.uppercased())] \(finding.message)</li>"
                                
                                if finding.pos != 0,
                                   let snippets = script.focusedSnippets,
                                   snippetIndex < snippets.count {
                                    let snippetEscaped = htmlEscape(snippets[snippetIndex])
                                    html += "<li><code>\(snippetEscaped)</code></li>"
                                    snippetIndex += 1
                                }
                            }
                            html += "</ul>"
                        }
                        counter += 1
                        html += "</ul></li>"
                    }
                    html += "</ul>"
                }
                
                // --- REPLACEMENT: Scripts in <body> ---
                if !scriptsInBody.isEmpty {
                    html += "<h4>Scripts in &lt;body&gt;</h4><ul>"
                    for script in scriptsInBody {
                        let sizeClass = script.size > 50000 ? "dangerous" : ""
                        let size = CommonTools.humanReadableBytes(script.size)
                        let origin = script.origin
                        let inline = script.isInline
                        html += "<li><strong>#\(String(counter)): </strong>"
                        if !inline &&
                            origin == .httpExternal || origin == .httpsExternal ||
                            origin == .protocolRelative || origin == .moduleExternal ||
                            origin == .moduleRelative || origin == .relative {
                            let originString: String = script.origin?.rawValue ?? "error"
                            html += "<strong>\(originString) Script</strong><ul>"
                            html += "<li><strong>Source:</strong> \(script.extractedSrc ?? "")</li>"
                            let isModule = script.isModule ?? false
                            if isModule {
                                html += "<li><strong>Module:</strong> Yes</li>"
                                html += "<li><strong>Cross-Origin:</strong> \(script.crossOriginValue ?? "empty (defaults to anonymous)")</li>"
                            }
                            if let sri = script.integrity, !sri.isEmpty {
                                html += "<li><strong>Integrity:</strong> <code>\(sri)</code></li>"
                            }
                        } else if origin == .moduleInline || origin == .inline {
                            html += "<strong>Inline Script</strong><ul>"
                            if let nonce = script.nonce, !nonce.isEmpty {
                                html += "<li><strong>Nonce:</strong> <code>\(nonce)</code></li>"
                            }
                        } else if origin == .dataURI {
                            html += "<strong>Data URI Script</strong><ul>"
                        } else if origin == .dataScript {
                            html += "<strong>Data Script</strong><ul>"
                        }
                        else {
                            html += "<strong>\(origin?.rawValue ?? "Unknown") Script</strong><ul>"
                        }
                        html += "<li class=\"\(sizeClass)\"><strong>Size:</strong> \(size)</li>"
                        if script.isInline, let findings = script.findings {
                            var snippetIndex = 0
                            html += "<ul>"
                            for finding in findings {
                                let severityClass = finding.severity.rawValue.lowercased()
                                html += "<li class=\"\(severityClass)\">[\(finding.severity.rawValue.uppercased())] \(finding.message)</li>"
                                
                                if finding.pos != 0,
                                   let snippets = script.focusedSnippets,
                                   snippetIndex < snippets.count {
                                    let snippetEscaped = htmlEscape(snippets[snippetIndex])
                                    html += "<li><code>\(snippetEscaped)</code></li>"
                                    snippetIndex += 1
                                }
                            }
                            html += "</ul>"
                        }
                        counter += 1
                        html += "</ul></li>"
                    }
                    html += "</ul>"
                }
                
                // Keep handling unknown context
                if !scriptsUnknown.isEmpty {
                    html += "<h4>Unknown context Scripts</h4><ul>"
                    for script in scriptsUnknown {
                        let origin = script.isInline ? "Inline" : "External"
                        if let findings = script.findings, !findings.isEmpty {
                            let issues = findings.map { "[\($0.severity.rawValue.uppercased())] \($0.message)" }.joined(separator: ", ")
                            html += "<li><strong>\(origin):</strong> \(issues)</li>"
                        }
                    }
                    html += "</ul>"
                }
                
                let relevantBody: [SecurityWarning.SourceType] = [.body]
                let sectionWarningsBody = report.warnings.filter { relevantBody.contains($0.source) }
                if !sectionWarningsBody.isEmpty {
                    html += "<ul>"
                    for warning in sectionWarningsBody {
                        html += "<li class=\"\(warning.severity.rawValue.lowercased())\">[\(warning.severity.rawValue.uppercased())] \(warning.message)</li>"
                    }
                    html += "</ul>"
                }
            }
        }
    }
    
    
    
    html += """
    </div>
    </body>
    </html>
    """
    
    return html
    
    
    //Helper for lamai tree view
    func renderNode(_ node: DecodedNode, indent: Int = 0) -> String {
        let method = node.method ?? "raw"
        let value = node.value
        let indentString = String(repeating: "&nbsp;&nbsp;&nbsp;&nbsp;", count: indent)
        
        var output = "<li>\(indentString)<strong>[\(method)]</strong> \(value)"
        
        if !node.findings.isEmpty {
            output += " <span class=\"critical\">[\(node.findings.map { $0.shortLabel }.joined(separator: ", "))]</span>"
        }
        
        output += "</li>"
        
        for child in node.children {
            output += renderNode(child, indent: indent + 1)
        }
        
        return output
    }
    
    func generateHTMLCertificate(from cert: ParsedCertificate) -> String {
        let formatter: ISO8601DateFormatter = {
            let formatter = ISO8601DateFormatter()
            formatter.timeZone = TimeZone(secondsFromGMT: 0)
            formatter.formatOptions = [.withInternetDateTime] // outputs full `T` + `Z` format
            return formatter
        }()
        
        return """
        <head><title>Certificate Info</title></head>
        <h3>Certificate Details</h3>
        <table>
            <tr><th>Common Name</th><td>\(cert.commonName ?? "-")</td></tr>
            <tr><th>Organization</th><td>\(cert.organization ?? "-")</td></tr>
            <tr><th>Issuer Common Name</th><td>\(cert.issuerCommonName ?? "-")</td></tr>
            <tr><th>Issuer Organization</th><td>\(cert.issuerOrganization ?? "-")</td></tr>
            <tr><th>Valid From</th><td>\(cert.notBefore.map { formatter.string(from: $0) } ?? "-")</td></tr>
            <tr><th>Expires</th><td>\(cert.notAfter.map { formatter.string(from: $0) } ?? "-")</td></tr>
            <tr><th>Public Key Algorithm</th><td>\(cert.publicKeyAlgorithm ?? "-") \(cert.publicKeyBits.map(String.init) ?? "-") bits</td></tr>
            <tr><th>Key Usage</th><td>\(cert.keyUsage ?? "-")</td></tr>
            <tr><th>Extended Key Usage</th><td>\(cert.formattedEKU ?? "-")</td></tr>
            <tr><th>Certificate Policies</th><td>\(cert.certificatePolicyOIDs ?? "-")</td></tr>
            <tr><th>Self Signed</th><td>\(cert.isSelfSigned ? "Yes" : "No")</td></tr>
            <tr><th>Subject Alternative Names</th><td>\(cert.subjectAlternativeNames?.joined(separator: ", ") ?? "-")</td></tr>
        </table>
        """
    }
    
    // Bit late to the party
    func htmlEscape(_ input: String) -> String {
        input
            .replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }
}
