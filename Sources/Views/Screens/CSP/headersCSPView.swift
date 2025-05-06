//
//  headersCSP.swift
//  LegitURL
//
//  Created by Chief Hakka on 25/04/2025.
//
import SwiftUI

struct CSPInspectorView: View {
    let csp: ClassifiedCSPResult
    @State private var expandedDirectives: Set<String> = []

    var body: some View {
        List {
            ForEach(csp.structuredCSP.sorted(by: { $0.key < $1.key }), id: \.key) { directive, values in
                Section(header: Text(directive).font(.headline)) {
                    let sourceInfo = csp.directiveSourceTraits[directive]
                    let bitFlag = csp.directiveBitFlags[directive] ?? 0
                    let flagView = CSPBitFlag(rawValue: bitFlag).descriptiveReasons()

                    if let info = sourceInfo {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("• URLs allowed: \(info.urlCount)")
                            if info.hasHTTP {
                                Text("Contains http: source").foregroundColor(.red)
                            }
                            if info.hasWildcard {
                                Text("Wildcard (*) domain present").foregroundColor(.orange)
                            }
                            if info.onlySelf {
                                Text("Only 'self' is specified").foregroundColor(.green)
                            }
                        }
                    }

                    if !flagView.isEmpty {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Detected Flags:")
                                .font(.subheadline).bold()
                            ForEach(flagView, id: \.self) { reason in
                                Text("• \(reason)")
                                    .font(.system(size: 13))
                            }
                        }.padding(.vertical, 4)
                    }

                    let analysis = CSPDirectiveAnalysis(directive: directive, flags: CSPBitFlag(rawValue: bitFlag))

                    if !analysis.warnings.isEmpty {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Configuration Issues:")
                                .font(.subheadline).bold()
                            ForEach(analysis.warnings, id: \.self) { msg in
                                Text("• \(msg)")
                                    .font(.system(size: 13))
                                    .foregroundColor(.red)
                            }

//                            if analysis.impactsScore {
//                                Text("→ This directive affects security scoring")
//                                    .font(.footnote)
//                                    .foregroundColor(.red)
//                                    .padding(.top, 2)
//                            }
                        }.padding(.vertical, 4)
                    }

                    let keys = values.keys.sorted { lhs, rhs in
                        String(data: lhs, encoding: .utf8) ?? "" < String(data: rhs, encoding: .utf8) ?? ""
                    }

                    let isExpanded = expandedDirectives.contains(directive)
                    let displayKeys = isExpanded ? keys : Array(keys.prefix(3))

                    VStack(alignment: .leading, spacing: 2) {
                        Text("Values:")
                            .font(.subheadline).bold()
                        ForEach(displayKeys, id: \.self) { value in
                            let stringVal = String(data: value, encoding: .utf8) ?? "Decoding Error"
                            let type = values[value] ?? .unknown
                            Text("• \(stringVal) [\(type.description)]")
                                .font(.system(size: 13))
                        }

                        if keys.count > 3 {
                            Button(action: {
                                if isExpanded {
                                    expandedDirectives.remove(directive)
                                } else {
                                    expandedDirectives.insert(directive)
                                }
                            }) {
                                Text(isExpanded ? "Show Less" : "Show All (\(keys.count))")
                                    .font(.footnote)
                                    .foregroundColor(.blue)
                                    .padding(.vertical, 4)
                            }
                        }
                    }
                }
            }
        }
        .navigationTitle(csp.source == "CSP" ? "CSP Directives" : "CSP Report-Only Directives")
    }
}
