//
//  CSPKeys.swift
//  URLChecker
//
//  Created by Chief Hakka on 07/04/2025.
//
// MARK: - Core Content Directives
let contentDirectives: Set<String> = [
    "default-src",
    "script-src",
    "style-src",
    "img-src",
    "connect-src",
    "font-src",
    "object-src",
    "media-src",
    "frame-src",
    "worker-src",
    "manifest-src",
    "prefetch-src",
    "child-src" // Deprecated, but still seen
]

// MARK: - Navigation & Behavior Directives
let behaviorDirectives: Set<String> = [
    "form-action",
    "navigate-to",
    "base-uri",
    "sandbox",
    "frame-ancestors"
]

// MARK: - Reporting & XSS Protections
let reportingDirectives: Set<String> = [
    "report-uri",         // Legacy
    "report-to",          // Modern version
    "require-trusted-types-for" // Advanced DOM protection
]

// MARK: - Master Set (Optional: Union of All)
let allDirectives: Set<String> =
    contentDirectives
    .union(behaviorDirectives)
    .union(reportingDirectives)
