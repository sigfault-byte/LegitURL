//
//  HeadersKeyWords.swift
//  URLChecker
//
//  Created by Chief Hakka on 20/03/2025.
//
struct HeadersKeyWords {
    static let serverHeaderKeys: Set<String> = [
        "server",
        "x-powered-by",
        "x-aspnet-version",
        "x-aspnetmvc-version",
        "x-generator",
        "x-drupal-cache",
        "x-backend-server"
    ]

    // Standard web servers (safe but should be hidden)
    static let commonWebServers: Set<String> = [
        "nginx",
        "apache"
    ]

    // Frameworks & PaaS (should NEVER be exposed)
    static let frameworksAndPaaS: Set<String> = [
        "express", "django", "rails", "tomcat",
        "vercel", "firebase", "netlify", "cloudflare",
        "heroku", "render", "fly.io"
    ]
}
