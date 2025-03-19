//
//  WhiteList.swift
//  LegitURL
//
//  Created by Chief Hakka on 07/03/2025.
//
struct WhiteList {
    static let trustedDomains: Set<String> = [
        // 🔹 Tech Giants
        "apple.com", "microsoft.com", "google.com", "amazon.com", "openai.com",
        "facebook.com", "meta.com", "instagram.com", "whatsapp.com", "twitter.com",
        "x.com", "linkedin.com", "youtube.com", "tiktok.com", "snapchat.com",
        
        // 🔹 Cloud Services & Hosting
        "aws.amazon.com", "azure.microsoft.com", "cloud.google.com",
        "dropbox.com", "box.com", "mega.nz", "icloud.com",
        
        // 🔹 Financial & Banking
        "paypal.com", "stripe.com", "squareup.com", "venmo.com",
        "bankofamerica.com", "chase.com", "wellsfargo.com", "citibank.com",
        "revolut.com", "wise.com", "americanexpress.com", "capitalone.com",
        
        // 🔹 Government & Official
        "gov.uk", "usa.gov", "europa.eu", "canada.ca", "gouv.fr", "bund.de",
        "nasa.gov", "whitehouse.gov",
        
        // 🔹 Security & Certification Authorities
        "letsencrypt.org", "digicert.com", "verisign.com", "cloudflare.com",
        "akamai.com", "sophos.com", "symantec.com", "mcafee.com", "kaspersky.com",
        
        // 🔹 Developers & Open Source
        "github.com", "gitlab.com", "bitbucket.org", "python.org", "golang.org",
        "nodejs.org", "npmjs.com", "docker.com", "kubernetes.io", "tensorflow.org",
        "mozilla.org", "gnu.org", "w3.org",
        
        // 🔹 Online Marketplaces & Retail
        "ebay.com", "walmart.com", "target.com", "bestbuy.com", "alibaba.com",
        "aliexpress.com", "rakuten.com",
        
        // 🔹 Email Providers
        "gmail.com", "outlook.com", "yahoo.com", "protonmail.com", "icloud.com",
        "zoho.com", "mail.com",
        
        // 🔹 Education & Research
        "harvard.edu", "mit.edu", "stanford.edu", "cam.ac.uk", "ox.ac.uk",
        "berkeley.edu", "columbia.edu", "princeton.edu", "yale.edu",
        
        // 🔹 News & Media
        "bbc.com", "cnn.com", "nytimes.com", "forbes.com", "reuters.com",
        "bloomberg.com", "wsj.com", "guardian.com", "lemonde.fr", "aljazeera.com",
        
        // 🔹 Healthcare & Pharma
        "who.int", "cdc.gov", "nih.gov", "pfizer.com", "moderna.com",
        "johnsonandjohnson.com", "roche.com", "astrazeneca.com",
        
        // 🔹 Gaming & Entertainment
        "steamcommunity.com", "epicgames.com", "playstation.com", "xbox.com",
        "nintendo.com", "netflix.com", "spotify.com", "hulu.com", "disneyplus.com",
        "steampowered.com"
    ]
    
    static let commonAcronyms: Set<String> = [
        "vpn", "ibm", "ai", "5g", "iot", "dns", "ssl", "tls", "sql", "xml", "ip", "mac", "usb",
        "nfc", "gpu", "cpu", "ram", "hd", "ssd", "cdn", "api", "dev", "ops", "log"
    ]
    
    static let safePaths: Set<String> = [
        "about", "account", "admin", "assets", "api", "archive", "auth", "blog",
        "cart", "cdn", "checkout", "contact", "css", "dashboard", "docs", "download",
        "faq", "feed", "forum", "help", "home", "images", "index", "js", "legal",
        "login", "logout", "media", "news", "notifications", "orders", "password",
        "payment", "pdf", "privacy", "profile", "public", "redirect", "register",
        "reports", "robots.txt", "rss", "search", "secure", "settings", "signup",
        "static", "store", "styles", "support", "terms", "tos", "uploads", "user",
        "verify", "videos", "wp-admin", "wp-content", "wp-includes"
    ]
    
    static let commonSafeKeys: Set<String> = [
        // 🌐 General Parameters
        "id", "lang", "locale", "ver", "type", "mode",

        // 🔐 Authentication (Only session-related, avoid credentials)
        "state", "token", "sessionid", "sid",

        // 📈 Analytics (Non-suspicious tracking)
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",

        // 🛒 E-Commerce & Checkout
        "order", "cart", "product", "sku", "price", "currency",

        // 🔄 Pagination & Sorting
        "page", "offset", "limit", "sort", "orderBy", "dir", "filter",

        // 📌 UI Preferences & Configuration
        "theme", "darkmode", "view", "layout", "expand", "collapse",

        // 📡 API Calls & Responses
        "format", "callback", "query", "fields", "include", "exclude",

        // ⏳ Time-based (Neutral metadata)
        "timestamp", "ts", "expires", "start", "end", "date",

        // 📂 File Handling & Media (Non-sensitive)
        "file", "download", "media", "preview", "attachment"
    ]
}
