//
//  CookeViewModel.swift
//  URLChecker
//
//  Created by Chief Hakka on 08/04/2025.
//
import Foundation

struct CookieViewModel: Identifiable {
    let id: UUID
    let name: String
    let value: String
    let isCrossSite: Bool
    let humanReadableExpiry: String
    let severity: CookieSeverity
    let flags: CookieFlagBits
    let sameSite: String?
    let secure: Bool
    let httpOnly: Bool
    let entropy: Float?

    init(from result: CookieAnalysisResult) {
        self.id = result.id
        self.name = result.cookie.name
        self.value = result.cookie.value
        self.isCrossSite = result.cookie.sameSite == "None"
        self.humanReadableExpiry = CookieViewModel.humanizeExpiry(result.cookie.expire)
        self.severity = result.severity
        self.flags = result.flags
        self.sameSite = result.cookie.sameSite
        self.secure = result.cookie.secure
        self.httpOnly = result.cookie.httpOnly
        self.entropy = result.entropy
    }

    var displayedSameSitePolicy: String {
        sameSite ?? "Missing, default to Lax"
    }

    var displayedSecureStatus: String {
        if secure {
            return "Yes"
        } else {
            return "Missing"
        }
    }
    
    var displayHttpOnly: String {
        if httpOnly {
            return "Yes"
        } else {
            return "Missing"
        }
    }
    
    var readableFlags: [String] {
        flags.descriptiveReasons(entropyScore: entropy)
    }

    private static func humanizeExpiry(_ date: Date?) -> String {
        guard let expiry = date else { return "Session" }
        let interval = expiry.timeIntervalSinceNow
        if interval <= 0 { return "Expired" }

        let secondsInDay: Double = 86400
        let secondsInYear: Double = 31536000
        let secondsInHour: Double = 3600

        if interval >= secondsInYear {
            let years = Int(round(interval / secondsInYear))
            return "\(years) year\(years > 1 ? "s" : "")"
        } else if interval >= secondsInDay {
            let days = Int(round(interval / secondsInDay))
            return "\(days) day\(days > 1 ? "s" : "")"
        } else {
            let hours = Int(round(interval / secondsInHour))
            return "\(hours) hour\(hours > 1 ? "s" : "")"
        }
    }
}


