//
//  JSONReportHelper.swift
//  LegitURL
//
//  Created by Chief Hakka on 03/06/2025.
//
import Foundation

struct JSONReportHelper {
    
    //Date formatter
    public static func makeISOFormatter(date: Date? = nil) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.formatOptions = [.withInternetDateTime]
        
        if let date = date {
            return formatter.string(from: date)
        } else {
            return String(Int(Date().timeIntervalSince1970))
        }
    }
    
    public static func getPreferredLanguageCode() -> String {
        
        var userLocale = Locale.preferredLanguages.first ?? "en"
        if let dashIndex = userLocale.firstIndex(of: "-") {
            userLocale = String(userLocale.prefix(upTo: dashIndex))
        }
        if userLocale.isEmpty {
            userLocale = "en"
        }
        
        return userLocale
    }
    
    //MARK: THE END FUNCTION IS HERE
    func serializeAndClean(_ json: [[String: Any]]) throws -> Data {
        let jsonData = try JSONSerialization.data(
            withJSONObject: json.map { NSDictionary(dictionary: $0) },
            options: [.withoutEscapingSlashes, .sortedKeys, /*.prettyPrinted*/]
        )

        guard var jsonString = String(data: jsonData, encoding: .utf8) else {
            throw NSError(domain: "SerializationError", code: -1, userInfo: nil)
        }

        let prefixesToRemove = ["\"00_", "\"01_", "\"02_", "\"03_", "\"04_", "\"05_",
                                "\"06_", "\"07_", "\"08_", "\"09_", "\"10_", "\"11_",
                                "\"12_", "\"13_", "\"14_", "\"15_", "\"16_", "\"17_",
                                "\"18_", "\"19_", "\"20_", "\"21_", "\"22_", "\"23_",
                                "\"24_", "\"25_", "\"26_", "\"27_"]
        
        for prefix in prefixesToRemove {
            jsonString = jsonString.replacingOccurrences(of: prefix, with: "\"")
        }

        guard let cleanedData = jsonString.data(using: .utf8) else {
            throw NSError(domain: "SerializationError", code: -1, userInfo: nil)
        }

        return cleanedData
    }
    
    
}
