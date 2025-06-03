////
////  GenerateJSON.swift
////  LegitURL
////
////  Created by Chief Hakka on 27/05/2025.
////
////  Created to generate a compact, high-signal structured JSON object from URLQueue analysis results
//
//import Foundation
//
//struct JsonReportBuilder {
//    public static func generateLLMJson(from queue: URLQueue, brief: Bool = false) throws -> [Data] {
//        
//        //Early guard for undefined weird quirk
//        guard let first = queue.offlineQueue.first,
//              let last = queue.offlineQueue.last else {
//            throw NSError(domain: "Invalid queue", code: -1)
//        }
//        
//        //MARK: Important Const
//        //TimeStamp
//        let formatter = JSONReportHelper.makeISOFormatter()
//        //User Locale
//        var userLocale = JSONReportHelper.getPreferredLanguageCode()
//        
//        //Main jason object
//        var finalOutput: [[String: Any]] = []
//        
//        //priming the model depending on the type of report
//        let (prime, instruction) = LLMPriming.loadPrimmingInstructions(brief: brief, locale: userLocale)
//        finalOutput.append(prime)
//        finalOutput.append(instruction)
//        
//        //Create the MetaBlock
//        var test = MetaJSONBuilder.makeHostAndPageBlocks(from: queue)
//        
//        ///DEBUG PARTY TIME
//        #if DEBUG
//        do {
//            let encoder = JSONEncoder()
//            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
//
//            let (urlMap, hostsDict, pagesArray, headersArray) = test
//
//            let urlArray = urlMap
//                .sorted { $0.value < $1.value }
//                .map { ["id": $0.value, "url": $0.key] }
//
//            let hostsData = try encoder.encode(hostsDict)
//            let pagesData = try encoder.encode(pagesArray)
//
//            let hostsJSON = try JSONSerialization.jsonObject(with: hostsData) as? [String: Any] ?? [:]
//            let pagesJSON = try JSONSerialization.jsonObject(with: pagesData) as? [[String: Any]] ?? []
//
//            let final: [String: Any] = [
//                "01_urls": urlArray,
//                "02_hosts": hostsJSON,
//                "03_pages": pagesJSON
//            ]
//
//            let cleanedFinalData = try JSONReportHelper.serializeAndClean(final)
//            print("🚀 Clean Host+Page JSON:")
//            print(String(data: cleanedFinalData, encoding: .utf8) ?? "encoding failed")
//            
//            print("🧪 Headers placeholder:", headersArray)
//        } catch {
//            print("Serialization failed: \(error)")
//        }
//        #endif
//        
//        return []
//    }
//    
//    
//    
//    
//
//    
//}
