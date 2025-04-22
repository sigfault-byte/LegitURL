//
//  UserHeuristicCache.swift
//  URLChecker
//
//  Created by Chief Hakka on 21/04/2025.
//
import Foundation

struct UserHeuristicsCache {
    static private(set) var brands: Set<String> = []
    static private(set) var scamwords: Set<String> = []
    static private(set) var trustedDomains: Set<String> = []

    static func load() {
        let watchlist = UserWatchlistManager.load()
        let userBrandSet = Set(watchlist.map(\.normalizedBrand))
        let userDomainSet = Set(watchlist.compactMap { $0.realWebsite?.host?.lowercased() })

        let scamlist = UserScamwordManager.load()
        let userScamSet = Set(scamlist.map(\.normalized))

        brands = CoreBrands.names.union(userBrandSet)
        trustedDomains = WhiteList.trustedDomains.union(userDomainSet)
        scamwords = SuspiciousKeywords.scamTerms.union(userScamSet)
    }
    
    static func flush() {
        brands = []
        scamwords = []
        trustedDomains = []
    }
}
