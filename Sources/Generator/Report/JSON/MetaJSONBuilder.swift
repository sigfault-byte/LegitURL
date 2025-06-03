//
//  MetaJSONBuilder.swift
//  LegitURL
//
//  Created by Chief Hakka on 03/06/2025.
//
struct MetaJSONBuilder {
    // MARK: - HostEntry and PageEntry for deduplicated host/page blocks

    struct HostEntry: Encodable, Hashable {
        let domain: String
        let tld: String
        let host: String
        let subdomain: String?
        let punycode: Bool
        let idnaDecoded: String

        func hash(into hasher: inout Hasher) {
            hasher.combine(host)
        }

        static func == (lhs: HostEntry, rhs: HostEntry) -> Bool {
            return lhs.host == rhs.host
        }
    }

    struct PageEntry: Encodable {
        let id: String
        let host_id: String
        let url: String
        let path: String?
        let queryPresent: Bool
        let fragmentPresent: Bool
        let signal: [[String: String]]?
    }

    /// Returns a tuple of (hosts: [String: HostEntry], pages: [PageEntry], headers: [String])
    static func makeHostAndPageBlocks(from redirectChain: URLQueue) -> (url: [String: String], hosts: [String: HostEntry], pages: [PageEntry], headers: [String]) {
        var hostMap: [HostEntry: String] = [:]
        var hostsJSON: [String: HostEntry] = [:]
        var pages: [PageEntry] = []
        var hostIndex = 1
        var pageIndex = 1

        var urlMap: [String: String] = [:]
        var urlIndex = 1

        
        for entry in redirectChain.offlineQueue {
            
            let url = entry.components.fullURL ?? ""
            if urlMap[url] == nil {
                urlMap[url] = "u\(urlIndex)"
                urlIndex += 1
            }
            
            let c = entry.components

            guard let host = c.host,
                  let domain = c.extractedDomain,
                  let tld = c.extractedTLD,
                  let idna = c.punycodeHostDecoded else {
                continue
            }

            let hostEntry = HostEntry(
                domain: domain,
                tld: tld,
                host: host,
                subdomain: c.subdomain,
                punycode: c.punycodeHostEncoded?.contains("xn--") ?? false,
                idnaDecoded: idna
            )

            let hostID: String
            if let existing = hostMap[hostEntry] {
                hostID = existing
            } else {
                hostID = "h\(hostIndex)"
                hostMap[hostEntry] = hostID
                hostsJSON[hostID] = hostEntry
                hostIndex += 1
            }

            let signal = SecurityWarningTriage.getRelevantSecurityWarnings(for: entry, with: [.host, .path, .query, .fragment])

            let page = PageEntry(
                id: "u\(pageIndex)",
                host_id: hostID,
                url: "u\(urlIndex)",
                path: c.path,
                queryPresent: !(c.query?.isEmpty ?? true),
                fragmentPresent: !(c.fragment?.isEmpty ?? true),
                signal: signal
            )

            pages.append(page)
            pageIndex += 1
        }

        return (url: urlMap, hosts: hostsJSON, pages: pages, headers: ["placeholder-header"])
    }
}

struct MetaEntry: Encodable {
    let url: String
    let domain: String?
    let tld: String?
    let host: String?
    let subdomain: String?
    let punycode: Bool?
    let idnaDecoded: String?
    let path: String?
    let queryPresent: Bool?
    let fragmentPresent: Bool?
    let signal: [[String: String]]?

    enum CodingKeys: String, CodingKey {
        case url = "00_url"
        case domain = "01_domain"
        case tld = "02_tld"
        case host = "03_host"
        case subdomain = "04_subdomain"
        case punycode = "05_punycode"
        case idnaDecoded = "06_idna_decoded"
        case path = "07_path"
        case queryPresent = "08_query_present"
        case fragmentPresent = "09_fragment_present"
        case signal = "10_signal"
    }
}
