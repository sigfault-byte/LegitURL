//
//  Regex.swift
//  LegitURL
//
//  Created by Chief Hakka on 11/03/2025.
// not used anymore
// read carefully the RFC, maybe the old one about URL. And apply the logic? ...

import Foundation

struct Regex {
//    /// Query regex RFC compliant .... NEW rfc
//    static let strictQueryRegex = #"^((?:[A-Za-z0-9\-._~!$&'()*+,;:@]|%[0-9A-Fa-f]{2})+)=((?:[A-Za-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})+)(?:&((?:[A-Za-z0-9\-._~!$&'()*+,;:@]|%[0-9A-Fa-f]{2})+)=((?:[A-Za-z0-9\-._~!$&'()*+,;=:@/?]|%[0-9A-Fa-f]{2})+))*$"#
//    RFC 1738
    static let strictQueryRegex = #"^((?:[A-Za-z0-9\$\-_\.\+]|%[0-9A-Fa-f]{2})+)=((?:[A-Za-z0-9\$\-_\.\+]|%[0-9A-Fa-f]{2})+)(?:&((?:[A-Za-z0-9\$\-_\.\+]|%[0-9A-Fa-f]{2})+)=((?:[A-Za-z0-9\$\-_\.\+]|%[0-9A-Fa-f]{2})+))*$"#
    
    /// Wide regex: also allows raw '=' and '://' in values.
    static let wideQueryRegex = #"^((?:[A-Za-z0-9\-._~]|%[0-9A-Fa-f]{2})+=(?:[A-Za-z0-9\-._~=%]|%[0-9A-Fa-f]{2}|:\/\/)+)(?:&(?:[A-Za-z0-9\-._~]|%[0-9A-Fa-f]{2})+=(?:[A-Za-z0-9\-._~=%]|%[0-9A-Fa-f]{2}|:\/\/)+)*$"#
    
    /// Strict regex: only RFC 3986 allowed characters. for fragment
    static let normalFragmentRegex = #"^(?:[A-Za-z0-9\-._~]|%[0-9A-Fa-f]{2})*$"#
}
