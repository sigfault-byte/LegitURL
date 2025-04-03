//
//  DestinatuionInfoViewModel.swift
//  URLChecker
//
//  Created by Chief Hakka on 02/04/2025.
//
import SwiftUI
class DestinationInfoViewModel: ObservableObject {
    
    @Published var inputDomain: String
    @Published var finalHost: String
    @Published var finalHostPunycode: String
    @Published var hopCount: Int = 0
    var punycodeWarning: Bool {
        finalHost != finalHostPunycode
    }
    @Published var domainLabel: String
    @Published var tldLabel: String
    
    init(inputDomain: String, finalHost: String, finalHostPunycode: String, hopCount: Int, domainLabel: String, tldLabel: String) {
        self.inputDomain = inputDomain
        self.finalHost = finalHost
        self.finalHostPunycode = finalHostPunycode
        self.hopCount = hopCount
        self.domainLabel = domainLabel
        self.tldLabel = tldLabel
    }
}
