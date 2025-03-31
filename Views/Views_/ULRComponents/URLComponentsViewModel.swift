//
//  URLComponentsViewModel.swift
//  URLChecker
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

class URLComponentsViewModel: ObservableObject {
    @Published var urlInfo: [URLInfo] = [] {
        didSet {
            updateURL()
        }
    }
    
    @Published var onlineInfo: [OnlineURLInfo] = []
    @Published var isAnalysisComplete: Bool = false
    
    //Var for UI
    @Published var isExpanded: Bool = false
    @Published var isPathExpanded: Bool = false
    @Published var isQueryExpanded: Bool = false
    @Published var isFragmentExpanded: Bool = false
    @Published var urlEntered: String = "Loading..."
    
    init(urlInfo: [URLInfo] = [], onlineInfo: [OnlineURLInfo] = [], isAnalysisComplete: Bool = false) {
        self.urlInfo = urlInfo
        self.onlineInfo = onlineInfo
        self.isAnalysisComplete = isAnalysisComplete
    }
    
    private func updateURL() -> Void {
        print("happended")
        self.urlEntered = self.urlInfo.first?.components.fullURL ?? ""
        print(self.urlEntered)
    }
}

