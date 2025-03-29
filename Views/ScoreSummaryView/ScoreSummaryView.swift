import SwiftUI

struct ScoreSummaryView: View {
    @ObservedObject var urlQueue: URLQueue
    @Binding var analysisStarted: Bool // ✅ Tracks when analysis starts
    
    var body: some View {
        VStack(spacing: 20) { // ✅ Adjust spacing to control white space
            VStack {
                Text("Legitimacy Score")
                    .font(.title2)
                    .foregroundColor(.primary)
                
                Text("\(urlQueue.LegitScore)")
                    .font(.system(size: 48, weight: .bold))
                    .foregroundColor(urlQueue.LegitScore > 50 ? .green : .red)
                
                ProgressView(value: CGFloat(urlQueue.LegitScore) / 100.0)
                    .progressViewStyle(LinearProgressViewStyle())
                    .scaleEffect(x: 1, y: 2)
                    .accentColor(urlQueue.LegitScore > 50 ? .green : .red)
                    .padding(.horizontal)
            }
            .padding(.top, 40)
            
            if analysisStarted {
                VStack {
                    if let finalHost = urlQueue.offlineQueue.last?.components.host {
                        VStack {
                            Text("Final domain:")
                                .font(.headline)
                                .foregroundColor(.blue)
                            Text("\(finalHost)\n\(urlQueue.offlineQueue.count > 1 ? "  (\(urlQueue.offlineQueue.count - 1) hops)" : "")")
                                .font(.system(size: 25, weight: .bold))
                                .foregroundColor(.primary)
                                .padding(.top, 4)
                                .multilineTextAlignment(.center)
                        }
                        .transition(.move(edge: .top))
                    }
                    if URLQueue.shared.isAnalysisComplete {
                        if let warningSummary = generateWarningSummary(from: urlQueue) {
                            Text(warningSummary)
                                .font(.subheadline)
                                .foregroundColor(.orange)
                                .multilineTextAlignment(.center)
                                .padding(.horizontal)
                                .transition(.opacity)
                        }
                    }
                }
            }
            
            Spacer() // ✅ Pushes everything up when analysis results appear
        }
//        .frame(height: UIScreen.main.bounds.height * 0.5, alignment: .top) // ✅ Ensures it stays compact
        .animation(.easeInOut(duration: 0.5), value: analysisStarted)
    }
    // Function to generate a simple warning summary
    func generateWarningSummary(from queue: URLQueue) -> String? {
        let criticalWarnings = queue.allWarnings.filter {
            $0.severity == .dangerous || $0.severity == .suspicious || $0.severity == .critical && analysisStarted
        }
        
        if criticalWarnings.isEmpty {
            return "Everything looks Good!"
        }
        
        if criticalWarnings.contains(where: { $0.message.localizedCaseInsensitiveContains("homograph") }) {
            return "⚠️ This domain looks like a well-known site. Possible scam."
        }
        
//        if criticalWarnings.contains(where: { $0.message.localizedCaseInsensitiveContains("HTTP") }) {
//            return "⚠️ This site is missing HTTPS! It's insecure."
//        }
        
        // ✅ Fix: Use two separate `.contains(where:)` calls
        if criticalWarnings.contains(where: { $0.message.localizedCaseInsensitiveContains("phishing") }) ||
            criticalWarnings.contains(where: { $0.message.localizedCaseInsensitiveContains("scam") }) {
            return "⚠️ This website might be trying to trick you. Some warnings suggest it could be a phishing site."
        }
        
        return "⚠️ This website has multiple security risks. Proceed with caution."
    }
}
