import SwiftUI

struct ScoreSummaryViewOLD: View {
    @ObservedObject var urlQueue = URLQueue.shared
    
    @State private var animatedScore: Int = 100
    @State private var scoreAnimationStarted = false
    @State private var scoreIsStable = false
    @State private var showAnalysisError: Bool = false
    
    @State private var flickerText: String = "00"
    @State private var flickerColor: Color = .gray
    
    var scoreColor: Color {
        if animatedScore > 80 {
            return .green
        } else if animatedScore > 50 {
            return .orange
        } else {
            return .red
        }
    }
    
    var body: some View {
        VStack(alignment: .center, spacing: 20) {
            VStack(spacing: 16) {
                HStack(alignment: .center) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text("Legitimacy Score")
                            .font(.title2)
                        if scoreIsStable && !isFetchFailure(){
                            Text(
                                urlQueue.LegitScore > 80 ? "This looks safe." :
                                    urlQueue.LegitScore > 50 ? "This might be suspicious." :
                                    "⚠️ This looks dangerous."
                            )
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                            .transition(.scale(scale: 0.85, anchor: .center).combined(with: .opacity))
                            .animation(.easeInOut(duration: 0.5), value: scoreIsStable)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    
                    Text(scoreAnimationStarted ? (isFetchFailure() ? "x00" : "\(animatedScore)") : flickerText)
                        .font(.system(size: 80, weight: .black, design: .monospaced))
                        .foregroundColor(
                            scoreAnimationStarted
                                ? (isFetchFailure() ? .gray : scoreColor)
                                : flickerColor
                        )
                        .shadow(color:
                            (scoreAnimationStarted
                                ? (isFetchFailure() ? .gray : scoreColor)
                                : flickerColor
                            ).opacity(0.4),
                            radius: 10, x: 0, y: 0
                        )
                        .frame(minWidth: 80, minHeight: 80)
                }
                .frame(maxWidth: .infinity)
                if showAnalysisError {
                    VStack(spacing: 4) {
                        Text(isFetchFailure() ? "The website could not be reached." : "Online analysis could not be completed.")
                            .bold()
                            .foregroundColor(.red)
                            .font(.subheadline)
                        Text("A critical error occurred (e.g. fetch failure or blocked content).")
                            .font(.footnote)
                            .multilineTextAlignment(.center)
                    }
                }
                Divider()
                
                if urlQueue.isAnalysisComplete {
                    displayFinalMessage()
                }
            }
            .cornerRadius(12)
        }
        .onAppear {
            Timer.scheduledTimer(withTimeInterval: 0.15, repeats: true) { timer in
                if !scoreAnimationStarted {
                    let hex = String(format: "%02X", Int.random(in: 0...255))
                    flickerText = hex

                    let colors: [Color] = [.gray, .cyan, .orange, .purple, .yellow, .blue]
                    flickerColor = colors.randomElement() ?? .gray
                } else {
                    timer.invalidate()
                }
            }
        }
        .animation(.easeInOut(duration: 0.45), value: urlQueue.isAnalysisComplete)
        .onChange(of: urlQueue.LegitScore) { newValue, _ in
            guard urlQueue.isAnalysisComplete else { return }
            print(urlQueue.isAnalysisComplete)
            triggerScoreAnimation()
        }
        .onChange(of: urlQueue.isAnalysisComplete) {_, _ in
            guard urlQueue.isAnalysisComplete else { return }
            triggerScoreAnimation()
        }
        .task {
            if urlQueue.isAnalysisComplete && !scoreAnimationStarted {
                triggerScoreAnimation()
            }
        }
        .task {
            while !scoreAnimationStarted {
                try? await Task.sleep(nanoseconds: 300_000_000)
                if urlQueue.offlineQueue.last?.warnings.contains(where: { $0.severity == .fetchError || $0.severity == .critical }) == true {
                    showAnalysisError = true
                    
                    break
                }
            }
        }
    }
    
    private func isFetchFailure() -> Bool {
        guard let last = urlQueue.offlineQueue.last else { return false }
        return last.warnings.contains(where: { $0.severity == .fetchError })
    }
    
    private func displayFinalMessage() -> some View {
        if let finalHost = urlQueue.offlineQueue.last?.components.host {
            return AnyView(
                VStack(spacing: 8) {
                    HStack {
                        Text("Final domain:")
                            .font(.subheadline)
                        Spacer()
                        Text(finalHost)
                            .font(.subheadline)
                            .bold()
                    }

                    HStack {
                        Text("In:")
                            .font(.subheadline)
                        Spacer()
                        Text("\(urlQueue.offlineQueue.count - 1) hops")
                            .font(.subheadline)
                            .bold()
                    }

                    Text("Be attentive — your link is taking you to \(finalHost)")
                        .font(.footnote)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.top, 4)
                }
                .frame(maxWidth: .infinity)
                .transition(.scale(scale: 0.85, anchor: .center).combined(with: .opacity))
                .animation(.easeInOut(duration: 0.5), value: scoreIsStable)
            )
        } else {
            return AnyView(EmptyView())
        }
    }
    
    func triggerScoreAnimation() {
        scoreAnimationStarted = true
        Timer.scheduledTimer(withTimeInterval: 0.02, repeats: true) { timer in
            if animatedScore > urlQueue.LegitScore {
                animatedScore -= 1
            } else if animatedScore < urlQueue.LegitScore {
                animatedScore += 1
            } else {
                scoreIsStable = true
                timer.invalidate()
            }
        }
    }
}
