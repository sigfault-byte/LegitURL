//
//  AppCoordinatorView.swift
//  LegitURL
//
//  Created by Chief Hakka on 31/03/2025.
//
import SwiftUI

struct AppCoordinatorView: View {
    @ObservedObject var model: AppCoordinatorModel

    var body: some View {
        ZStack {
            switch model.screen {
            case .input(let incomingURL):
                URLInputView(
                    incomingURL: incomingURL,
                    onAnalyze: { urlInput, info in
                        withAnimation(.easeInOut) {
                            model.showAnalysis(from: urlInput, info: info)
                        }
                    }
                )
                .id(incomingURL?.absoluteString ?? "null")
            case .analysis(let input, let info):
                URLAnalysisView(
                    urlInput: input,
                    infoMessage: info,
                    onExit: {
                        withAnimation(.easeInOut) {
                            model.showInput(with: nil)
                        }
                    }
                )
            }
        }
    }
}

//struct AppCoordinatorView: View {
//    @State private var rootScreen: RootScreen = .input
//
//    // Define the ripple’s center (you can adjust this based on your design).
//    let rippleCenter = CGPoint(x: UIScreen.main.bounds.midX, y: UIScreen.main.bounds.midY)
//
//    var body: some View {
//        ZStack {
//            if case .input = rootScreen {
//                URLInputView(onAnalyze: { urlInput, info in
//                    withAnimation(.easeInOut) {
//                        rootScreen = .analysis(urlInput: urlInput, infoMessage: info)
//                    }
//                })
//                .transition(AnyTransition.ripple(center: rippleCenter))
//            }
//            if case .analysis(let urlInput, let infoMessage) = rootScreen {
//                URLAnalysisView(
//                    urlInput: urlInput,
//                    infoMessage: infoMessage,
//                    onExit: {
//                        withAnimation(.easeInOut) {
//                            rootScreen = .input
//                        }
//                    }
//                )
//                .transition(AnyTransition.ripple(center: rippleCenter))
//            }
//        }
//    }
//}
//
//extension AnyTransition {
//    // trying to find the center point!
//    static func ripple(center: CGPoint) -> AnyTransition {
//        .modifier(
//            active: RippleTransitionModifier(progress: 0, center: center),
//            identity: RippleTransitionModifier(progress: 1, center: center)
//        )
//    }
//}
//
//struct RippleTransitionModifier: AnimatableModifier {
//    var progress: CGFloat
//    var center: CGPoint
//
//    var animatableData: CGFloat {
//        get { progress }
//        set { progress = newValue }
//    }
//
//    func body(content: Content) -> some View {
//        content
//            .clipShape(CircularClipShape(progress: progress, center: center))
//    }
//}
//
//struct CircularClipShape: Shape {
//    var progress: CGFloat
//    var center: CGPoint
//
//    var animatableData: CGFloat {
//        get { progress }
//        set { progress = newValue }
//    }
//
//    func path(in rect: CGRect) -> Path {
////        radius to cover all view
//        let maxRadius = sqrt(pow(rect.width, 2) + pow(rect.height, 2))
//        let currentRadius = maxRadius * progress
//        let circleRect = CGRect(
//            x: center.x - currentRadius,
//            y: center.y - currentRadius,
//            width: 2 * currentRadius,
//            height: 2 * currentRadius
//        )
//
//        var path = Path()
//        path.addEllipse(in: circleRect)
//        return path
//    }
//}
