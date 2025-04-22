import SwiftUI

struct QRScannerView: UIViewControllerRepresentable {
    var onScanned: (String) -> Void

    func makeCoordinator() -> QRScannerCoordinator {
        QRScannerCoordinator(onScanned: onScanned)
    }

    func makeUIViewController(context: Context) -> ScannerViewController {
        let controller = ScannerViewController()
        controller.delegate = context.coordinator
        return controller
    }

    func updateUIViewController(_ uiViewController: ScannerViewController, context: Context) {}
}
