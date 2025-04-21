//
//  QRScannerViewModel.swift
//  URLChecker
//
//  Created by Chief Hakka on 21/04/2025.
//
//SwiftUI View
//  ⇣
//QRScannerView (UIViewControllerRepresentable)
//  ⇣
//ScannerViewController (AVFoundation QR logic)
//  ⇣
//metadataOutput(...) detects QR → stops session
//  ⇣
//Delegate sends code → Coordinator calls closure
//  ⇣
//SwiftUI receives result

import UIKit
import AVFoundation

protocol ScannerViewControllerDelegate: AnyObject {
    func didScan(code: String)
}

class ScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    weak var delegate: ScannerViewControllerDelegate?

    private let session = AVCaptureSession()
    private var previewLayer: AVCaptureVideoPreviewLayer!
    

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black

        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device) else {
            return
        }

        let output = AVCaptureMetadataOutput()

        if session.canAddInput(input) && session.canAddOutput(output) {
            session.addInput(input)
            session.addOutput(output)

            //restricting detection to qrCode
            output.setMetadataObjectsDelegate(self, queue: DispatchQueue.main)
            output.metadataObjectTypes = [.qr]
        }

        previewLayer = AVCaptureVideoPreviewLayer(session: session)
        previewLayer.videoGravity = .resizeAspectFill
        previewLayer.frame = view.layer.bounds
        view.layer.addSublayer(previewLayer)

        DispatchQueue.global(qos: .userInitiated).async {
            self.session.startRunning()
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if session.isRunning {
//            print("viewWillDisappear triggered — stopping camera session")
            session.stopRunning()
        }
    }

    deinit {
        if session.isRunning {
//            print("deinit triggered — stopping leftover camera session")
            session.stopRunning()
        } /*else {*/
//            print("ScannerViewController deinitialized — session already stopped.")
//        }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        guard let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              let stringValue = obj.stringValue else { return }

        session.stopRunning()
        delegate?.didScan(code: stringValue)
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }
}

class QRScannerCoordinator: NSObject, ScannerViewControllerDelegate {
    var onScanned: (String) -> Void

    init(onScanned: @escaping (String) -> Void) {
        self.onScanned = onScanned
    }

    func didScan(code: String) {
        DispatchQueue.main.async {
            self.onScanned(code)
        }
    }
}
