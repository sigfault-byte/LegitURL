//
//  ShareViewController.swift
//  LegitURLShare
//
//  Created by Chief Hakka on 22/05/2025.
//

//import UIKit
//import Social
//
//class ShareViewController: SLComposeServiceViewController {
//
//    override func isContentValid() -> Bool {
//        // Do validation of contentText and/or NSExtensionContext attachments here
//        return true
//    }
//
//    override func didSelectPost() {
//        // This is called after the user selects Post. Do the upload of contentText and/or NSExtensionContext attachments.
//
//        // Inform the host that we're done, so it un-blocks its UI. Note: Alternatively you could call super's -didSelectPost, which will similarly complete the extension context.
//        self.extensionContext!.completeRequest(returningItems: [], completionHandler: nil)
//    }
//
//    override func configurationItems() -> [Any]! {
//        // To add configuration options via table cells at the bottom of the sheet, return an array of SLComposeSheetConfigurationItem here.
//        return []
//    }
//
//}


//import UIKit
//import MobileCoreServices

//class ShareViewController: UIViewController {
//
//    override func viewDidLoad() {
//        super.viewDidLoad()
//        view.backgroundColor = .systemBackground
//
//        guard let extensionItem = extensionContext?.inputItems.first as? NSExtensionItem else {
//            print("No extension item")
//            return
//        }
//
//        if let itemProvider = extensionItem.attachments?.first(where: { $0.hasItemConformingToTypeIdentifier("public.url") }) {
//            itemProvider.loadItem(forTypeIdentifier: "public.url", options: nil) { (item, error) in
//                if let url = item as? URL {
//                    let shaeded = url.absoluteString.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
//                    if let customURL = URL(string: "legiturl://analyze?url=\(encoded)") {
//                        DispatchQueue.main.async {
//                            self.extensionContext?.open(customURL, completionHandler: { success in
//                                if !success {
//                                    print("Failed to open main app")
//                                }
//                                self.extensionContext?.completeRequest(returningItems: nil, completionHandler: nil)
//                            })
//                        }
//                    }
//                }
//                else {
//                    print("No URL found or failed to load item: \(String(describing: error))")
//                }
//            }
//        } else {
//            print("No item provider with public.url")
//        }
//    }
//}

import UIKit
import SwiftUI
import UniformTypeIdentifiers

// Constants for main app
let appGroupID   = "group.IJTWTML.LegitURL.shared"

let sharedURLKey = "SharedURL"
let legitScheme  = "legiturl://analyze?url="
 
final class ShareViewController: UIViewController {

    private var sharedURL: URL?

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground   // fallback

        // Extract the first public.url the user shared
        guard
            let itemProvider = extensionContext?
                .inputItems
                .compactMap({ $0 as? NSExtensionItem })
                .flatMap({ $0.attachments ?? [] })
                .first(where: { $0.hasItemConformingToTypeIdentifier(UTType.url.identifier) })
        else { finish(); return }

        itemProvider.loadItem(forTypeIdentifier: UTType.url.identifier,
                              options: nil) { [weak self] item, error in
            guard let self,
                  let url = (item as? URL) ?? (item as? NSURL) as URL? else {
                self?.finish(); return
            }
            self.sharedURL = url
            DispatchQueue.main.async { self.presentSheet(for: url) }
        }
    }

    // MARK: – UI ????

    private func presentSheet(for url: URL) {
        let hc = UIHostingController(
            rootView: ShareSheet(
                url: url,
                onOpenApp: { [weak self] in self?.openInLegitURL() },
                onCancel:  { [weak self] in self?.finish() }
            )
        )
        hc.modalPresentationStyle = .formSheet
        present(hc, animated: true)
    }

    // MARK: to main app

    private func openInLegitURL() {
        guard let url = sharedURL else { finish(); return }

        // Hand‑off: save and exit - extension is not allowed to open the app ..... <333
        stashForLater(url)
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert]) { granted, _ in
            guard granted else { return }
            let content = UNMutableNotificationContent()
            content.title = "Link saved to LegitURL"
            content.body  = "Open LegitURL to analyse the shared link."
            let request = UNNotificationRequest(identifier: UUID().uuidString,
                                                content: content,
                                                trigger: nil)
            UNUserNotificationCenter.current().add(request, withCompletionHandler: nil)
        }
        finish()
    }

    private func stashForLater(_ url: URL) {
        if let d = UserDefaults(suiteName: appGroupID) {
            d.set(url.absoluteString, forKey: sharedURLKey)
            d.synchronize()

//            let check = d.string(forKey: sharedURLKey)
//            print("shareExtension wrote:", check ?? "fuck")
//
//            let snapshot = d.dictionaryRepresentation()
//            print(" snapshot:", snapshot.keys.filter { $0.hasPrefix("Shared") || $0.contains("URL") })
//        } else {
//            print(" filed to access UserDefaults with App Group")
        }
    }

    private func finish() {
        extensionContext?.completeRequest(returningItems: nil, completionHandler: nil)
    }
}

/// Tiny SwiftUI helper view
private struct ShareSheet: View {
    let url: URL
    let onOpenApp: () -> Void
    let onCancel:  () -> Void

    var body: some View {
        VStack(spacing: 20) {
            Text("Analyse this link in LegitURL?")
                .font(.headline)
            Text(url.absoluteString)
                .font(.footnote)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            HStack {
                Button("Cancel", action: onCancel)
                Spacer()
                Button("Open in LegitURL", action: onOpenApp)
                    .bold()
            }
            .padding(.horizontal)
        }
        .padding()
        .frame(minWidth: 280)
    }
}
