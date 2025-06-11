//
//  LegitURLTests.swift
//  LegitURLTests
//
//  Created by Chief Hakka on 30/05/2025.
//

import XCTest
import MachO
import Darwin
@testable import LegitURL

func logResourceSnapshot(label: String = "📊 Resource Snapshot") {
    var info = task_vm_info_data_t()
    var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.stride) / 4

    let kerr = withUnsafeMutablePointer(to: &info) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
            task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
        }
    }

    if kerr == KERN_SUCCESS {
        let usedMB = Double(info.phys_footprint) / 1024 / 1024
        print("""
        \(label)
        RAM Used: \(String(format: "%.2f", usedMB)) MB
        """)
    } else {
        print("Error with task_info(): \(kerr)")
    }

    let cpuTime = ProcessInfo.processInfo.systemUptime
    print("⏱️ System Uptime: \(String(format: "%.2f", cpuTime)) sec")
}

func logPeakMemory(label: String = "📈 Peak Memory Snapshot") {
    var info = task_basic_info()
    var count = mach_msg_type_number_t(MemoryLayout.size(ofValue: info)) / 4

    let kerr = withUnsafeMutablePointer(to: &info) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
            task_info(mach_task_self_, task_flavor_t(TASK_BASIC_INFO), $0, &count)
        }
    }

    if kerr == KERN_SUCCESS {
        let peakMB = Double(info.resident_size) / 1024 / 1024
        print("\(label)\n📈 Peak RAM: \(String(format: "%.2f", peakMB)) MB")
    } else {
        print("Error (peak memory): \(kerr)")
    }
}

final class LegitURLTests: XCTestCase {

    func testAnalysisEngine_PerformanceForSimpleURL() async {
        let testURL1 = "https://stripe.com/ae"
        let testURL2 = "https://store.steampowered.com/"
        let testURL3 = "https://www.societegenerale.com/fr"
        let testURL4 = "https://x.com"
        
        AnalysisEngine.hasManuallyStopped = false
        AnalysisEngine.hasFinalized = false

//        print(" BEFORE analysis")
//        logResourceSnapshot(label: "RAM Snapshot (Before)")
//        logPeakMemory(label: "Peak RAM (Before)")

        let start = Date()
        await AnalysisEngine.analyze(urlString: testURL4)
        let duration = Date().timeIntervalSince(start) * 1000 // ms
        
        let findingsCount = URLQueue.shared.offlineQueue.flatMap { $0.warnings }.count
        
        print("📝Total number of findings: \(findingsCount)")
        print("⌛️ Analysis duration ( end of XCTestCase ): \(String(format: "%.2f", duration)) ms")

        
        
//        print("📌 AFTER analysis")
//        logResourceSnapshot(label: "📊 RAM Snapshot (After)")
//        logPeakMemory(label: "📈 Peak RAM (After)")

        XCTAssertLessThan(duration, 4000, " Max is 4000 ms")
    }
}
