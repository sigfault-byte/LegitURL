//
//  URLQueue.swift
//  LegitURL
//
//  Created by Chief Hakka on 23/04/2025.
//
extension URLQueue {
    static func updateOnlineInfo(_ info: OnlineURLInfo) {
        if let index = shared.onlineQueue.firstIndex(where: { $0.id == info.id }) {
            shared.onlineQueue[index] = info
        }
    }
}
