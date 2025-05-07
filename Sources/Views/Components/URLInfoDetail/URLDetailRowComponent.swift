//
//  URlDetailRow.swift
//  LegitURL
//
//  Created by Chief Hakka on 01/04/2025.
//
import SwiftUI

struct URLDetailRow: View {
    var label: String
    var value: String
    
    var body: some View {
        if value.count > 50 {
            VStack(alignment: .leading, spacing: 2) {
                Text(label)
                    .font(.body)
                    .foregroundColor(.primary)
                
                Text(value)
                    .font(.callout)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.leading)
                    .lineLimit(nil)
            }
            .padding(.vertical, 4)
        } else {
            HStack {
                Text(label)
                    .font(.body)
                    .foregroundColor(.primary)
                
                Spacer()
                
                Text(value)
                    .font(.callout)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.trailing)
                    .lineLimit(3)
            }
            .padding(.vertical, 4)
        }
    }
}
