import Foundation

let scriptSources = [
    "Example.com/path/2737.js",
    "Example.com/path/123/we.js",
    "Example.com/path/other/file.css",
    "Example.com/another/thing.html",
    "Example.com/another/stuff.php",
    "Different.org/page.html",
    "Example.com/path/image.png",
    "Example.com/index.html",
    "AnotherExample.com/script.js",
    "AnotherExample.com/utils/helper.js",
    "/_next/static/chunks/fd9d1056-c07a78c5d535bea4.js",
    "/_next/static/chunks/main-app-6f0b34eb81b2baab.js",
    "/_next/static/chunks/8b9c1878-e0950841cd716641.js",
    "/_next/static/runtime/webpack.js"
]

// 1_ Sort all script ASCII
// ensures similar paths are adjacent
let sortedSources = scriptSources.sorted()

print("Step 1 - Sorted Sources:")
print(sortedSources.joined(separator: "\n"))

// final grouped output, list of similar script paths
var groups: [[String]] = []

// Index for the sorted lis
var i = 0

print("\nStep 2 - Begin Grouping:")

// 2_iterate through the sorted list and group entries by prefixes
while i < sortedSources.count {
    print("\nStarting new group from: \(sortedSources[i])")
    // Start a new group beginning with the current item
    var group = [sortedSources[i]]
    // This holds the evolving "common prefix" for the current group
    var prefix = sortedSources[i]

    // Step 2.1: Scan forward from the current item
    // Imagine a vertical scan window sliding down the sorted list, checking each next entry
    for j in (i+1)..<sortedSources.count {
        // Get the common prefix between the current prefix and the next item
        // This mimics a character-by-character scan from left to right, stopping at the first mismatch
        let common = commonPrefix(prefix, sortedSources[j])
        print("Comparing with: \(sortedSources[j])")
        print("Common prefix: \(common)")
        // If the prefix is long enough (heuristic: more than 5 chars), we assume it's part of the same group
        if common.count > 5 {
            // Add the item to the group
            group.append(sortedSources[j])
            // Update the prefix so future comparisons are more specific to this group
            prefix = common
        } else {
            print("Prefix too short, stopping group.")
            // If the prefix is too short, stop scanning — we've hit a different pattern
            break
        }
    }

    // Save the group we just built
    print("Group finalized: \(group)")
    groups.append(group)
    // Move the index forward by the number of items we just grouped
    i += group.count
}

// Helper: Computes the longest shared prefix between two strings, char by char
func commonPrefix(_ a: String, _ b: String) -> String {
    let aChars = Array(a)
    let bChars = Array(b)
    var result = ""
    for (ac, bc) in zip(aChars, bChars) {
        if ac == bc {
            result.append(ac)
        } else {
            break
        }
    }
    return result
}

// Helper: Given a group, find the longest common prefix across all items in the group
func groupCore(_ group: [String]) -> String {
    guard var prefix = group.first else { return "" }
    for item in group.dropFirst() {
        prefix = commonPrefix(prefix, item)
        if prefix.isEmpty { break }
    }
    return prefix
}

// Final Output: Show each group with its shared prefix and the differing suffixes
print("\nStep 3 - Final Grouped Output:")
for group in groups {
    // For each group, extract the "core" prefix
    // Then remove this prefix from each item to isolate their unique part
    let core = groupCore(group)
    let diffs = group.map { String($0.dropFirst(core.count)) }
    // Display the grouped prefix and the unique tail of each path
    print("\"group: \(core)\" diff: \(diffs)")
}
