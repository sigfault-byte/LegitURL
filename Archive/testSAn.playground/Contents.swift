import Foundation

let sanList = [
    "info-emplois-collectivites.fr",
    "mail.aprem-wx.com",
    "smesg.net",
    "smktg.net",
    "smsg.fr",
    "www.apdifu.com",
    "www.apfilut.fr",
    "www.apjowit.fr",
    "www.aploram.fr",
    "www.aprbc.fr",
    "www.aprem-af.com",
    "www.aprem-fg.com",
    "www.aprem-gfd.fr",
    "www.aprem-hi.com",
    "www.aprem-jk.com",
    "www.aprem-kg.com",
    "www.aprem-qc.com",
    "www.aprem-tdi.com",
    "www.aprem-uv.com",
    "www.aprem-vga.com",
    "www.aprem-wx.com",
    "www.apriwey.fr",
    "www.aprovde.fr",
    "www.aproxeml14.com",
    "www.aproxeml19.com",
    "www.aproxeml24.com",
    "www.aproxeml32.com",
    "www.aprudit.com",
    "www.apsihuk.fr",
    "www.apsjkc.com",
    "www.aptella.fr",
    "www.at-9u.fr",
    "www.data-marketing-projet.net",
    "www.distrimail.net",
    "www.ed-gatan.com",
    "www.ed-getam.com",
    "www.ed-mutu.fr",
    "www.ed-sitam.com",
    "www.ed-trouvi.com",
    "www.ed-virou.com",
    "www.ed-vitan.com",
    "www.els-utr.com",
    "www.info-emplois-collectivites.fr",
    "www.mail.aprem-wx.com",
    "www.man-entreprise.com",
    "www.master-rt.net",
    "www.mixcd.fr",
    "www.neomacom.fr",
    "www.parvati410.com",
    "www.power-mta.com",
    "www.smesg.net",
    "www.smktg.net",
    "www.smsg.fr",
    "www.trqopt.fr",
    "www.vme-04.com",
    "www.vme-agencemd.fr",
    "www.vme-ghd.fr",
    "www.vme-hbi.fr",
    "www.vme-mci.com",
    "www.vme-ody.com",
    "www.vme-trckb.fr",
    "www.vme-uvi.com",
    "www.vml-103.com",
    "www.vml-854.com",
    "www.vml-ext7.com",
    "www.vml-tma.com",
    "www.vml04.com",
    "www.vmlas.fr",
    "www.vmle-ext6.com",
    "www.vmle-pmy.com",
    "www.vmleo.com",
    "www.vmleu.com",
    "www.vmlpu.fr",
    "www.vmlta.com",
    "www.vmluy.fr",
    "www.vmlws.fr",
    "www.votcenter.com"
]

let stripped = sanList.map {
    $0.replacingOccurrences(of: "www.", with: "")
      .components(separatedBy: ".").first ?? ""
}

func ngrams(_ word: String, n: Int) -> [String] {
    guard word.count >= n else { return [] }
    return (0...(word.count - n)).map {
        let start = word.index(word.startIndex, offsetBy: $0)
        let end = word.index(start, offsetBy: n)
        return String(word[start..<end])
    }
}

var freq = [String: Int]()
for domain in stripped {
    for gram in ngrams(domain, n: 3) {
        freq[gram, default: 0] += 1
    }
}

let sorted = freq.sorted { $0.value > $1.value }
for (gram, count) in sorted.prefix(10) {
    print("🧬 \(gram): \(count) times")
}

let ogDomain = "www.man-entreprise.com"
var sanCopy = sanList
let numberOfSANs = sanCopy.count
sanCopy.append(ogDomain)
let numberOfSANsWithOG = sanCopy.count

let setOFJoined: Set<String> = Set(sanCopy)

print("Sans Number: \(numberOfSANs)")
print("Sans + Og Number: \(numberOfSANsWithOG)")
print("Unique Sans Number: \(setOFJoined.count)")

let duplicates = sanCopy.filter { item in
    sanCopy.firstIndex(of: item) != sanCopy.lastIndex(of: item)
}

let uniqueDuplicates = Set(duplicates)

print("🕵️‍♂️ Duplicated Entries Detected:")
for dup in uniqueDuplicates {
    print("🔁 \(dup)")
}
