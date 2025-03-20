import UIKit
@testable import URLChecker

var greeting = "Hello, playground"
let str = "eyJpdiI6IkRRbzBCU1duQ0xiOXJ5cXdnREFEdmc9PSIsInZhbHVlIjoiZXRudGdaYkhta2g1UVFlcHVkdWs3aUVqSzlaYjZaM2VCdmRHQnlTWU9LYzFRZTlFN2oybWpIL0ZnZkg2SUdhVnlVZTFBcFZFd1pKMHZWS2ZOVjVtSEE9PSIsIm1hYyI6ImM1ZTRhZTIzODlhZjM4MGEwYjU4Y2Y0MmVhZDhlN2ExM2RlODA4MzNkNzgzYjlkNTc3OGQ2MjE0NjRmNDFjYzIiLCJ0YWciOiIifQ=="

var decoded = DecodingTools.decodeBase64(str)
print(decoded ?? "")

var iv = DecodingTools.decodeBase64("DQo0BSWnCLb9ryqwgDADvg==")
var value = DecodingTools.decodeBase64("etntgZbHmkh5QQepuduk7iEjK9Zb6Z3eBvdGBySYOKc1Qe9E7j2mjH")
var value2 = DecodingTools.decodeBase64("FgfH6IGaVyUe1ApVEwZJ0vVKfNV5mHA==")
var mac = DecodingTools.decodeHex("c5e4ae2389af380a0b58cf42ead8e7a13de80833d783b9d5778d621464f41cc2")
var macUUID = DecodingTools.analyzeUUID("c5e4ae2389af380a0b58cf42ead8e7a13de80833d783b9d5778d621464f41cc2")

print("iv :", iv)
print("value :", value)
print("value2 :", value2)
print("mac :", mac)
print("macUUID:", macUUID )
