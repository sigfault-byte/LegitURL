## 1 LegitURL

LegitURL is an iOS app that analyzes URLs to help users — both non-technical and technical — assess the legitimacy of a web link.

The app performs both offline and online analysis to detect phishing, scam patterns, suspicious behaviors, and poor security practices.

Its mission is to make internet safety transparent and accessible, without compromising user privacy.

For more information about the motivations and background of this project, see [WHY.md](WHY.md).

For a detailed history of the project's development, see [HISTORY.md](HISTORY.md).

## 2 Who is this for 

The app's main target is non-technical users. Its purpose is to help them determine whether a link is suspicious. 
The original main logic was to follow the redirect link, to expose what url was entered, and where it takes you.
The development revealed that in order to accomplished such logic, technical folks might also find interest in a iOS app that dissects URL, headers, TLS, Cookie and a quick analysis of the body, on their phone, in an offline environment.

## 3 How does it work
LegitURL analyzes URLs in two phases: offline (local processing) and online (server requests). Users paste a link, press a button, and receive a safety assessment.

### 3.1 Input Validation
- Only secure (HTTPS) links are analyzed, per Apple’s URLSession guidelines. If no scheme is specified, `https://` is prefixed.
- Non-secure (HTTP) links are flagged as unsafe without further analysis.

### 3.2 Offline Analysis
	The URL is broken into parts, using both Apple’s URLComponents and Mozilla’s Public Suffix List to correctly identify domains and TLDs.
	Perform various checks on the domain, subdomain, path, query and fragment.
	The checks for all of them are:
		If an underscore (_) is found in the subdomain, it is removed. If a hyphen (-) is found in the domain or subdomain, the component is split into parts for the following analysis.
		the domain is converted to IDNA so it can reveal if there are some non latin letters inside. And if there was a tentative to impersonated a known brand.
			if there are, it will discern if its a mix of latin and extended latin, or latin with Cyrillic or greek.
			if the whole domain is from another alphabet, it will check if the TLD is from the same alphabet.
		a lookup of Scam words, Phishing words, known brand words ( that the user can populate ), and a quick Levenshtein and 2gram comparison to catch typo, and lookalike .
		It (awkwardly) uses the iOS dictionary to check whether words exist in the current locale. If not found, it falls back to entropy checks.
		The same logic applies to the path, The path is split into parts using the "/" separator. They are matched against the iOS dictionnary, if it fails, an entropy check is made. 
		The scam words and brand check, as well as typo's are also check, but the signal it case of a match, is considered less relevant than a finding in domain or subdomain.
		If the query and fragment are well formatted, i.e no funky ?# or #?:
		The query is broken into two array, after being sure it respects a clean key value structure.
		If the fragment resembles a query string, the same logic is applied and it is broken into key-value pairs.
			otherwise, its check just like the path, plus some various checks like UUID, URL, Email, redirect detection, bad js
		the key and value are passed to a decoding node tree, named "Lamai". It will try to decode base64, unicode, url encoding, and % encoding. It will elect the most interesting branch up to a depth of 5 per branch, based on factors such as: whether the decoded value is printable, whether sibling nodes are deeper, and if stuck at a certain depth, whether it can attempt further decoding by splitting the content into smaller parts.
		If a branch reaches a final depth, it will then analyze the content, to discover if it's an email, an IP, address url, a uuid, has any scam word or phishing words and known brand.

		If a URL is found, it is looped back into the analyzer.

### 3.3 Online Analysis
	It grabs the first URL found in the offline queue and makes a GET request to the "coreURL" (i.e., the base URL, stripped of query parameters and fragments). If the connection hangs for more than 10 sec, the connection is cut.
	It does not follow the redirect, and extract all information: the headers, the body, the TLS certificate.
	It will first look what kind of response was return, if its a redirect it will look if the redirect changes domain, or if its an internal redirect.
	
	It will then analyze the tls certificate.
		It performs various checks, some of which are redundant with Apple’s security policies, such as whether the domain is in the SAN, whether the certificate is still valid, whether the chain is valid, and whether it is self-signed.
		It will expose the certificate’s validity period in human-readable "days" format, log the CA and CN, show the policy, and reveal whether the domain is EV, OV, or DV.
	
	It then analyzes the cookies sent by the server.
		If the response code is anything else than a 200, it will consider this signal as suspicious.
		It will measure the size of the cookie's value, then uses it to measure the average size of the cookie given by the server. An excessive amount on a 3xx is even more suspicious.
		It will then analyze individual cookies. Their exact value and its entropy, the presence or absence of the important flag samesite, httponly and secure, its exportation. Depending on their combination will try to sort them between tracking, suspicious and dangerous.
		For instance a cookie with no httponly, no secure, and a samesite=none is considered dangerous, no matter its size; a cookie with a value inferior to 10 bytes with missing flag like httponly or secure, will be analyze as a weaker signal than if its size was above.
		It will log the cookie keys it encountered, so if the same cookie are send again in the next response, they are not penalized again, although they receive a higher penalty when set on a non-200 response.
	
	It will then do an analysis of the html body.. quickly.
		It will make sure the the html is correctly formatted, so it needs to have a correct <html><head></head><body></body></html> structure, otherwise its considered as a moderate signal of a suspicious behavior.
		It will then extract all <script></script> inside the body, and classify them between inline, or external / relative script and in their context, whether they are in the head or the body.
		If any <script> tag lacks a proper </script> (unless self-closed), the HTML is considered malformed.
		It will calculate the ratio between inline script and HTML content. The higher the ratio, especially for a small body — for example, a 1000-byte HTML with more than 50% JavaScript — this is considered a moderate signal.
		It will also calculate the script density of the internal and external imported scripts relative to the HTML size.
		It will then look all inline script for suspicious js "setter" functions like eval, atob, btoa, location.href, getElementById, 
		It will also look at specific accessor, like document.cookie, or seItem, or WebAssembly. If a setter is found, and an accessor is found the site is considered no secure.
			e.g: A atob() is found, and a document.cookie is found -> this could either indicate that the website is bypassing the header contract for cookie saving, or is manipulating cookie;
				if document.getElementById is found, and within a fixed amount of byte .submit( is found -> this is most likely an autosubmitted trick.
		it will save external and nonce value, to compare it to the header csp policy.
	It will then do an analysis of the header content.
		EXPLANATION OF HEADER ANALYSIS

### 3.4 Output
- Non-technical users receive a simple safety signal (e.g., red for dangerous, yellow for suspicious, green for safe).
- Technical users can view detailed logs, including domain breakdowns, TLS details, and script analysis.

## 4 Scoring System
	The app main logic is that every URL starts with 100 points.
	Each signal in the redirect chain may lower those points. It could be: a scam word in the subdomain, a reference to a brand in the domain, an obfuscated blob with high entropy in the path, a call to window.open in the body, a fresh DV certificate, a cookie with missing flags. It uses the Punycode dependency to convert user input to IDNA to be sure the domain is not a trick.
	Adding those penalties together, and into different layer help the app to give an overall penalty of the whole chain, or on the single response. Penalty can have variable penalty for the same type, for instance, a exact brand in the domain is penalize differently depending on its structure an content, applepie.com is penalize differently than apple-pie.com and secure-apple.com is another penalty.
	Individually the signal helps the app to see the specific of each part, but to have an overall idea with the whole context, the app uses bit flag to detect "combo" of highly suspicious signal. For instance, a scam word in the subdomain and a brand match in the domain leads to a critical signal, a fresh tls, with weak headers and some wacky html is another. Combo result in an additional penalty on the overall score.

## 5 Core detection features
	The app is pretty straightforward and uses mainly swift foundation import. It uses two other packages: a punycode converter, and a x509 decoding package.
	Every exact matches is mostly done using .contain swift core method. For byte matching, numerous custom functions were created depending on the goal it's trying to achieve. For instance, it may take a byte position at input, and look up to a certain number of byte forward, while counting, or ignoring spaces, tabs, or \n.
	Every typo checks uses both a levenshtein = 1 check a 2gram in case levenshtein fails. The ngram condition depends on where the word is compared. For instance in the query the ngram needs to be more strick than it is in the domain.
	Lamai uses common custom function to decode base64 - it just pads whatever blobs that  looks like base64 if the %4 is not 0, same for url and % encode or unicode. It will just loop until its maximum authorized depth to try to its best to decode anything. Each branch tries different tactics, it could be decoding, scam or phishing or brand detection, splitting into smaller parts, or identifying uuid, email json ip etc.
	Each branch goal is to go as deep as it can as long as the results gives something. The last resort is looking at the entropy of the string. But this is tricky, because anything can have a high entropy, but it does not mean it can or cannot be decoded... So an early entropy check might stop other branches because of a finding.
	The body scan is straight forward, and does q quick byte scan to extract the location of the html, body, head and all <script> tags, classifies them, extract their value, if correct html and open and enclosing tag is correct.
		For www.google.com the attraction is sub 7ms for a ~ 180KB body. For a bigger body like steampowered.com which is ~ 780KB, it's around 20ms.
	The cookie analysis uses bit a 16bit int mask, to store different flags, such as "long value" "highentropy" "httponly" flag missing. It then can use them to combo them into moderate signal. A 365 days + 100 byte value, without httponly -> terrible signal, thought it could be either marketting / tracking or scam. A samesite=none with no httponly or no secure flag is also terrible signal too. But, one is a heavy tracking, the second is borderline dangerous. The app, in its current form, tries to mitigate this strange ressemblance to strict a strict, yet fair penalty.
	The TLS check is made after decoding the raw certificate. The check are redundant to apple's security pre check thanks to url session. But it's possible to manually do it by bypassing URLSession security. Thought the point is to deliver the app, and this would result in a refusal from apple.
	It off course, alongside urlsession, verify if the tls chain is correct, extract the oid policy and saves them correctly wether its DV OV or EV. It looks if the san are wildcard and if the domain is correctly referenced inside. The TLS checks, in the end, primarily looks for the TLS period, to flag fresh tls and tries to reward EV or OV domain. Thought this is tricky, because some domain have OV with wildcard san, and then let users create subdomains.
	EXPLANATION OF HEADER ANALYSIS

## 6 Example use case
	##Exemple 1.

	If the user correctly saved that bankoftrust.com is on their “watchlist”, the app will use it as a whitelist domain, skipping domain checks and keeping “bankoftrust” as a keyword to monitor.

	User pastes:
	https://secure-login.trustedbank.com.userauth-check.info/session?token=xyz

	URL breakdown:
		•Domain:	userauth-check
		•TLD: 		info
		•Subdomain:	secure-login.trustedbank.com
		•Path: 		/session
		•Query: 	token=xyz

	Offline Analysis Results:
		•Domain: 	“userauth” not in dictionary → weak signal, no penalty.
		•TLD: 		info has bad reputation → moderate signal, penalty of -20.
		•Subdomain: 	scam/phishing words and brand impersonation detected.
		•Path: 		“session” not in dictionary → weak signal, no penalty.
				But the path resembles an API endpoint, implying it’s awaiting a value — weak signal, small penalty: -10 (1/10 of the max score).
		•Query: 	Value passed to Lamai. Assume nothing was found.

	Conclusion:
		→ Total penalty from subdomain + suspicious TLD + API-style path, detected as a combo adds a -100 penalty.
		→ This would be flagged as dangerous.
		→ Online check is skipped — the offline score is already critically low.

	Verdict: The URL impersonates a known brand using a deceptive subdomain, suspicious TLD, and tokenized query path. Score: 0/100 — flagged as DANGEROUS.


	##Exemple 2.
	Let’s consider this random link from a promoted x.com post:
		bit.ly/mihoyanagi

	URL breakdown:
		•Domain: 	bit
		•TLD: 		ly
		•Path:		/mihoyanagi

	Offline Analysis Results:
		•Path term not recognized by dictionary → no penalty.
		→ Score remains 100.

	Online Check Begins:
		•GET request is sent with a real iOS User-Agent and clean headers.
		•301 redirect to https://jolyvip.com/mihoyanagi → domain changes → weak signal, small penalty.
		•TLS certificate valid.
		•Sets a 29-byte cookie on a non-200 → missing Secure and HttpOnly, lifespan 180 days → critical signal.

	URL Loop: https://jolyvip.com/mihoyanagi
		•Offline:	domain not in dictionary → no penalty.
		•Online: 	302 redirect to https://coingrok.io → domain changes again → weak signal, small penalty.
			•TLS is 4 days old → moderate signal, -20.
			•2 cookies set on redirect (non-200):
				•One is 10 bytes, missing all flags, 31-day lifespan, SameSite=Lax → weak signal.
				•One is 213 bytes, missing all flags, SameSite=Lax → moderate signal, -10.

	URL Loop: https://coingrok.io
		•Offline: 	domain not in dictionary → no penalty.
		•Online:	 200 OK.
			•TLS is from Google Trust Services (CN: WE1), valid → no issue.
			•No cookies.
			•Body analysis: inline JavaScript = 74% of HTML. Script density = 1.282 → abnormal, potential obfuscation → penalty.
			•Header analysis:
			•CSP header reveals random external domains with wildcards → penalty.
			•Server: cloudflare → info only, no penalty.
			•X-Powered-By: Next.js → backend stack leakage → weak signal, small penalty.

	→ No more URLs to analyze.

	Verdict: A redirect chain ending in a shady domain with tracking cookies, excessive inline scripts, and CSP violations. Score: 0/100 — flagged as DANGEROUS.

	## Example 3 – Cloaked Scam Infrastructure via Shared TLS Certificate

		Let’s consider the following link:
		    https://www.man-entreprise.com/vrp/ayxxxxxxx/yyyy  
			    (The query has been altered to avoid exposing personal data.)

	###  URL Breakdown:
		• Domain: man-entreprise  
		• TLD: com  
		• Path: /vrp/ayxxxxxxx/yyyy

	---

	###  Offline Analysis:
		→ No warnings or signals detected.

	---

	###  Online Analysis Begins:

		- A GET request is sent using a clean iOS User-Agent with stripped headers.
		- The server responds with a **302 redirect** to:  
			  `https://ed.manageo.biz/clt-su/SFR/formulaire16_2tps.jsp?...`  
  				*(Parameters include leaked personal data — redacted here.)*

	---

	###  TLS Certificate Details (Intermediate Domain: man-entreprise.com)

		- Certificate type: **DV** (Domain Validation)  
			- Issuer: Let's Encrypt  
			- Age: **10 days old** (Issued 2024/04/10, analyzed on 2024/04/20)  
			- Subject Alternative Names (SANs): **76 entries**, no wildcards  
			  - All entries are fully-qualified domain names (FQDNs)
			  - Many share a base pattern with randomized strings, or are entirely unrelated
		  - → 🚨 Strong signal of **certificate-based cloaking infrastructure**

	---

	###  Response Details (man-entreprise.com):
		- No cookies set
		- Headers:
		  - `x-powered-by: PHP/5.6` → weak stack leak
		  - `server: ovhcloud` → neutral, mildly leaky

	---

	###  URL Chain Continues:

		Target URL (altered):  
			`https://ed.manageo.biz/clt-su/SFR/formulaire16_2tps.jsp?...`

	- Domain has **.biz** TLD → moderate suspicion
	- Redirect to a different domain → moderate signal
	- Query string is malformed:
		- Some key-value pairs are empty or improperly encoded
		  - Contains non-conforming characters
	  → Combined: moderate signal of a sloppy or deceptive system

	---

	###  Final Destination: ed.manageo.biz

	- Response: **200 OK**
	- Cookie: `JSESSIONID` is missing `Secure` flag → weak signal
	- Script origin: **undetectable**
  		- Could indicate cloaking or malformed attributes → moderate signal
		- Script density: **1.325 scripts per 1000 bytes**
		- Abnormally high → possible obfuscation or injected behavior
	- TLS certificate:
		- DV, Let's Encrypt
		- Issued ~1 month ago
  		- **25 SANs**, no wildcards, same pattern as earlier
	  →  Strong signal of shared scam infrastructure

	---

	### Verdict:

	A suspicious redirect chain ending in a `.biz` domain that:
		- Hosts **obfuscated and potentially cloaked scripts**
		- Uses **malformed queries** and leaked personal data
		- Shares a **Let's Encrypt DV certificate with 25 unrelated FQDNs**

	Combined with the initial domain sharing a DV cert with 76 unrelated domains, this URL likely belongs to a **scalable phishing infrastructure** designed to impersonate services like Manageo.

	**Trust Score: 0 (CRITICAL)**  



LEGITURL — README

1. What is LegitURL?
2. Who is this for?
3. How does it work?
    - Offline Analysis
    - Online Analysis
4. Scoring System
    - Bitmask Warning System
    - Final Score Calculation
5. Core Detection Features
    - Domain & Subdomain Analysis
    - Scam Word & Brand Detection
    - Encoding & Entropy Heuristics (Lamai Decoder)
    - Body Script & Content Analysis
    - Cookie Behavior Analysis
    - Header & TLS Certificate Checks
	## Core Idea

A TLS certificate issued by Let’s Encrypt with a high number (e.g., 30+ or even 10+) of specific Fully Qualified Domain Names (FQDNs) listed in the Subject Alternative Name (SAN) field — and no wildcard entries — especially on a short-lived certificate (common with Let’s Encrypt), is a **strong signal of potential malicious infrastructure** designed for obfuscation.

---

### Key Supporting Points

- **Corporate Contrast**:  
  Legitimate organizations with numerous subdomains (e.g., `login.example.com`, `api.example.com`) typically use **wildcard SANs** (`*.example.com`) for efficiency and broader coverage.

- **Let’s Encrypt Wildcard Policy**:  
  Wildcards require a **DNS-01 challenge**, which most scammers avoid because it requires control over DNS — incompatible with throwaway infrastructure or automated domain abuse.

- **Operational Inefficiency**:  
  Maintaining dozens of hardcoded FQDNs on short-lived certificates is **inefficient for any real business** — but aligns perfectly with **phishing kits**, **redirect networks**, or **botnet mailers**.

- **Obfuscation by Design**:  
  A SAN list full of loosely related or completely unrelated domains suggests intentional **scamkit cloaking**, making detection harder for traditional tools that analyze URLs in isolation.

- **Elevated Risk When Combined**:  
  When this SAN pattern is detected **alongside other red flags** — e.g., `.biz` or `.click` domains, malformed URLs, JS obfuscation, or redirects — it **strongly correlates** with known phishing and fraud operations.

---

### Conclusion

This TLS SAN pattern deviates from modern best practices and reveals intent:
> Not to securely serve users — but to **cloak a network of scam infrastructure.**
6. Example Use Case
7. Philosophy Behind the App
8. Why This App Exists
9. Contact & License