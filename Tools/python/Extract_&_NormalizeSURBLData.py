import requests
import csv

# 🔗 SURBL TLD Abuse Rankings URL
SURBL_URL = "https://www.surbl.org/static/tld-abuse-complete-rankings.txt"

# 📂 Output CSV
OUTPUT_FILE = "surbl_abuse.csv"


def fetch_surbl_data():
    """Download and parse the SURBL TLD Abuse Rankings."""
    print("Fetching SURBL TLD abuse rankings...")
    response = requests.get(SURBL_URL, timeout=10)
    response.raise_for_status()
    return response.text


def parse_surbl_data(text):
    """Extract TLDs and their abuse rankings."""
    lines = text.splitlines()
    tld_abuse = {}

    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue  # Skip lines that don't have enough parts

        tld = parts[1].strip().lower()  # Extract TLD
        count_str = parts[-1].strip()  # Last part should be the abuse count

        if not count_str.isdigit():
            continue  # Skip lines where last part is not a number

        count = int(count_str)

        if tld not in tld_abuse:
            tld_abuse[tld] = count

    return tld_abuse


def normalize_scores(tld_abuse):
    """Normalize abuse scores to a 0-1 scale."""
    max_value = max(tld_abuse.values()) if tld_abuse else 1  # lmao /0  Avoid division by zero
 
    return {tld: round(count / max_value, 4) for tld, count in tld_abuse.items()}


def save_to_csv(tld_scores):
    """Save the normalized TLD abuse data to a CSV file."""
    print(f"💾 Saving data to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["tld", "abuse_score"])  # Header ?
        for tld, score in sorted(tld_scores.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([tld, score])

    print(f"{len(tld_scores)} TLDs saved in {OUTPUT_FILE}")


def main():
    text = fetch_surbl_data()
    tld_abuse = parse_surbl_data(text)
    normalized_scores = normalize_scores(tld_abuse)
    save_to_csv(normalized_scores)


if __name__ == "__main__":
    main()