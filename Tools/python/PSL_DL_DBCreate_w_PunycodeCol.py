# Downloads the PSL list and cleans it
# Sorts TLDs by length, then alphabetically
# Adds a punycode_suffix column in SQLite
# Ensures all non-ASCII TLDs are converted to Punycode

import requests
import idna  # Handles Punycode conversion

# Download URL for the latest PSL list
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
DB_PATH = "public_suffix_list.sqlite"

def download_psl():
    """Download the latest Public Suffix List and clean."""
    response = requests.get(PSL_URL, timeout=10)
    response.raise_for_status()

    lines = response.text.splitlines()
    suffixes = []

    for line in lines:
        line = line.strip()
        if line and not line.startswith("//"):  # Ignore comments and empty lines
            suffixes.append(line)

    print(f"Downloaded {len(suffixes)} suffixes.")

    # Sort by length first, then alphabetically
    sorted_suffixes = sorted(set(suffixes), key=lambda s: (len(s), s))

    return sorted_suffixes

def to_punycode(domain):
    """Convert a domain to Punycode, or return it unchanged if it's already ASCII."""
    try:
        return idna.encode(domain).decode("utf-8")
    except idna.IDNAError:
        return domain  # Return unchanged if conversion fails

def create_database(suffixes):
    """Create SQLite DB and insert PSL data with Punycode."""
    conn = sqlite3.connect(DB_PATH)
    conn.text_factory = lambda x: str(x, "utf-8", "ignore")  # Ensure UTF-8 !!!
    cursor = conn.cursor()

    # Add a Punycode column
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS psl (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        suffix TEXT UNIQUE COLLATE NOCASE,
        punycode_suffix TEXT UNIQUE COLLATE NOCASE
    )
    """)

    # Convert to Punycode before inserting
    converted_suffixes = [(s, to_punycode(s)) for s in suffixes]

    cursor.executemany("INSERT OR IGNORE INTO psl (suffix, punycode_suffix) VALUES (?, ?)", converted_suffixes)
    conn.commit()
    conn.close()
    print(f"Database '{DB_PATH}' updated with {len(suffixes)} TLDs and their Punycode equivalents.")
    # TODO: -> add directly to the model / database folder. It should normaly overwrite the current one, other might as well rm it before

def main():
    suffixes = download_psl()
    create_database(suffixes)

if __name__ == "__main__":
    main()
