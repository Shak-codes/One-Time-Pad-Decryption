import re
import requests
from bs4 import BeautifulSoup


def fetch_formal_contractions():
    url = "https://en.wikipedia.org/wiki/Wikipedia:List_of_English_contractions"
    r = requests.get(url)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")

    contractions = set()

    table = soup.find("table", {"class": "wikitable"})
    for row in table.find_all("tr"):
        cols = row.find_all("td")
        if len(cols) >= 2:
            contraction = cols[0].get_text(strip=True)

            if any(classifier in contraction for classifier in ["informal", "slang", "colloquial", "dialect", "nonstandard", "poetic"]):
                continue

            contraction = contraction.replace("(formal)", "")

            contractions.add(contraction)

    return sorted(contractions)


def append_contractions_to_file(filepath, contractions):
    with open(filepath, 'a', encoding='utf-8') as f:
        for contraction in contractions:
            f.write(contraction + '\n')


if __name__ == "__main__":
    contractions = fetch_formal_contractions()
    append_contractions_to_file("english-words.10", contractions)
