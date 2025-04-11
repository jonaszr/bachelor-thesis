import requests
from bs4 import BeautifulSoup
import json
import time
import logging

logging.basicConfig(filename='scraping_errors.log', level=logging.ERROR)


def scrape_snyk_maven_vulnerabilities():
    base_url = "https://security.snyk.io/vuln/maven"
    vuln_data = []
    page = 1

    try:
        while len(vuln_data) < 2000:
            url = f"{base_url}/{page}" if page > 1 else base_url
            response = requests.get(url)
            if response.status_code != 200:
                logging.error(
                    f"Failed to fetch the page {url}. Status code: {response.status_code}")
                break

            soup = BeautifulSoup(response.text, 'html.parser')
            vulnerabilities = soup.select(
                'a.anchor.anchor--underline.anchor--default')
            if not vulnerabilities:
                logging.error(
                    f"No vulnerabilities found on page {page}. Check the HTML structure.")
                break

            for vuln in vulnerabilities:
                href = vuln.get('href', '')
                # Ensure the link is a vulnerability link
                if not href.startswith('/vuln/'):
                    continue

                vuln_id = "https://security.snyk.io" + href

                try:
                    vuln_response = requests.get(vuln_id)
                    if vuln_response.status_code != 200:
                        logging.error(
                            f"Failed to fetch details for {vuln_id}. Status code: {vuln_response.status_code}")
                        continue

                    vuln_soup = BeautifulSoup(
                        vuln_response.text, 'html.parser')
                    patch_urls = [link['href'] for link in vuln_soup.find_all(
                        'a', string="GitHub Commit")]

                    vuln_data.append({
                        "VulnID": vuln_id,
                        "PatchUrls": patch_urls
                    })

                    if len(vuln_data) >= 700:  # Stop if we reach 700 entries
                        break

                    time.sleep(0.1)  # Rate limiting

                except Exception as e:
                    logging.error(f"Error fetching details for {vuln_id}: {e}")

            page += 1  # Move to the next page

        with open('snyk_maven_vulnerabilities.json', 'w') as json_file:
            json.dump(vuln_data, json_file, indent=4)

        print(
            f"Scraping completed. Collected {len(vuln_data)} entries. Data saved to snyk_maven_vulnerabilities.json.")

    except Exception as e:
        logging.error(f"Error during scraping: {e}")


if __name__ == "__main__":
    scrape_snyk_maven_vulnerabilities()
