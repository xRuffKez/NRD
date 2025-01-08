import os
import base64
import requests
import re
import json
import shutil
import tarfile
from datetime import datetime
import logging
import idna  # For Punycode encoding

# Setup logging
logging.basicConfig(level=logging.INFO)

def fetch_valid_tlds():
    """Fetches the list of valid TLDs from the IANA website."""
    tld_url = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
    try:
        response = requests.get(tld_url)
        if response.status_code == 200:
            tlds = {line.strip().lower() for line in response.text.splitlines() if line and not line.startswith("#")}
            logging.info(f"Fetched {len(tlds)} valid TLDs.")
            return tlds
        else:
            logging.error(f"Failed to fetch TLDs. Status Code: {response.status_code}")
    except Exception as e:
        logging.error(f"Error fetching TLD list: {e}")
    return set()

def is_valid_domain(domain, valid_tlds):
    """Checks if a domain ends with a valid TLD."""
    match = re.search(r'\.([a-zA-Z]{2,})$', domain)
    return match and match.group(1).lower() in valid_tlds

def filter_domains(domains, valid_tlds):
    """Filters a set of domains to include only those with valid TLDs."""
    return {domain for domain in domains if is_valid_domain(domain, valid_tlds)}

def fetch_additional_source():
    """Fetches and returns domain data from an additional source."""
    additional_url = os.getenv("ADDITIONAL_SOURCE_URL")
    if not additional_url:
        logging.warning("No ADDITIONAL_SOURCE_URL provided.")
        return set()

    headers = {"User-Agent": os.getenv("USER_AGENT")}
    try:
        response = requests.get(additional_url, headers=headers)
        if response.status_code == 200:
            all_domains = set(re.findall(r'(?<!@)(?:[\w-]+\.)+[a-zA-Z]{2,}(?!\.)', response.text))
            logging.info(f"Fetched {len(all_domains)} domains from additional source.")
            return all_domains
        else:
            logging.error(f"Failed to fetch additional source. Status Code: {response.status_code}")
    except Exception as e:
        logging.error(f"Error fetching additional source: {e}")
    return set()

def download_file_if_etag_changed(url, dest, etag_file):
    """Downloads a file only if the ETag has changed."""
    logging.info(f"Checking URL: {url}")
    response = requests.head(url)
    etag = response.headers.get('ETag')
    if os.path.exists(etag_file):
        with open(etag_file, 'r', encoding='utf-8') as f:
            saved_etags = json.load(f)
    else:
        saved_etags = {}
    if saved_etags.get(url) == etag:
        logging.info(f"No change detected for URL: {url}")
        return False
    headers = {"User-Agent": os.getenv("USER_AGENT")}
    response = requests.get(url, headers=headers, stream=True)
    if response.status_code == 200:
        with open(dest, 'wb') as f:
            for chunk in response.iter_content(1024):
                f.write(chunk)
        if etag:
            saved_etags[url] = etag
            with open(etag_file, 'w', encoding='utf-8') as f:
                json.dump(saved_etags, f)
        return True
    logging.error(f"Failed to download from URL: {url}, Status Code: {response.status_code}")
    return False

def extract_largest_file_from_tar_gz(file_path, dest_dir):
    """Extracts the largest file from a tar.gz archive."""
    try:
        with tarfile.open(file_path, "r:gz") as tar:
            largest_file = max(
                (member for member in tar.getmembers() if member.isfile()),
                key=lambda member: member.size,
                default=None,
            )

            if not largest_file:
                logging.warning(f"No files found in archive: {file_path}")
                return None

            largest_file.name = os.path.basename(largest_file.name)
            tar.extract(largest_file, dest_dir)
            extracted_file_path = os.path.join(dest_dir, largest_file.name)
            logging.info(f"Extracted the largest file: {largest_file.name} ({largest_file.size} bytes)")
            return extracted_file_path
    except Exception as e:
        logging.error(f"Error extracting the largest file from {file_path}: {e}")
        return None

def write_output_files(domains, output_dir, description, split_logic):
    """Writes filtered domains to output files in various formats."""
    formats = {
        "adblock": lambda domain: f"||{domain}^",
        "wildcard": lambda domain: f"*.{domain}",
        "unbound": lambda domain: f'local-zone: "{domain}" static',
        "base64": lambda domain: base64.b64encode(domain.encode('utf-8')).decode('utf-8')
    }

    # Write the plain domains-only file with Punycode encoding
    base_file = os.path.join(output_dir, f"{description}.txt")
    with open(base_file, 'w', encoding='utf-8') as f:
        for domain in sorted(domains):
            punycode_domain = idna.encode(domain).decode('ascii')
            f.write(f"{punycode_domain}\n")
    logging.info(f"Generated domains-only file: {base_file}")

    # Split domains-only file if required
    if split_logic.get("domains-only", 1) > 1:
        split_files = split_file(base_file, split_logic["domains-only"])
        logging.info(f"Split domains-only file: {split_files}")

    # Write other formats and split if required
    for fmt, transform in formats.items():
        filename = os.path.join(output_dir, f"{description}_{fmt}.txt")
        with open(filename, 'w', encoding='utf-8') as f:
            now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
            f.write(f"# {description} ({fmt})\n# Generated on {now}\n")
            for domain in sorted(domains):
                punycode_domain = idna.encode(domain).decode('ascii')
                f.write(f"{transform(punycode_domain)}\n")

        # Determine number of parts based on splitting logic
        num_parts = split_logic.get(fmt, 1)
        if num_parts > 1:
            split_files = split_file(filename, num_parts)
            logging.info(f"Split files generated for {fmt}: {split_files}")

def split_file(input_file, num_parts):
    """Splits a file into the specified number of parts."""
    try:
        with open(input_file, 'r', encoding='utf-8') as infile:
            lines = infile.readlines()
        num_lines = len(lines)
        chunk_size = (num_lines + num_parts - 1) // num_parts

        base_name, ext = os.path.splitext(input_file)
        split_files = []
        for i in range(num_parts):
            part_file = f"{base_name}_part{i + 1}{ext}"
            with open(part_file, 'w', encoding='utf-8') as outfile:
                outfile.writelines(lines[i * chunk_size:(i + 1) * chunk_size])
            split_files.append(part_file)
        return split_files
    except Exception as e:
        logging.error(f"Error splitting file {input_file}: {e}")
        return []

def is_valid_label(domain):
    """
    Validates each label of a domain based on the following rules:
    1. The domain must allow a-z, A-Z, 0-9, hyphen (-), and non-ASCII characters.
    2. Each label must be between 1 and 63 characters long.
    3. Labels must not start or end with a hyphen (-).
    4. The final TLD must be between 2 and 6 characters long.
    """
    try:
        # Check the overall domain length
        if len(domain) < 1 or len(domain) > 253:
            return False

        # Split domain into labels
        labels = domain.split('.')

        # Validate all labels except the last TLD
        for label in labels[:-1]:
            if len(label) < 1 or len(label) > 63 or label.startswith('-') or label.endswith('-'):
                return False
            # Allow any Unicode characters (non-ASCII) but ensure valid general structure
            if not re.match(r'^[\w-]+$', label, re.UNICODE):  # Allows a-z, A-Z, 0-9, -, and Unicode characters
                return False

        # Validate the TLD (last label)
        tld = labels[-1]
        if len(tld) < 2 or len(tld) > 6 or not re.match(r'^[a-zA-Z]+$', tld):
            return False

        return True
    except Exception:
        return False

def decode_file(input_file, output_dir, description, split_logic, additional_domains=None, valid_tlds=None):
    """Decodes an input file and processes its domains."""
    try:
        with open(input_file, 'r', encoding='utf-8', errors='replace') as infile:
            domains = set()
            for line in infile:
                try:
                    # Decode the line from base64
                    decoded_str = base64.b64decode(line.strip()).decode('utf-8')
                    if decoded_str:
                        # Extract domain candidates using regex
                        extracted_domains = re.findall(r'(?<!@)(?:[\w.-]+\.)+[a-zA-Z]{2,}(?!\.)', decoded_str)

                        # Validate domains BEFORE Punycode encoding
                        valid_domains = {d for d in extracted_domains if is_valid_label(d)}
                        domains.update(valid_domains)
                except Exception as e:
                    logging.error(f"Error decoding line in {input_file}: {e}")

        # Filter domains by valid TLDs if provided
        if valid_tlds:
            initial_count = len(domains)
            domains = filter_domains(domains, valid_tlds)
            logging.info(f"Filtered domains: {initial_count} -> {len(domains)} based on valid TLDs.")

        # Merge additional domains for standard 30-day lists only
        if additional_domains and description == "nrd-30day":
            initial_count = len(domains)
            domains.update(additional_domains)
            logging.info(f"Merged {len(domains) - initial_count} additional domains into {description}.")

        if not domains:
            logging.warning(f"No valid domains found in file {input_file}. Skipping output generation.")
            return

        # Write validated domains to output files
        write_output_files(domains, output_dir, description, split_logic)
    except Exception as e:
        logging.error(f"Error decoding file {input_file}: {e}")

def process_files_with_additional_source():
    """Processes files with the additional source and TLD filtering."""
    additional_domains = fetch_additional_source()
    valid_tlds = fetch_valid_tlds()

    urls = [
        {
            "url": os.getenv('NORDOMAIN_30DAY_URL'),
            "description": "nrd-30day",
            "split_logic": {"domains-only": 2, "adblock": 2, "wildcard": 2, "unbound": 3, "base64": 2}
        },
        {
            "url": os.getenv('NORDOMAIN_14DAY_URL'),
            "description": "nrd-14day",
            "split_logic": {"domains-only": 1, "adblock": 1, "wildcard": 1, "unbound": 2, "base64": 1}
        },
        {
            "url": os.getenv('PHISHING_30DAY_URL'),
            "description": "nrd-phishing-30day",
            "split_logic": {"domains-only": 1, "adblock": 1, "wildcard": 1, "unbound": 3, "base64": 1}
        },
        {
            "url": os.getenv('PHISHING_14DAY_URL'),
            "description": "nrd-phishing-14day",
            "split_logic": {"domains-only": 1, "adblock": 1, "wildcard": 1, "unbound": 2, "base64": 1}
        }
    ]
    temp_dir = 'temp'
    output_dir = 'output'
    etag_file = 'etags.json'

    os.makedirs(temp_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    for entry in urls:
        url, description, split_logic = entry["url"], entry["description"], entry["split_logic"]
        temp_file = os.path.join(temp_dir, os.path.basename(url))

        if not url or not download_file_if_etag_changed(url, temp_file, etag_file):
            continue

        largest_file = extract_largest_file_from_tar_gz(temp_file, temp_dir)
        if largest_file:
            decode_file(largest_file, output_dir, description, split_logic, additional_domains, valid_tlds)

    shutil.rmtree(temp_dir)

if __name__ == '__main__':
    process_files_with_additional_source()
