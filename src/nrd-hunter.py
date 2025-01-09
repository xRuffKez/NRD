import os
import base64
import requests
import re
import json
import shutil
import tarfile
from datetime import datetime
import logging
import idna

logging.basicConfig(level=logging.INFO)

def fetch_valid_tlds():
    tld_url = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
    try:
        response = requests.get(tld_url)
        if response.status_code == 200:
            tlds = {line.strip().lower() for line in response.text.splitlines() if line and not line.startswith("#")}
            if tlds:
                logging.info(f"Fetched {len(tlds)} valid TLDs.")
                return tlds
    except Exception as e:
        logging.error(f"Error fetching TLD list: {e}")
    
    # Fallback TLDs
    fallback_tlds = {"com", "org", "net", "edu", "gov", "info"}
    logging.warning(f"Using fallback TLDs: {fallback_tlds}")
    return fallback_tlds

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
            # Identify the largest file in the archive
            largest_file = max(
                (member for member in tar.getmembers() if member.isfile()),
                key=lambda member: member.size,
                default=None,
            )

            if not largest_file:
                logging.warning(f"No files found in archive: {file_path}")
                return None

            # Set the extraction path
            extracted_file_path = os.path.join(dest_dir, largest_file.name)
            tar.extract(largest_file, dest_dir)  # Extract without "ExtractPolicy"
            logging.info(f"Extracted the largest file: {largest_file.name} ({largest_file.size} bytes)")
            return extracted_file_path
    except Exception as e:
        logging.error(f"Error extracting the largest file from {file_path}: {e}")
        return None

def write_output_files(domains, output_dir, description, split_logic):
    """Writes domain data in various formats and splits files if needed."""
    formats = {
        "adblock": lambda domain: f"||{domain}^",
        "wildcard": lambda domain: f"*.{domain}",
        "unbound": lambda domain: f'local-zone: "{domain}" static',
        "base64": lambda domain: base64.b64encode(domain.encode('utf-8')).decode('utf-8')
    }

    # Ensure the output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Generate the base file for domains without renaming to _domains-only
    base_file = os.path.join(output_dir, f"{description}.txt")
    try:
        with open(base_file, 'w', encoding='utf-8') as f:
            for domain in sorted(domains):
                punycode_domain = idna.encode(domain).decode('ascii')
                f.write(f"{punycode_domain}\n")
        logging.info(f"Generated base file: {base_file}")
    except Exception as e:
        logging.error(f"Failed to write base file: {e}")

    # Split the domains-only file if needed
    if split_logic.get("domains-only", 1) > 1:
        split_files = split_file(base_file, split_logic["domains-only"])
        logging.info(f"Split domains file into: {split_files}")

    # Generate files for each additional format
    for fmt, transform in formats.items():
        filename = os.path.join(output_dir, f"{description}_{fmt}.txt")
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                now = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
                f.write(f"# {description} ({fmt})\n# Generated on {now}\n")
                for domain in sorted(domains):
                    punycode_domain = idna.encode(domain).decode('ascii')
                    f.write(f"{transform(punycode_domain)}\n")
            logging.info(f"Generated file: {filename}")

            # Split the file for the format if needed
            num_parts = split_logic.get(fmt, 1)
            if num_parts > 1:
                split_files = split_file(filename, num_parts)
                logging.info(f"Split {fmt} file into: {split_files}")
        except Exception as e:
            logging.error(f"Failed to write {fmt} file: {e}")

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
    try:
        if len(domain) < 1 or len(domain) > 253:
            return False

        labels = domain.split('.')
        
        for label in labels[:-1]:
            if len(label) < 1 or len(label) > 63 or label.startswith('-') or label.endswith('-'):
                return False
            
            if len(label) > 3 and label[2] == '-' and label[3] == '-':
                return False
            
            if not re.match(r'^[a-zA-Z0-9\u00C0-\u017F\u0400-\u04FF\u0530-\u058F\u0590-\u05FF\u0600-\u06FF\u0900-\u097F\u1E00-\u1EFF-]+$', label):
                return False

        # Validate the TLD (last label)
        tld = labels[-1]
        if len(tld) < 2 or len(tld) > 6 or not re.match(r'^[a-zA-Z]+$', tld):
            return False

        return True
    except Exception:
        return False

def decode_file(input_file, output_dir, description, split_logic, additional_domains=None, valid_tlds=None):
    try:
        with open(input_file, 'r', encoding='utf-8', errors='replace') as infile:
            domains = set()
            for line in infile:
                try:
                    decoded_str = base64.b64decode(line.strip()).decode('utf-8')
                    extracted_domains = re.findall(r'(?<!@)(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}', decoded_str)
                    valid_domains = {d for d in extracted_domains if is_valid_label(d)}
                    domains.update(valid_domains)
                except Exception:
                    logging.warning(f"Failed to decode line: {line.strip()[:50]}...")
        
        # Apply TLD and additional domain filtering
        if valid_tlds:
            domains = filter_domains(domains, valid_tlds)
        if additional_domains and description == "nrd-30day":
            domains.update(additional_domains)
        domains = {d for d in domains if is_valid_label(d)}

        if domains:
            write_output_files(domains, output_dir, description, split_logic)
        else:
            logging.warning(f"No valid domains found in file {input_file}. Skipping output generation.")
    except Exception as e:
        logging.error(f"Error decoding file {input_file}: {e}")

def process_files_with_additional_source():
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
    try:
        process_files_with_additional_source()
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
