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

def fetch_tlds():
    """Fetches the list of valid TLDs from the IANA website."""
    tld_url = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
    try:
        response = requests.get(tld_url)
        if response.status_code == 200:
            tlds = {line.strip().lower() for line in response.text.splitlines() if line and not line.startswith("#")}
            logging.info(f"Fetched {len(tlds)} valid TLDs.")
            return tlds
        else:
            logging.error(f"Failed to fetch TLDs. HTTP Status Code: {response.status_code}")
    except Exception as e:
        logging.error(f"Error fetching TLD list: {e}")
    return set()

def is_valid_domain(domain, tlds):
    """Checks if a domain ends with a valid TLD."""
    match = re.search(r'\.([a-zA-Z]{2,})$', domain)
    return match and match.group(1).lower() in tlds

def filter_domains(domains, tlds):
    """Filters a set of domains to include only those with valid TLDs."""
    return {domain for domain in domains if is_valid_domain(domain, tlds)}

def fetch_additional_domains():
    """Fetches and returns domain data from an additional source."""
    additional_source_url = os.getenv("ADDITIONAL_SOURCE_URL")
    if not additional_source_url:
        logging.warning("No ADDITIONAL_SOURCE_URL provided.")
        return set()

    headers = {"User-Agent": os.getenv("USER_AGENT")}
    try:
        response = requests.get(additional_source_url, headers=headers)
        if response.status_code == 200:
            all_domains = set(re.findall(r'(?<!@)(?:[\w-]+\.)+[a-zA-Z]{2,}(?!\.)', response.text))
            logging.info(f"Fetched {len(all_domains)} domains from additional source.")
            return all_domains
        else:
            logging.error(f"Failed to fetch additional domains. HTTP Status Code: {response.status_code}")
    except Exception as e:
        logging.error(f"Error fetching additional domains: {e}")
    return set()

def download_file(url, destination):
    """Downloads a file from the specified URL."""
    logging.info(f"Downloading from URL: {url}")
    headers = {"User-Agent": os.getenv("USER_AGENT")}
    try:
        response = requests.get(url, headers=headers, stream=True)
        if response.status_code == 200:
            with open(destination, 'wb') as file:
                for chunk in response.iter_content(1024):
                    file.write(chunk)
            logging.info(f"Downloaded file to {destination}")
            return True
        else:
            logging.error(f"Failed to download file. HTTP Status Code: {response.status_code}")
    except Exception as e:
        logging.error(f"Error downloading file: {e}")
    return False

def extract_largest_tar_file(archive_path, destination_dir):
    """Extracts the largest file from a tar.gz archive."""
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            largest_file = max(
                (member for member in archive.getmembers() if member.isfile()),
                key=lambda member: member.size,
                default=None,
            )

            if not largest_file:
                logging.warning(f"No files found in archive: {archive_path}")
                return None

            largest_file.name = os.path.basename(largest_file.name)
            archive.extract(largest_file, destination_dir)
            extracted_file_path = os.path.join(destination_dir, largest_file.name)
            logging.info(f"Extracted the largest file: {largest_file.name} ({largest_file.size} bytes)")
            return extracted_file_path
    except Exception as e:
        logging.error(f"Error extracting largest file from {archive_path}: {e}")
        return None

def write_output_files(domains, output_dir, description, split_config):
    """Writes filtered domains to output files in various formats."""
    formats = {
        "adblock": lambda domain: f"||{domain}^",
        "wildcard": lambda domain: f"*.{domain}",
        "unbound": lambda domain: f'local-zone: "{domain}" static',
        "base64": lambda domain: base64.b64encode(domain.encode('utf-8')).decode('utf-8')
    }

    # Write the plain domains-only file
    plain_file = os.path.join(output_dir, f"{description}.txt")
    with open(plain_file, 'w', encoding='utf-8') as file:
        for domain in sorted(domains):
            punycode_domain = idna.encode(domain).decode('ascii')
            file.write(f"{punycode_domain}\n")
    logging.info(f"Generated plain domains file: {plain_file}")

    # Split plain domains file if required
    if split_config.get("domains-only", 1) > 1:
        split_files = split_file(plain_file, split_config["domains-only"])
        logging.info(f"Split domains-only file into {split_files}")

    # Write other formats
    for fmt, transform in formats.items():
        format_file = os.path.join(output_dir, f"{description}_{fmt}.txt")
        with open(format_file, 'w', encoding='utf-8') as file:
            now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
            file.write(f"# {description} ({fmt})\n# Generated on {now}\n")
            for domain in sorted(domains):
                punycode_domain = idna.encode(domain).decode('ascii')
                file.write(f"{transform(punycode_domain)}\n")

        # Split format files if required
        num_parts = split_config.get(fmt, 1)
        if num_parts > 1:
            split_files = split_file(format_file, num_parts)
            logging.info(f"Split {fmt} file into {split_files}")

def split_file(input_file, num_parts):
    """Splits a file into the specified number of parts."""
    try:
        with open(input_file, 'r', encoding='utf-8') as file:
            lines = file.readlines()
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

def process_file(url, description, split_config, additional_domains, tlds, temp_dir, output_dir):
    """Processes a single file for domain extraction and filtering."""
    temp_file_path = os.path.join(temp_dir, os.path.basename(url))

    if not url or not download_file(url, temp_file_path):
        return

    largest_file = extract_largest_tar_file(temp_file_path, temp_dir)
    if largest_file:
        decode_file(largest_file, output_dir, description, split_config, additional_domains, tlds)

def main():
    """Main script workflow."""
    additional_domains = fetch_additional_domains()
    tlds = fetch_tlds()

    urls = [
        {
            "url": os.getenv('NORDOMAIN_30DAY_URL'),
            "description": "nrd-30day",
            "split_config": {"domains-only": 2, "adblock": 2, "wildcard": 2, "unbound": 3, "base64": 2}
        },
        # Add other URLs and configurations here
    ]
    temp_dir = 'temp'
    output_dir = 'output'

    os.makedirs(temp_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    for entry in urls:
        process_file(entry["url"], entry["description"], entry["split_config"], additional_domains, tlds, temp_dir, output_dir)

    shutil.rmtree(temp_dir)

if __name__ == '__main__':
    main()
