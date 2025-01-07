import os
import tarfile
import base64
import requests
import re
import json
import shutil
from datetime import datetime
import logging


logging.basicConfig(level=logging.INFO)


def download_file_if_etag_changed(url, dest, etag_file):
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


def fetch_additional_source():
    """Fetches and returns domain data from ADDITIONAL_SOURCE_URL, excluding TLD-only domains."""
    additional_url = os.getenv("ADDITIONAL_SOURCE_URL")
    if not additional_url:
        logging.warning("No ADDITIONAL_SOURCE_URL provided.")
        return set()

    headers = {"User-Agent": os.getenv("USER_AGENT")}
    try:
        response = requests.get(additional_url, headers=headers)
        if response.status_code == 200:
            all_domains = set(re.findall(r'(?<!@)(?:[\w-]+\.)+[a-zA-Z]{2,}(?!\.)', response.text))
            filtered_domains = {
                domain for domain in all_domains
                if not re.match(r'^\.[a-zA-Z]{2,}$', domain)  # Exclude TLD-only domains (e.g., `.com`, `.top`)
            }
            logging.info(f"Fetched {len(all_domains)} domains, filtered to {len(filtered_domains)} valid domains.")
            return filtered_domains
        else:
            logging.error(f"Failed to fetch additional source. Status Code: {response.status_code}")
    except Exception as e:
        logging.error(f"Error fetching additional source: {e}")
    return set()


def extract_largest_file_from_tar_gz(file_path, dest_dir):
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


def decode_base64(encoded_str):
    try:
        return base64.b64decode(encoded_str).decode('utf-8')
    except Exception as e:
        logging.error(f"Invalid Base64 string: {encoded_str[:30]}... - {e}")
        return ""


def encode_base64(string):
    return base64.b64encode(string.encode('utf-8')).decode('utf-8')


def extract_domains(decoded_str):
    return list(set(re.findall(r'(?<!@)(?:[\w-]+\.)+[a-zA-Z]{2,}(?!\.)', decoded_str)))


def write_header(outfile, description, num_entries=0):
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    outfile.write(f"# {description}\n# Author: xRuffKez\n# Time of Compilation: {now}\n# Number of entries: {num_entries}\n#\n")


def split_file(input_file, num_parts):
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


def write_output_files(domains, output_dir, description, split_logic):
    formats = {
        "adblock": lambda domain: f"||{domain}^",
        "wildcard": lambda domain: f"*.{domain}",
        "unbound": lambda domain: f'local-zone: "{domain}" static',
        "base64": lambda domain: encode_base64(domain)
    }

    base_file = os.path.join(output_dir, f"{description}.txt")
    with open(base_file, 'w', encoding='utf-8') as f:
        for domain in sorted(domains):
            f.write(f"{domain}\n")
    logging.info(f"Generated domains-only file: {base_file}")

    if split_logic.get("domains-only", 1) > 1:
        split_files = split_file(base_file, split_logic["domains-only"])
        logging.info(f"Split domains-only file: {split_files}")

    for fmt, transform in formats.items():
        filename = os.path.join(output_dir, f"{description}_{fmt}.txt")
        with open(filename, 'w', encoding='utf-8') as f:
            write_header(f, f"{description} ({fmt})", len(domains))
            for domain in sorted(domains):
                f.write(f"{transform(domain)}\n")

        num_parts = split_logic.get(fmt, 1)
        if num_parts > 1:
            split_files = split_file(filename, num_parts)
            logging.info(f"Split files generated for {fmt}: {split_files}")


def decode_file(input_file, output_dir, description, split_logic, additional_domains=None):
    try:
        with open(input_file, 'r', encoding='utf-8', errors='replace') as infile:
            domains = set()
            for line in infile:
                decoded_str = decode_base64(line.strip())
                if decoded_str:
                    domains.update(extract_domains(decoded_str))

        if additional_domains and "30day" in description:
            initial_count = len(domains)
            domains.update(additional_domains)
            logging.info(f"Merged {len(domains) - initial_count} additional domains into {description}.")

        if not domains:
            logging.warning(f"No valid domains found in file {input_file}. Skipping output generation.")
            return

        write_output_files(domains, output_dir, description, split_logic)
    except Exception as e:
        logging.error(f"Error decoding file {input_file}: {e}")


def process_files_with_additional_source():
    additional_domains = fetch_additional_source()

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
            decode_file(largest_file, output_dir, description, split_logic, additional_domains)

    shutil.rmtree(temp_dir)


if __name__ == '__main__':
    process_files_with_additional_source()
