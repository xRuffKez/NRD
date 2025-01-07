import os
import tarfile
import base64
import requests
import re
import json
import shutil
from datetime import datetime
import logging

# Setup logging
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
    response = requests.get(url, stream=True)
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
        "domains-only": lambda domain: domain,
        "adblock": lambda domain: f"||{domain}^",
        "wildcard": lambda domain: f"*.{domain}",
        "unbound": lambda domain: f'local-zone: "{domain}" static',
        "base64": lambda domain: encode_base64(domain)
    }

    # Write the plain domains-only file without a suffix
    base_file = os.path.join(output_dir, f"{description}.txt")
    with open(base_file, 'w', encoding='utf-8') as f:
        for domain in sorted(domains):
            f.write(f"{domain}\n")

    # Write other formats and split if required
    for fmt, transform in formats.items():
        # Skip "domains-only" since it already has its plain file
        if fmt == "domains-only":
            continue

        filename = os.path.join(output_dir, f"{description}_{fmt}.txt")
        with open(filename, 'w', encoding='utf-8') as f:
            write_header(f, f"{description} ({fmt})", len(domains))
            for domain in sorted(domains):
                f.write(f"{transform(domain)}\n")

        # Determine number of parts based on splitting logic
        num_parts = split_logic.get(fmt, 1)
        if num_parts > 1:
            split_files = split_file(filename, num_parts)
            logging.info(f"Split files generated for {fmt}: {split_files}")


def decode_file(input_file, output_dir, description, split_logic):
    try:
        with open(input_file, 'r', encoding='utf-8', errors='replace') as infile:
            domains = set()
            for line in infile:
                decoded_str = decode_base64(line.strip())
                if decoded_str:
                    domains.update(extract_domains(decoded_str))

        if not domains:
            logging.warning(f"No valid domains found in file {input_file}. Skipping output generation.")
            return

        write_output_files(domains, output_dir, description, split_logic)
    except Exception as e:
        logging.error(f"Error decoding file {input_file}: {e}")


def process_files_with_additional_source():
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
            decode_file(largest_file, output_dir, description, split_logic)

    shutil.rmtree(temp_dir)


if __name__ == '__main__':
    process_files_with_additional_source()
