import os
import tarfile
import base64
import requests
import re
import json
import shutil
from datetime import datetime

def download_file_if_etag_changed(url, dest, etag_file):
    response = requests.head(url)
    etag = response.headers.get('ETag')
    if os.path.exists(etag_file):
        with open(etag_file, 'r', encoding='utf-8') as f:
            saved_etags = json.load(f)
    else:
        saved_etags = {}
    if saved_etags.get(url) == etag:
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
    return False

def extract_tar_gz(file_path, dest_dir):
    try:
        with tarfile.open(file_path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.isfile() and not member.name.endswith('.rules') and member.name != 'COPYRIGHT':
                    member.name = os.path.basename(member.name)
                    tar.extract(member, dest_dir)
    except Exception: pass

def decode_base64(encoded_str):
    return base64.b64decode(encoded_str).decode('utf-8')

def encode_base64(string):
    return base64.b64encode(string.encode('utf-8')).decode('utf-8')

def extract_domains(decoded_str):
    return list(set(re.findall(r'(?<!@)(?:[\w-]+\.)+[a-zA-Z]{2,}(?!\.)', decoded_str)))

def write_header(outfile, description, num_entries=0):
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    outfile.write(f"# {description}\n# Author: xRuffKez\n# Time of Compilation: {now}\n# Number of entries: {num_entries}\n#\n")

def decode_file(input_file, output_file, adblock_output_file, wildcard_output_file, unbound_output_file, base64_output_file, description):
    try:
        with open(input_file, 'r', encoding='utf-8', errors='replace') as infile:
            domains = set()
            for line in infile:
                decoded_str = decode_base64(line.strip())
                domains.update(extract_domains(decoded_str))
        num_entries = len(domains)
        with open(output_file, 'w', encoding='utf-8') as outfile, open(adblock_output_file, 'w', encoding='utf-8') as adblock_outfile, open(wildcard_output_file, 'w', encoding='utf-8') as wildcard_outfile, open(unbound_output_file, 'w', encoding='utf-8') as unbound_outfile, open(base64_output_file, 'w', encoding='utf-8') as base64_outfile:
            write_header(outfile, description, num_entries)
            write_header(adblock_outfile, f"{description} (Adblock format)", num_entries)
            write_header(wildcard_outfile, f"{description} (Wildcard format)", num_entries)
            write_header(unbound_outfile, f"{description} (Unbound format)", num_entries)
            write_header(base64_outfile, f"{description} (Base64 format)", num_entries)
            for domain in sorted(domains):
                outfile.write(f"{domain}\n")
                adblock_outfile.write(f"||{domain}^\n")
                wildcard_outfile.write(f"*.{domain}\n")
                unbound_outfile.write(f'local-zone: "{domain}" static\n')
                base64_outfile.write(f"{encode_base64(domain)}\n")
    except Exception: pass

def split_file(input_file):
    with open(input_file, 'r', encoding='utf-8') as infile:
        lines = infile.readlines()
    third = len(lines) // 3
    base_name = os.path.splitext(input_file)[0]
    parts = [f"{base_name}_part{i}.txt" for i in range(1, 4)]
    for i, part in enumerate(parts):
        with open(part, 'w', encoding='utf-8') as outfile:
            write_header(outfile, f"Part {i + 1} of 3", num_entries=len(lines[i * third:(i + 1) * third]))
            outfile.writelines(lines[i * third:(i + 1) * third])
    return parts

def fetch_additional_source(url, user_agent, dest_file):
    headers = {"User-Agent": user_agent}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        domains = re.findall(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]\.[a-zA-Z-]*[a-z]{2,}[a-zA-Z-]*$', response.text, re.MULTILINE)
        if domains:
            with open(dest_file, 'w', encoding='utf-8') as f:
                f.writelines(domain + '\n' for domain in sorted(set(domains)))
            return dest_file
    return None

def process_files_with_additional_source():
    urls = [
        {"url": os.getenv('NORDOMAIN_30DAY_URL'), "description": "30-day Domain List", "expected_file": "nrd-30day"},
        {"url": os.getenv('NORDOMAIN_14DAY_URL'), "description": "14-day Domain List", "expected_file": "nrd-14day"},
        {"url": os.getenv('PHISHING_30DAY_URL'), "description": "30-day Phishing Domain List", "expected_file": "nrd-phishing-30day"},
        {"url": os.getenv('PHISHING_14DAY_URL'), "description": "14-day Phishing Domain List", "expected_file": "nrd-phishing-14day"}
    ]
    user_agent = os.getenv('USER_AGENT')  # Pull User-Agent from GitHub secrets
    temp_dir = 'temp'
    output_dir = 'output'
    etag_file = 'etags.json'
    os.makedirs(temp_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)
    output_files = set()
    additional_source_url = os.getenv('ADDITIONAL_SOURCE_URL')
    additional_source_file = os.path.join(temp_dir, "additional_domains.txt")
    additional_file = fetch_additional_source(additional_source_url, user_agent, additional_source_file)
    if additional_file:
        urls.append({"url": additional_file, "description": "Additional Domain List", "expected_file": "additional-domains"})
    for entry in urls:
        url, description, expected_file = entry["url"], entry["description"], entry["expected_file"]
        file_name = os.path.join(temp_dir, os.path.basename(url) if url.startswith("http") else expected_file)
        if not url.startswith("http") or not download_file_if_etag_changed(url, file_name, etag_file):
            if not os.path.exists(file_name):
                continue
        try:
            if url.startswith("http"):
                extract_tar_gz(file_name, temp_dir)
        except Exception: pass
        input_file = os.path.join(temp_dir, expected_file)
        output_file = os.path.join(output_dir, f"{expected_file}.txt")
        adblock_output_file = os.path.join(output_dir, f"{expected_file}_adblock.txt")
        wildcard_output_file = os.path.join(output_dir, f"{expected_file}_wildcard.txt")
        unbound_output_file = os.path.join(output_dir, f"{expected_file}_unbound.txt")
        base64_output_file = os.path.join(output_dir, f"{expected_file}_base64.txt")
        if os.path.exists(input_file):
            decode_file(input_file, output_file, adblock_output_file, wildcard_output_file, unbound_output_file, base64_output_file, description)
            files_to_split = [output_file, adblock_output_file, wildcard_output_file, base64_output_file, unbound_output_file]
            for file in files_to_split:
                if os.path.exists(file):
                    output_files.update(split_file(file))
    shutil.rmtree(temp_dir)
    return [os.path.basename(f) for f in output_files if '.' in f]

if __name__ == '__main__':
    decoded_files = process_files_with_additional_source()
    print(f"Generated files: {decoded_files}")
