import os
import tarfile
import base64
import requests
import re
import json
import shutil
import idna
from datetime import datetime

def download_file(url, dest):
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        with open(dest, 'wb') as f:
            for chunk in response.iter_content(1024):
                f.write(chunk)
        print(f"Downloaded: {dest}")
        return True
    except Exception as e:
        print(f"Error downloading {url}: {e}")
        return False
def extract_tar_gz(file_path, dest_dir):
    try:
        with tarfile.open(file_path, "r:gz") as tar:
            for member in tar.getmembers():
                if "rules" in member.name and not member.name.endswith('.rules'):
                    tar.extract(member, path=dest_dir)
                elif member.isfile() and not (member.name.endswith('.rules') or member.name == 'COPYRIGHT'):
                    tar.extract(member, path=dest_dir)
        print(f"Extracted: {file_path}")
    except Exception as e:
        print(f"Failed to extract {file_path}: {e}")

def decode_base64(encoded_str):
    return base64.b64decode(encoded_str).decode('utf-8')

def encode_base64(string):
    return base64.b64encode(string.encode('utf-8')).decode('utf-8')

def extract_domains(decoded_str):
    domain_pattern = r'(?<!@)(?:[\w-]+\.)+[a-zA-Z]{2,}(?!\.)'
    raw_domains = re.findall(domain_pattern, decoded_str)
    return list({idna.encode(domain).decode('ascii') if not idna.IDNAError else domain for domain in raw_domains})

def process_decoded_domains(input_file, exclusions, output_files):
    domains = set()
    with open(input_file, 'r', encoding='utf-8', errors='replace') as infile:
        for line in infile:
            decoded_str = decode_base64(line.strip())
            extracted_domains = extract_domains(decoded_str)
            domains.update(d for d in extracted_domains if d not in exclusions)
    
    with open(output_files['txt'], 'w', encoding='utf-8') as outfile:
        for domain in sorted(domains):
            outfile.write(f"{domain}\n")

            for key, template in output_files['templates'].items():
                with open(output_files[key], 'a', encoding='utf-8') as f:
                    f.write(template.format(domain))

def load_exclusions(exclusion_dir='lists', exclusion_filename='exclusion'):
    exclusion_file = os.path.join(exclusion_dir, exclusion_filename)
    try:
        with open(exclusion_file, 'r', encoding='utf-8') as f:
            exclusions = {line.strip() for line in f if line.strip() and not line.startswith('#')}
        return exclusions
    except Exception as e:
        print(f"Error loading exclusions: {e}")
        return set()

def split_file(input_file, parts=2):
    try:
        with open(input_file, 'r', encoding='utf-8') as infile:
            lines = infile.readlines()
        part_size = len(lines) // parts
        base_name = os.path.splitext(input_file)[0]
        return [write_split_file(base_name, lines[i * part_size:(i + 1) * part_size]) for i in range(parts)]
    except Exception as e:
        print(f"Error splitting {input_file}: {e}")
        return []

def write_split_file(base_name, lines):
    part_file = f"{base_name}_part{len(os.path.splitext(base_name))}.txt"
    with open(part_file, 'w', encoding='utf-8') as f:
        f.writelines(lines)
    return part_file

def process_files():
    exclusions = load_exclusions()
    urls = [
        {"url": os.getenv('NORDOMAIN_30DAY_URL'), "expected_file": "nrd-30day"},
        {"url": os.getenv('NORDOMAIN_14DAY_URL'), "expected_file": "nrd-14day"},
        {"url": os.getenv('PHISHING_30DAY_URL'), "expected_file": "nrd-phishing-30day"},
        {"url": os.getenv('PHISHING_14DAY_URL'), "expected_file": "nrd-phishing-14day"}
    ]
    
    temp_dir, output_dir = 'temp', 'output'
    os.makedirs(temp_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    for entry in urls:
        url, expected_file = entry['url'], entry['expected_file']
        file_name = os.path.join(temp_dir, os.path.basename(url.split('?')[0]))
        
        if not url or not download_file(url, file_name):
            continue
        
        extract_tar_gz(file_name, temp_dir)
        input_file = os.path.join(temp_dir, expected_file)
        
        if not os.path.exists(input_file):
            print(f"File {input_file} not found.")
            continue
        
        output_files = {key: os.path.join(output_dir, f"{expected_file}_{key}.txt") for key in ['txt', 'adblock', 'wildcard', 'unbound', 'base64']}
        output_files['templates'] = {
            'adblock': '||{}^\n',
            'wildcard': '*.{}\n',
            'unbound': 'local-zone: "{}" static\n',
            'base64': '{}\n'
        }
        process_decoded_domains(input_file, exclusions, output_files)
        
        for output_file in output_files.values():
            if "unbound" in output_file:
                split_file(output_file, 3)
            else:
                split_file(output_file, 2)

    shutil.rmtree(temp_dir)

if __name__ == '__main__':
    process_files()
    print("Processing complete.")

  
