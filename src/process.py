import os
import tarfile
import base64
import requests
import re
import json
import shutil
import idna

def download_file(url, dest):
    """Download a file from the URL and save it to the destination path."""
    response = requests.get(url, stream=True)
    if response.status_code == 200:
        with open(dest, 'wb') as f:
            for chunk in response.iter_content(1024):
                f.write(chunk)
        print(f"Downloaded file saved as: {dest}")
        return True
    else:
        print(f"Failed to download {url} (status code: {response.status_code})")
        return False

def extract_tar_gz(file_path, dest_dir):
    """Extract .tar.gz files to the specified destination directory."""
    try:
        with tarfile.open(file_path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.isfile() and not member.name.endswith('.rules') and member.name != 'COPYRIGHT':
                    member.name = os.path.basename(member.name)
                    tar.extract(member, dest_dir)
            print(f"Successfully extracted {file_path}")
    except Exception as e:
        print(f"Failed to extract {file_path}: {e}")

def decode_base64(encoded_str):
    """Decode a Base64 encoded string."""
    decoded_bytes = base64.b64decode(encoded_str)
    return decoded_bytes.decode('utf-8')

def encode_base64(string):
    """Encode a string into Base64."""
    return base64.b64encode(string.encode('utf-8')).decode('utf-8')

def extract_domains(decoded_str):
    """Extract domains from a decoded string."""
    domain_pattern = r'(?<!@)(?:[\w-]+\.)+[a-zA-Z]{2,}(?!\.)'
    raw_domains = re.findall(domain_pattern, decoded_str)
    punycoded_domains = set()

    for domain in raw_domains:
        try:
            punycoded_domains.add(idna.encode(domain).decode('ascii'))
        except idna.IDNAError:
            punycoded_domains.add(domain)

    return list(punycoded_domains)

def decode_file(input_file, output_files, description, exclusions):
    """Decode Base64 lines in the input file and save results in various formats."""
    try:
        domains = set()
        with open(input_file, 'r', encoding='utf-8', errors='replace') as infile:
            for line in infile:
                encoded_str = line.strip()
                if encoded_str:
                    decoded_str = decode_base64(encoded_str)
                    extracted_domains = extract_domains(decoded_str)
                    filtered_domains = [d for d in extracted_domains if d not in exclusions]
                    domains.update(filtered_domains)

        with open(output_files['default'], 'w', encoding='utf-8') as outfile, \
             open(output_files['adblock'], 'w', encoding='utf-8') as adblock_outfile, \
             open(output_files['wildcard'], 'w', encoding='utf-8') as wildcard_outfile, \
             open(output_files['unbound'], 'w', encoding='utf-8') as unbound_outfile, \
             open(output_files['base64'], 'w', encoding='utf-8') as base64_outfile:
            for domain in sorted(domains):
                outfile.write(domain + '\n')
                adblock_outfile.write(f'||{domain}^\n')
                wildcard_outfile.write(f'*.{domain}\n')
                unbound_outfile.write(f'local-zone: "{domain}" static\n')
                base64_outfile.write(f'{encode_base64(domain)}\n')

        print(f"Decoded and saved data for {description}")
    except Exception as e:
        print(f"Error processing {input_file}: {e}")

def load_exclusions(exclusion_dir='lists', exclusion_filename='exclusions'):
    """Load exclusions from a file."""
    exclusion_file = os.path.join(exclusion_dir, exclusion_filename)
    try:
        with open(exclusion_file, 'r', encoding='utf-8') as f:
            exclusions = {line.strip() for line in f if line.strip() and not line.startswith('#')}
        print(f"Loaded {len(exclusions)} exclusions from {exclusion_file}")
        return exclusions
    except FileNotFoundError:
        print(f"Exclusion file {exclusion_file} not found. No exclusions applied.")
        return set()
    except Exception as e:
        print(f"Failed to load exclusions from {exclusion_file}: {e}")
        return set()

def process_files():
    """Main function to process files from URLs."""
    exclusion_dir = 'lists'
    exclusion_filename = 'exclusions'
    exclusions = load_exclusions(exclusion_dir, exclusion_filename)
    
    urls = [
        {"url": os.getenv('NORDOMAIN_30DAY_URL'), "description": "30-day Domain List", "expected_file": "nrd-30day"},
        {"url": os.getenv('NORDOMAIN_14DAY_URL'), "description": "14-day Domain List", "expected_file": "nrd-14day"},
        {"url": os.getenv('PHISHING_30DAY_URL'), "description": "30-day Phishing Domain List", "expected_file": "nrd-phishing-30day"},
        {"url": os.getenv('PHISHING_14DAY_URL'), "description": "14-day Phishing Domain List", "expected_file": "nrd-phishing-14day"}
    ]
    
    temp_dir = 'temp'
    output_dir = 'output'
    os.makedirs(temp_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    for entry in urls:
        url = entry["url"]
        description = entry["description"]
        expected_file = entry["expected_file"]
        file_name = os.path.join(temp_dir, os.path.basename(url))
        
        if not download_file(url, file_name):
            continue
        
        try:
            extract_tar_gz(file_name, temp_dir)
        except Exception as e:
            print(f"Failed to extract {file_name}: {e}")
            continue

        input_file = os.path.join(temp_dir, expected_file)
        if not os.path.exists(input_file):
            print(f"Expected input file {input_file} not found.")
            continue

        output_files = {
            "default": os.path.join(output_dir, f"{expected_file}.txt"),
            "adblock": os.path.join(output_dir, f"{expected_file}_adblock.txt"),
            "wildcard": os.path.join(output_dir, f"{expected_file}_wildcard.txt"),
            "unbound": os.path.join(output_dir, f"{expected_file}_unbound.txt"),
            "base64": os.path.join(output_dir, f"{expected_file}_base64.txt")
        }

        decode_file(input_file, output_files, description, exclusions)
    
    shutil.rmtree(temp_dir)
    print("Processing completed.")

if __name__ == '__main__':
    process_files()
