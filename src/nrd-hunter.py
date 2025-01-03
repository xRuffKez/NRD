import os
import tarfile
import base64
import requests
import re
import json
import shutil
import idna
from datetime import datetime

def download_file_if_etag_changed(url, dest, etag_file):
    response = requests.head(url)
    if response.status_code != 200:
        print(f"Failed to access {url}")
        return False

    etag = response.headers.get('ETag')
    if not etag:
        print(f"No ETag found for {url}, proceeding with download.")
        etag = None

    if os.path.exists(etag_file):
        with open(etag_file, 'r', encoding='utf-8') as f:
            saved_etags = json.load(f)
    else:
        saved_etags = {}

    if saved_etags.get(url) == etag:
        print(f"ETag for {url} has not changed. Skipping download.")
        return False

    print(f"Downloading {url} as ETag has changed or no ETag was found.")
    response = requests.get(url, stream=True)
    if response.status_code == 200:
        with open(dest, 'wb') as f:
            for chunk in response.iter_content(1024):
                f.write(chunk)
        print(f"Downloaded file saved as: {dest}")
        if etag:
            saved_etags[url] = etag
            with open(etag_file, 'w', encoding='utf-8') as f:
                json.dump(saved_etags, f)
        return True
    else:
        print(f"Failed to download {url}")
        return False

def extract_tar_gz(file_path, dest_dir):
    try:
        with tarfile.open(file_path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.isfile() and not member.name.endswith('.rules') and member.name != 'COPYRIGHT':
                    member.name = os.path.basename(member.name)
                    tar.extract(member, dest_dir)
            print(f"Successfully extracted {file_path}")
            print("Extracted files:")
            for member in tar.getmembers():
                print(member.name)
    except Exception as e:
        print(f"Failed to extract {file_path}: {e}")

def decode_base64(encoded_str):
    decoded_bytes = base64.b64decode(encoded_str)
    return decoded_bytes.decode('utf-8')

def encode_base64(string):
    return base64.b64encode(string.encode('utf-8')).decode('utf-8')

def extract_domains(decoded_str):
    domain_pattern = r'(?<!@)(?:[\w-]+\.)+[a-zA-Z]{2,}(?!\.)'
    raw_domains = re.findall(domain_pattern, decoded_str)
    punycoded_domains = set()

    for domain in raw_domains:
        try:
            punycoded_domains.add(idna.encode(domain).decode('ascii'))
        except idna.IDNAError:
            # If conversion fails, fallback to the original domain
            punycoded_domains.add(domain)

    return list(punycoded_domains)

def write_header(outfile, description, num_entries=0):
    now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    header = (
        f"# {description}\n"
        f"# Author: xRuffKez\n"
        f"# Time of Compilation: {now}\n"
        f"# Number of entries: {num_entries}\n"
        f"#\n"
    )
    outfile.write(header)

def decode_file(input_file, output_file, adblock_output_file, wildcard_output_file, unbound_output_file, base64_output_file, description):
    try:
        with open(input_file, 'r', encoding='utf-8', errors='replace') as infile:
            domains = set()
            for line in infile:
                encoded_str = line.strip()
                if encoded_str:
                    decoded_str = decode_base64(encoded_str)
                    domains.update(extract_domains(decoded_str))

        num_entries = len(domains)

        with open(output_file, 'w', encoding='utf-8') as outfile, \
             open(adblock_output_file, 'w', encoding='utf-8') as adblock_outfile, \
             open(wildcard_output_file, 'w', encoding='utf-8') as wildcard_outfile, \
             open(unbound_output_file, 'w', encoding='utf-8') as unbound_outfile, \
             open(base64_output_file, 'w', encoding='utf-8') as base64_outfile:

            write_header(outfile, description, num_entries)
            write_header(adblock_outfile, description + " (Adblock format)", num_entries)
            write_header(wildcard_outfile, description + " (Wildcard format)", num_entries)
            write_header(unbound_outfile, description + " (Unbound format)", num_entries)
            write_header(base64_outfile, description + " (Base64 format)", num_entries)

            for domain in sorted(domains):
                outfile.write(domain + '\n')
                adblock_outfile.write(f'||{domain}^\n')
                wildcard_outfile.write(f'*.{domain}\n')
                unbound_outfile.write(f'local-zone: "{domain}" static\n')
                base64_outfile.write(f'{encode_base64(domain)}\n')
        print(f"Decoded and saved data to {output_file}, {adblock_output_file}, {wildcard_output_file}, {unbound_output_file}, {base64_output_file}")
    except UnicodeDecodeError as e:
        print(f"Error decoding file {input_file}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while processing {input_file}: {e}")

def split_into_two_files(input_file):
    part_files = []
    try:
        with open(input_file, 'r', encoding='utf-8') as infile:
            lines = infile.readlines()
        
        halfway = len(lines) // 2
        base_name = os.path.splitext(input_file)[0]
        
        part1 = base_name + "_part1.txt"
        part2 = base_name + "_part2.txt"
        
        with open(part1, 'w', encoding='utf-8') as outfile:
            write_header(outfile, f"Part 1 of 2", num_entries=len(lines[:halfway]))
            outfile.writelines(lines[:halfway])
        part_files.append(part1)
        
        with open(part2, 'w', encoding='utf-8') as outfile:
            write_header(outfile, f"Part 2 of 2", num_entries=len(lines[halfway:]))
            outfile.writelines(lines[halfway:])
        part_files.append(part2)
        
        print(f"Split {input_file} into {part1} and {part2}")

        os.remove(input_file)
        print(f"Removed original file: {input_file}")
    except Exception as e:
        print(f"Failed to split {input_file}: {e}")
    
    return part_files

def split_into_three_files(input_file):
    part_files = []
    try:
        with open(input_file, 'r', encoding='utf-8') as infile:
            lines = infile.readlines()
        
        third = len(lines) // 3
        base_name = os.path.splitext(input_file)[0]
        
        part1 = base_name + "_part1.txt"
        part2 = base_name + "_part2.txt"
        part3 = base_name + "_part3.txt"
        
        with open(part1, 'w', encoding='utf-8') as outfile:
            write_header(outfile, f"Part 1 of 3", num_entries=len(lines[:third]))
            outfile.writelines(lines[:third])
        part_files.append(part1)
        
        with open(part2, 'w', encoding='utf-8') as outfile:
            write_header(outfile, f"Part 2 of 3", num_entries=len(lines[third:2*third]))
            outfile.writelines(lines[third:2*third])
        part_files.append(part2)
        
        with open(part3, 'w', encoding='utf-8') as outfile:
            write_header(outfile, f"Part 3 of 3", num_entries=len(lines[2*third:]))
            outfile.writelines(lines[2*third:])
        part_files.append(part3)
        
        print(f"Split {input_file} into {part1}, {part2}, and {part3}")

        os.remove(input_file)
        print(f"Removed original file: {input_file}")
    except Exception as e:
        print(f"Failed to split {input_file}: {e}")
    
    return part_files

def process_files():
    urls = [
        {"url": os.getenv('NORDOMAIN_30DAY_URL'), "description": "30-day Domain List", "expected_file": "nrd-30day"},
        {"url": os.getenv('NORDOMAIN_14DAY_URL'), "description": "14-day Domain List", "expected_file": "nrd-14day"},
        {"url": os.getenv('PHISHING_30DAY_URL'), "description": "30-day Phishing Domain List", "expected_file": "nrd-phishing-30day"},
        {"url": os.getenv('PHISHING_14DAY_URL'), "description": "14-day Phishing Domain List", "expected_file": "nrd-phishing-14day"}
    ]
    
    
    temp_dir = 'temp'
    output_dir = 'output'
    etag_file = 'etags.json'
    os.makedirs(temp_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    output_files = set()
    split_files = set()

    for entry in urls:
        url = entry["url"]
        description = entry["description"]
        expected_file = entry["expected_file"]
        file_name = os.path.join(temp_dir, url.split('/')[-1])
        
        if not download_file_if_etag_changed(url, file_name, etag_file):
            continue
        
        try:
            extract_tar_gz(file_name, temp_dir)
        except Exception as e:
            print(f"Failed to extract {file_name}: {e}")
            continue

        input_file = os.path.join(temp_dir, expected_file)
        output_file = os.path.join(output_dir, f"{expected_file}.txt")
        adblock_output_file = os.path.join(output_dir, f"{expected_file}_adblock.txt")
        wildcard_output_file = os.path.join(output_dir, f"{expected_file}_wildcard.txt")
        unbound_output_file = os.path.join(output_dir, f"{expected_file}_unbound.txt")
        base64_output_file = os.path.join(output_dir, f"{expected_file}_base64.txt")

        if not os.path.exists(input_file):
            print(f"Expected input file {input_file} not found.")
            continue
        
        try:
            decode_file(input_file, output_file, adblock_output_file, wildcard_output_file, unbound_output_file, base64_output_file, description)
        except Exception as e:
            print(f"Failed to decode {input_file}: {e}")
            continue
        
        files_to_split = [
            (output_file, "default"),
            (adblock_output_file, "default"),
            (wildcard_output_file, "default"),
            (base64_output_file, "default"),
            (unbound_output_file, "default")
        ]

        for file, split_option in files_to_split:
            if os.path.exists(file):
                try:
                    print(f"Processing {file} for splitting.")
                    if "unbound" in file:
                        if "30day" in file:
                            part_files = split_into_three_files(file)
                        else:
                            part_files = split_into_two_files(file)
                    else:
                        if file not in [output_file, adblock_output_file, wildcard_output_file, base64_output_file] or ("14day" not in file and "phishing" not in file):
                            part_files = split_into_two_files(file)
                        else:
                            part_files = [file]

                    output_files.update(part_files)
                    split_files.update(part_files)
                except Exception as e:
                    print(f"Failed to split {file}: {e}")
            else:
                print(f"File not found, cannot split: {file}")
    
    shutil.rmtree(temp_dir)

    return [os.path.basename(f) for f in output_files if '.' in f]

if __name__ == '__main__':
    decoded_files = process_files()

    print("Files processed successfully.")
    print(f"Generated files: {decoded_files}")
