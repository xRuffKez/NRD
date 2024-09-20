import os
import tarfile
import base64
import requests
import re
import shutil

def download_file(url, dest):
    response = requests.get(url, stream=True)
    if response.status_code == 200:
        with open(dest, 'wb') as f:
            for chunk in response.iter_content(1024):
                f.write(chunk)
        print(f"Downloaded file saved as: {dest}")
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
    except Exception as e:
        print(f"Failed to extract {file_path}: {e}")

def decode_base64(encoded_str):
    decoded_bytes = base64.b64decode(encoded_str)
    return decoded_bytes.decode('utf-8')

def encode_base64(string):
    return base64.b64encode(string.encode('utf-8')).decode('utf-8')

def extract_domains(decoded_str):
    domain_pattern = r'(?<!@)(?:[\w-]+\.)+[a-zA-Z]{2,}(?!\.)'
    return re.findall(domain_pattern, decoded_str)

def decode_file(input_file, output_file, adblock_output_file, wildcard_output_file, unbound_output_file, base64_output_file):
    try:
        with open(input_file, 'r', encoding='utf-8', errors='replace') as infile:
            domains = set()
            for line in infile:
                encoded_str = line.strip()
                if encoded_str:
                    decoded_str = decode_base64(encoded_str)
                    domains.update(extract_domains(decoded_str))

        with open(output_file, 'w', encoding='utf-8') as outfile, \
             open(adblock_output_file, 'w', encoding='utf-8') as adblock_outfile, \
             open(wildcard_output_file, 'w', encoding='utf-8') as wildcard_outfile, \
             open(unbound_output_file, 'w', encoding='utf-8') as unbound_outfile, \
             open(base64_output_file, 'w', encoding='utf-8') as base64_outfile:

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
            outfile.writelines(lines[:halfway])
        part_files.append(part1)
        
        with open(part2, 'w', encoding='utf-8') as outfile:
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
            outfile.writelines(lines[:third])
        part_files.append(part1)
        
        with open(part2, 'w', encoding='utf-8') as outfile:
            outfile.writelines(lines[third:2*third])
        part_files.append(part2)
        
        with open(part3, 'w', encoding='utf-8') as outfile:
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
    os.makedirs(temp_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    output_files = set()
    split_files = set()

    for entry in urls:
        url = entry["url"]
        description = entry["description"]
        expected_file = entry["expected_file"]
        file_name = os.path.join(temp_dir, url.split('/')[-1])
        
        if not download_file(url, file_name):
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
            decode_file(input_file, output_file, adblock_output_file, wildcard_output_file, unbound_output_file, base64_output_file)
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
                        part_files = split_into_two_files(file)

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
