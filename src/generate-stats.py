import os
import matplotlib.pyplot as plt
from collections import Counter

def read_domains(file_path):
    """Reads domains from a file and returns them as a set."""
    if not os.path.exists(file_path):
        return set()
    with open(file_path, 'r', encoding='utf-8') as f:
        return set(line.strip() for line in f if line.strip())

def compute_tld_stats(domains):
    """Counts the occurrences of each TLD in the domain set."""
    tlds = [domain.split('.')[-1].lower() for domain in domains]
    return Counter(tlds)

def generate_stats(base_dir, output_image):
    """Generates and visualizes statistics from domain-only files."""
    sources = [
        {"name": "30-day", "file": os.path.join(base_dir, "nrd-30day.txt")},
        {"name": "30-day Phish", "file": os.path.join(base_dir, "nrd-phishing-30day.txt")},
        {"name": "14-day", "file": os.path.join(base_dir, "nrd-14day.txt")},
        {"name": "14-day Phish", "file": os.path.join(base_dir, "nrd-phishing-14day.txt")}
    ]

    stats = {}
    valid_sources = []

    for source in sources:
        domains = read_domains(source["file"])
        if domains:  # Only include files with data
            tld_stats = compute_tld_stats(domains)
            stats[source["name"]] = dict(tld_stats.most_common(10))
            valid_sources.append(source)

    if not valid_sources:
        print("No valid data found. No graphs will be generated.")
        return

    # Visualization
    num_sources = len(valid_sources)
    fig, axs = plt.subplots(num_sources, 1, figsize=(12, 5 * num_sources))

    if num_sources == 1:  # Handle single subplot case
        axs = [axs]

    for i, source in enumerate(valid_sources):
        ax = axs[i]
        source_name = source["name"]
        tld_stats = stats[source_name]

        labels = list(tld_stats.keys())
        values = list(tld_stats.values())

        ax.bar(labels, values, color='skyblue')
        ax.set_title(f"{source_name} - Top 10 TLDs", fontsize=14)
        ax.set_ylabel('Count', fontsize=12)
        ax.set_xlabel('TLD', fontsize=12)
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=45, fontsize=10)
        ax.grid(axis='y', linestyle='--', alpha=0.7)

        # Add numerical annotations
        for x, y in enumerate(values):
            ax.text(x, y + max(values) * 0.01, str(y), ha='center', fontsize=10)

    plt.tight_layout()
    plt.savefig(output_image)
    plt.close()
    print(f"Statistics image saved to {output_image}")

if __name__ == "__main__":
    base_dir = "./output"  # Directory containing domain-only files
    output_image = "stats.png"  # Output image for the README
    generate_stats(base_dir, output_image)
