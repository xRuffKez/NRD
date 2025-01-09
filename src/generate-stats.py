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

def plot_stats(stats, output_path):
    """Plots statistics and saves them as an image."""
    labels = list(stats.keys())
    values = list(stats.values())

    plt.figure(figsize=(12, 6))

    # Bar Chart
    plt.bar(labels, values, color='skyblue')
    plt.title('Top 10 TLDs')
    plt.ylabel('Count')
    plt.xlabel('TLD')
    plt.xticks(rotation=45)

    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()

def generate_stats(base_dir, output_image):
    """Generates and visualizes statistics from domain-only files."""
    sources = [
        {"name": "30-day", "file": os.path.join(base_dir, "nrd-30day.txt")},
        {"name": "30-day Phish", "file": os.path.join(base_dir, "nrd-phishing-30day.txt")},
        {"name": "14-day", "file": os.path.join(base_dir, "nrd-14day.txt")},
        {"name": "14-day Phish", "file": os.path.join(base_dir, "nrd-phishing-14day.txt")}
    ]

    stats = {}
    yesterday_stats = {}
    for source in sources:
        today_domains = read_domains(source["file"])
        yesterday_file = source["file"].replace("_stats.txt", "_yesterday_stats.txt")
        yesterday_domains = read_domains(yesterday_file)

        domain_count = len(today_domains)
        domain_change = domain_count - len(yesterday_domains)
        tld_stats = compute_tld_stats(today_domains)
        top_10_tlds = dict(tld_stats.most_common(10))

        stats[source["name"]] = {
            "count": domain_count,
            "change": domain_change,
            "top_10_tlds": top_10_tlds
        }
    
    # Visualization
    fig, axs = plt.subplots(2, 2, figsize=(16, 12))

    for i, source in enumerate(sources):
        ax = axs[i // 2, i % 2]
        source_stats = stats[source["name"]]
        
        labels = list(source_stats["top_10_tlds"].keys())
        values = list(source_stats["top_10_tlds"].values())
        
        ax.bar(labels, values, color='skyblue')
        ax.set_title(f"{source['name']} - Top 10 TLDs")
        ax.set_ylabel('Count')
        ax.set_xlabel('TLD')
        ax.set_xticks(range(len(labels)))
        ax.set_xticklabels(labels, rotation=45)
        ax.grid(axis='y', linestyle='--', alpha=0.7)

    plt.tight_layout()
    plt.savefig(output_image)
    plt.close()
    print(f"Statistics image saved to {output_image}")

if __name__ == "__main__":
    base_dir = "./output"  # Directory containing domain-only files
    output_image = "stats.png"  # Output image for the README
    generate_stats(base_dir, output_image)
