import math
from collections import Counter
import plotly.graph_objects as go
import plotly.io as pio
import argparse
import os

def calculate_entropy(data):
    """Calculate the Shannon entropy of a data segment."""
    if len(data) == 0:
        return 0

    # Calculate the frequency of each byte value in the data segment
    byte_counts = Counter(data)
    entropy = 0.0

    for count in byte_counts.values():
        # Calculate the probability of each byte
        p = count / len(data)
        # Apply the Shannon entropy formula
        entropy -= p * math.log2(p)

    return entropy

def analyze_firmware_entropy(file_path, chunk_size=1024):
    """Analyze the entropy of a firmware file in chunks."""
    entropy_values = []

    with open(file_path, 'rb') as file:
        offset = 0
        while chunk := file.read(chunk_size):
            entropy = calculate_entropy(chunk)
            entropy_values.append((offset, entropy))
            offset += chunk_size

    return entropy_values

def save_entropy_to_file(entropy_values, output_file):
    """Save entropy values to a text file."""
    with open(output_file, 'w') as f:
        for offset, entropy in entropy_values:
            f.write(f'Offset {offset}: Entropy = {entropy:.4f}\n')

def plot_entropy(entropy_values, output_html):
    """Plot entropy values interactively using plotly and save as HTML."""
    offsets = [offset for offset, _ in entropy_values]
    entropies = [entropy for _, entropy in entropy_values]

    fig = go.Figure()

    # Add trace for entropy
    fig.add_trace(go.Scatter(x=offsets, y=entropies, mode='lines+markers', name='Entropy'))

    # Customize layout
    fig.update_layout(
        title='Entropy Analysis of Firmware',
        xaxis_title='Offset',
        yaxis_title='Entropy',
        template='plotly_dark',
        hovermode='closest'
    )

    # Save the plot as an HTML file
    pio.write_html(fig, file=output_html, auto_open=True)

def main():
    parser = argparse.ArgumentParser(description="Analyze entropy of a firmware file.")
    parser.add_argument('file_path', type=str, help="Path to the firmware binary file.")
    parser.add_argument('--chunk_size', type=int, default=1024, help="Chunk size for entropy analysis (default: 1024 bytes).")

    args = parser.parse_args()

    # Get the base name of the input file to use in output file names
    base_name = os.path.splitext(os.path.basename(args.file_path))[0]
    output_txt = f"{base_name}_entropy.txt"
    output_html = f"{base_name}_entropy.html"

    entropy_values = analyze_firmware_entropy(args.file_path, args.chunk_size)

    # Save the entropy values to a text file
    save_entropy_to_file(entropy_values, output_txt)

    # Plot the entropy values and save as HTML
    plot_entropy(entropy_values, output_html)

if __name__ == '__main__':
    main()
