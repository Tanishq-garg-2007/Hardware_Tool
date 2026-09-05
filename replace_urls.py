import os
import re

front_dir = 'c:/Users/tanis/OneDrive/Documents/IOT SECURITY/Hardware/front'

def process_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Replace "http://localhost:8000/..." with `${process.env.NEXT_PUBLIC_API_URL}/...`
    # Replace 'http://localhost:8000/...' with `${process.env.NEXT_PUBLIC_API_URL}/...`
    content = re.sub(r'[\"\']http://localhost:8000(/[^\"\']*)[\"\']', r'`${process.env.NEXT_PUBLIC_API_URL}\1`', content)
    
    # Replace http://localhost:8000 inside already backticked strings
    content = content.replace('http://localhost:8000', '${process.env.NEXT_PUBLIC_API_URL}')
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

for root, dirs, files in os.walk(front_dir):
    if 'node_modules' in root or '.next' in root:
        continue
    for file in files:
        if file.endswith('.js') or file.endswith('.jsx'):
            filepath = os.path.join(root, file)
            with open(filepath, 'r', encoding='utf-8') as f:
                if 'http://localhost:8000' in f.read():
                    process_file(filepath)
                    print(f'Updated {filepath}')
