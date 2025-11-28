import os

# Add extensions you want to include
extensions = ['.py', '.js', '.html', '.css', '.json', '.md']
# Add folders you want to IGNORE
ignore_dirs = ['node_modules', '.git', '__pycache__', 'venv', 'env']

output_file = 'project_context.txt'

with open(output_file, 'w', encoding='utf-8') as outfile:
    for root, dirs, files in os.walk("."):
        # Remove ignored directories to prevent walking into them
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        
        for file in files:
            if any(file.endswith(ext) for ext in extensions):
                file_path = os.path.join(root, file)
                outfile.write(f"\n\n--- START OF FILE: {file_path} ---\n\n")
                try:
                    with open(file_path, 'r', encoding='utf-8') as infile:
                        outfile.write(infile.read())
                except Exception as e:
                    outfile.write(f"Could not read file: {e}")