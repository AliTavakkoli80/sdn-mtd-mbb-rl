import os
import sys

def collect_project_code(output_file="project_code.txt", exclude_dirs=None, exclude_files=None):
    """
    Collects all Python source code files from the project directory into a single text file,
    excluding specified directories and files.
    
    Args:
        output_file (str): Name of the output text file
        exclude_dirs (list): List of directory names to exclude from collection
        exclude_files (list): List of file names to exclude from collection
    """
    # Default directories to exclude
    if exclude_dirs is None:
        exclude_dirs = ["flowmanager", "venv", ".git", "__pycache__", ".venv", ".tox", 
                        "build", "dist", ".mypy_cache", ".pytest_cache", ".vscode", 
                        ".idea", ".eggs", "node_modules"]
    
    # Default files to exclude
    if exclude_files is None:
        exclude_files = [".gitignore", ".gitattributes", ".dockerignore", "LICENSE", 
                         "Dockerfile", ".env", ".DS_Store", "*.log", ".coverage"]
    
    # Get the current working directory
    project_root = "/home/ubuntu/Project/MTD/mtd_ip_shuffling"
    
    with open(output_file, 'w', encoding='utf-8') as outfile:
        outfile.write("=" * 80 + "\n")
        outfile.write(f"PROJECT CODE COLLECTION\n")
        outfile.write(f"Generated: {os.path.basename(project_root)}\n")
        outfile.write(f"Excluded directories: {', '.join(exclude_dirs)}\n")
        outfile.write(f"Excluded files: {', '.join(exclude_files)}\n")
        outfile.write("=" * 80 + "\n\n")
        
        # Counters for statistics
        file_count = 0
        total_size = 0
        
        # Walk through all directories and files
        for root, dirs, files in os.walk(project_root):
            # Skip excluded directories
            skip_dir = False
            for exclude_dir in exclude_dirs:
                if exclude_dir in root:
                    skip_dir = True
                    break
            if skip_dir:
                continue
                
            # Process each file
            for file in files:
                # Skip excluded files
                skip_file = False
                for exclude_pattern in exclude_files:
                    if exclude_pattern.startswith("*."):
                        extension = exclude_pattern[2:]
                        if file.endswith(extension):
                            skip_file = True
                            break
                    elif file == exclude_pattern:
                        skip_file = True
                        break
                
                if skip_file:
                    continue
                
                # Only process relevant source code and config files
                file_lower = file.lower()
                if (file_lower.endswith('.py') or 
                    file_lower.endswith('.sh') or 
                    file_lower.endswith('.md') or 
                    file_lower.endswith('.txt') or
                    file_lower.endswith('.json') or
                    file_lower.endswith('.yaml') or
                    file_lower.endswith('.yml') or
                    file_lower == 'requirements.txt' or
                    file_lower == 'dockerfile' or
                    file_lower == '.env.example'):
                    
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, project_root)
                    
                    # Get file size
                    file_size = os.path.getsize(file_path)
                    total_size += file_size
                    file_count += 1
                    
                    # Write file header
                    outfile.write("\n" + "=" * 80 + "\n")
                    outfile.write(f"FILE: {relative_path} ({file_size} bytes)\n")
                    outfile.write("=" * 80 + "\n\n")
                    
                    try:
                        # Read and write file content
                        with open(file_path, 'r', encoding='utf-8') as infile:
                            content = infile.read()
                            outfile.write(content)
                    except Exception as e:
                        outfile.write(f"ERROR reading file: {str(e)}\n")
                    
                    outfile.write("\n" + "-" * 80 + "\n")

        # Write summary
        outfile.write("\n" + "=" * 80 + "\n")
        outfile.write("SUMMARY\n")
        outfile.write("=" * 80 + "\n")
        outfile.write(f"Total files collected: {file_count}\n")
        outfile.write(f"Total size: {total_size} bytes ({total_size/1024:.2f} KB)\n")
        outfile.write(f"Excluded directories: {', '.join(exclude_dirs)}\n")
        outfile.write(f"Excluded files: {', '.join(exclude_files)}\n")
        outfile.write("=" * 80 + "\n")

    print(f"✅ Code collection complete! Saved to: {output_file}")
    print(f"📁 Project root: {project_root}")
    print(f"📁 Total files collected: {file_count}")
    print(f"🔥 Total size: {total_size/1024:.2f} KB")
    print(f"🚫 Excluded directories: {', '.join(exclude_dirs)}")
    print(f"🚫 Excluded files: {', '.join(exclude_files)}")

if __name__ == "__main__":
    # You can customize the excluded directories and files here
    custom_exclude_dirs = ["flowmanager", "venv", ".git", "__pycache__", "logs", ".tox"]
    custom_exclude_files = [".gitignore", ".DS_Store", "*.log", ".coverage", ".env"]
    
    # Run the collection with custom exclusions
    collect_project_code(
        output_file="project_code.txt",
        exclude_dirs=custom_exclude_dirs,
        exclude_files=custom_exclude_files
    )