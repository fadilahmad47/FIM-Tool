import os, time, sys
import hashlib
import psutil

# Initialize the process variable outside the function
process = psutil.Process(os.getpid())

def md5(fname):
    hash_md5 = hashlib.md5()
    try:
        with open(fname, "rb") as f:
            chunk_size = 4096
            while chunk := f.read(chunk_size):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except PermissionError:
        print(f"Permission denied for file {fname}", flush=True)
    except FileNotFoundError:
        print(f"File not found: {fname}", flush=True)
    except IOError as e:
        print(f"I/O error({e.errno}) for file {fname}: {e.strerror}", flush=True)
    except Exception as e:  # A generic catch-all for any other exceptions
        print(f"Error processing file {fname}: {e}", flush=True)
    return None

def get_memory_usage():
    memory_info = process.memory_info()
    memory_used_mb = memory_info.rss / 1024 / 1024  # Convert bytes to MB
    return memory_used_mb


def walk_and_check_hashes(directory, hash_file_path):
    hash_set = set()
    files_processed = 0
    total_files = 0
    found_match = False  # Variable to track if any hash matches are found

        # Print initial memory usage
    initial_usage = get_memory_usage()
    print(f"Initial memory usage: {initial_usage:.2f} MB")


    start_time = time.time()  # Capture the start time


    # Load the hashes from the hash file
    try:
        with open(hash_file_path, 'r') as hash_file:
            for line in hash_file:
                hash_set.add(line.strip())
    except Exception as e:
        print(f"Error loading hash file: {e}", flush=True)
        return

    # First, count all files to be scanned
    for root, dirs, files in os.walk(directory):
        total_files += len(files)

    print(f"Total files to be scanned: {total_files}")

    # Walk through the directory
    for root, dirs, files in os.walk(directory):
        for name in files:
            # Check memory usage before processing each file
            current_usage = get_memory_usage()
            if current_usage > MEMORY_THRESHOLD_MB:  # Define MEMORY_THRESHOLD_MB as appropriate
                print(f"\nWarning: High memory usage detected - {current_usage:.2f} MB")

            file_path = os.path.join(root, name)
            file_hash = md5(file_path)

            if file_hash in hash_set:
                print(f"\033[91mHash match found for {file_path}\033[0m", flush=True)
                found_match = True  # Update found_match to True if a match is found

            files_processed += 1
            if files_processed % 10 == 0:  # Print every 10 files
                print(f"\rProcessed {files_processed} files...", flush=True)

    end_time = time.time()  # Capture the end time
    elapsed_time = end_time - start_time  # Calculate the elapsed time

    # After processing all files, print the final messages
    print(f"\nFinished processing. Total files processed: {files_processed}")
    print(f"Number of hashes used for comparison: {len(hash_set)}")
    print(f"Time taken: {elapsed_time:.2f} seconds")

    if not found_match:  # Check if no matches were found
        print("No matching hashes found.")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: <script> <directory_to_scan> <hash_file_path>")
    else:
        directory_to_scan = sys.argv[1]
        hash_file_path = sys.argv[2]
        MEMORY_THRESHOLD_MB = 300  # Set an appropriate memory usage threshold in MB
        walk_and_check_hashes(directory_to_scan, hash_file_path)

# LEGEND
# https://virusshare.com/hashes
    #     directory_to_scan = "/home/q/Documents/libri/infosec"
    # hash_file_path = "/home/q/Documents/cyber_security/hashes/unpacked"
#!/usr/bin/env python3
"""
Enhanced File Integrity Checker
- Original: visjble/File-Integrity-Checker
- Updates: Multi-algorithm support (MD5/SHA-256/SHA-512) + Whitelist/Blacklist via JSON config.
"""

import os
import sys
import json
import argparse
import hashlib
import psutil
from pathlib import Path

# Configurable constants
MEMORY_THRESHOLD_MB = 500  # Warn if memory > this

def load_hashes(hash_file_path):
    """Load valid hashes from file (one per line)."""
    try:
        with open(hash_file_path, 'r') as f:
            return set(line.strip() for line in f if line.strip())
    except FileNotFoundError:
        print(f"Error: Hash file '{hash_file_path}' not found.")
        sys.exit(1)

def compute_hash(file_path, algo='md5'):
    """Compute hash for file using specified algorithm, with MD5 fallback."""
    try:
        h = hashlib.new(algo)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        # Fallback to MD5
        print(f"Warning: Falling back to MD5 for {file_path}")
        return compute_hash(file_path, 'md5')

def is_in_list(path, path_list):
    """Check if path matches any in list (exact or prefix)."""
    for item in path_list:
        if path == item or path.startswith(item + os.sep):
            return True
    return False

def scan_directory(directory, valid_hashes, algo, blacklist, whitelist):
    """Recursively scan directory, skipping blacklist, prioritizing whitelist."""
    mismatches = []
    process = psutil.Process(os.getpid())
    
    for root, _, files in os.walk(directory):
        current_mem = process.memory_info().rss / 1024 / 1024
        if current_mem > MEMORY_THRESHOLD_MB:
            print(f"Warning: High memory usage ({current_mem:.1f} MB). Stopping.")
            break
        
        # Check if root is blacklisted
        if is_in_list(root, blacklist):
            print(f"Skipping blacklisted directory: {root}")
            continue
        
        priority = is_in_list(root, whitelist)
        prefix = "[PRIORITY] " if priority else ""
        
        for file in files:
            file_path = os.path.join(root, file)
            try:
                if os.path.getsize(file_path) == 0:
                    continue  # Skip empty files
                file_hash = compute_hash(file_path, algo)
                if file_hash not in valid_hashes:
                    mismatches.append(file_path)
                print(f"{prefix}Checked: {file_path} (hash: {file_hash[:8]}...)")
            except (PermissionError, OSError) as e:
                print(f"Error accessing {file_path}: {e}")
    
    return mismatches

def main():
    parser = argparse.ArgumentParser(description="Enhanced File Integrity Checker")
    parser.add_argument("directory", help="Directory to scan")
    parser.add_argument("hash_file", help="Path to valid hashes file")
    parser.add_argument("--hash-algo", choices=['md5', 'sha256', 'sha512'], default='md5',
                        help="Hash algorithm (default: md5)")
    parser.add_argument("--config", help="Path to JSON config for whitelist/blacklist")
    args = parser.parse_args()
    
    # Load config if provided
    blacklist = []
    whitelist = []
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
                blacklist = config.get("blacklist", [])
                whitelist = config.get("whitelist", [])
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading config '{args.config}': {e}")
            sys.exit(1)
    
    print(f"Scanning {args.directory} with {args.hash_algo.upper()}...")
    print(f"Blacklist: {blacklist}")
    print(f"Whitelist: {whitelist}")
    
    valid_hashes = load_hashes(args.hash_file)
    mismatches = scan_directory(args.directory, valid_hashes, args.hash_algo, blacklist, whitelist)
    
    if mismatches:
        print(f"\nMismatches found ({len(mismatches)}):")
        for path in mismatches:
            print(f"- {path}")
    else:
        print("\nAll files match known hashes. Integrity verified!")

if __name__ == "__main__":
    main()
