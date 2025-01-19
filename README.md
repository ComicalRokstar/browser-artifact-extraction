# browser-artifact-extraction
**Python Browser Artifact Extraction Tool**
This repository contains a Python-based tool designed for extracting, parsing, and analyzing browser artifacts from various web browsers. Browser artifacts provide valuable information for digital forensics and incident response (DFIR) investigations, such as browsing history, cookies, cache, download logs, and more.

**Key Features**
**Multi-Browser Support**: Works with popular web browsers like Chrome, Firefox, and Edge.
**Artifact Extraction**: Retrieves browser data, including history, cookies, bookmarks, and cache.
**Decryption Capabilities**: Decodes encrypted browser data (e.g., cookies, passwords) with AES.
**Customizable Output**: Supports exporting results in JSON, CSV, and other formats.
**Efficient Compression** Handling: Decodes compressed data formats like LZ4.

**Dependencies**
This project uses the following libraries:

**Standard Libraries**:
os, sqlite3, json, datetime, shutil, subprocess, sys, glob, argparse, configparser.
**Third-Party Libraries**:
pycryptodome (Crypto.Cipher, Crypto.Util.Padding): For AES decryption.
lz4.block: To handle LZ4-compressed data.
**Windows-Specific Library**:
winreg: For accessing Windows Registry to locate browser-related data.

**Getting Started:**
Clone the repository and install the required dependencies.
**Run Using**: python extract_artifacts.py --output results(output folder)
Analyze the extracted data using your preferred tools or built-in reporting options(txt files).

**Contributions**
Contributions and feedback are welcome! 
