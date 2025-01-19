import os
import sqlite3
import json
import base64
import datetime
import shutil
import subprocess
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import argparse
import winreg
import glob
import lz4.block
import configparser

# Check if pywin32 is installed, if not, install it
try:
    import win32crypt
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pywin32"])
    import win32crypt

# Utility Functions
def get_decryption_key(local_state_path):
    """Retrieve the decryption key for browsers using Chromium (e.g., Brave, Opera)."""
    with open(local_state_path, 'r', encoding='utf-8') as file:
        local_state = json.load(file)

    encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
    key = win32crypt.CryptUnprotectData(encrypted_key[5:], None, None, None, 0)[1]
    return key.ljust(32, b'\0')[:32]  # Ensure 32-byte key

def decrypt_data(encrypted_data, key):
    """Decrypt encrypted data using AES."""
    padding = len(encrypted_data) % 4
    if padding:
        encrypted_data += "=" * (4 - padding)

    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size).decode('utf-8')

def parse_url(url):
    """Parse a URL into its base URL and query parameters."""
    from urllib.parse import urlparse, parse_qs
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    query_params = parse_qs(parsed.query)
    params_str = ', '.join(f"{key}: {value}" for key, value in query_params.items())
    return base_url, params_str

firefox_path2 = r"C:\Users\Main\AppData\Roaming\Mozilla\Firefox\Profiles\26tlf38z.default-release"

def get_firefox_paths():
    """
    Locate Firefox profile paths and construct file paths.
    """
    profiles_ini = os.path.expanduser(os.path.join("~", "AppData", "Roaming", "Mozilla", "Firefox", "profiles.ini"))
    if os.path.exists(profiles_ini):
        try:
            with open(profiles_ini, 'r') as f:
                lines = f.readlines()

            profile_dir = None
            for i, line in enumerate(lines):
                # Look for the "Name=default-release" and get its associated "Path="
                if line.strip() == "Name=default-release":
                    for j in range(i, len(lines)):
                        if lines[j].strip().startswith("Path="):
                            profile_dir = lines[j].strip().split("=", 1)[-1]
                            break
                    if profile_dir:
                        break

            # Manually set profile_dir if needed (for testing purposes)
            profile_dir = "26tlf38z.default-release"

            if profile_dir:
                profile_path = os.path.expanduser(
                    os.path.join("~", "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", profile_dir)
                )

                # Define the paths for the additional files
                return {
                    "places_db": os.path.join(profile_path, "places.sqlite"),
                    "bookmarks_db": os.path.join(profile_path, "places.sqlite"),
                    "logins_json": os.path.join(profile_path, "logins.json"),
                    "key4_db": os.path.join(profile_path, "key4.db"),
                    "downloads": os.path.join(profile_path, "places.sqlite"),
                    "cookies": os.path.join(profile_path, "cookies.sqlite"),
                    "extensions": os.path.join(profile_path, "extensions"),  # Path to extensions folder
                    "cache": os.path.join(profile_path, "cache2"),  # Path to cache folder
                    "incognito": os.path.join(profile_path, "recovery.json"),  # Path to incognito data
                    "network_data": os.path.join(profile_path, "network_prediction.sqlite"),  # Network data
                    "temp_files": os.path.join(profile_path, "recovery.json")  # Temporary files
                }
            else:
                print("Default-release profile not found.")
        except Exception as e:
            print(f"Error reading Firefox profiles.ini: {e}")
    else:
        print("profiles.ini file not found.")
    return None

def get_brave_paths():
    """
    Dynamically locate Brave profile paths and construct file paths.
    """
    user_data_dir = os.path.expanduser(r"~\AppData\Local\BraveSoftware\Brave-Browser\User Data")
    if os.path.exists(user_data_dir):
        network_dir = os.path.join(user_data_dir, "Default", "Network")  # Directory containing the cookies file
        default_profile = os.path.join(user_data_dir, "Default")
        return {
            "local_state": os.path.join(user_data_dir, "Local State"),
            "history": os.path.join(default_profile, "History"),
            "bookmarks": os.path.join(default_profile, "Bookmarks"),
            "passwords": os.path.join(default_profile, "Login Data"),
            "downloads": os.path.join(default_profile, "History"),
            "cookies": os.path.join(network_dir, "Cookies"),
            "extensions": os.path.join(default_profile, "Extensions"),  # Path to extensions folder
            "cache": os.path.join(default_profile, "Cache"),  # Path to cache folder
            "incognito": os.path.join(default_profile, "Incognito"),  # Path to incognito data
            "network_data": os.path.join(network_dir, "Network Action Predictor"),  # Network data
            "temp_files": os.path.join(default_profile, "Temp")  # Temporary files
        }
    return None

def get_opera_paths():
    """
    Dynamically locate Opera profile paths and construct file paths.
    """
    roaming_dir = os.path.expanduser(r"~\AppData\Roaming\Opera Software\Opera Stable")
    if os.path.exists(roaming_dir):
        network_dir = os.path.join(roaming_dir, "Default", "Network")  # Directory containing the cookies file
        return {
            "local_state": os.path.join(roaming_dir, "Local State"),
            "history": os.path.join(roaming_dir, "Default", "History"),
            "bookmarks": os.path.join(roaming_dir, "Default", "Bookmarks"),
            "passwords": os.path.join(roaming_dir, "Default", "Login Data"),
            "downloads": os.path.join(roaming_dir, "Default", "History"),
            "cookies": os.path.join(network_dir, "Cookies"),  # Updated cookies file path
            "extensions": os.path.join(roaming_dir, "Default", "Extensions"),  # Path to extensions folder
            "cache": os.path.join(roaming_dir, "Default", "Code Cache"),  # Path to cache folder
            "incognito": os.path.join(roaming_dir, "Default", "Incognito"),  # Path to incognito data
            "network_data": os.path.join(network_dir, "Network Action Predictor"),  # Network data
            "temp_files": os.path.join(roaming_dir, "Default", "Temp")  # Temporary files
        }
    return None

def write_to_file(output_dir, filename, data):
    """Write data to a file in the specified output directory."""
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, filename), 'w', encoding='utf-8') as file:
        for line in data:
            file.write(line + '\n\n')
            
def write_to_file2(output_dir, filename, data):
    """Write data to a file in the specified output directory."""
    os.makedirs(output_dir, exist_ok=True)
    file_path = os.path.join(output_dir, filename)

    with open(file_path, 'w', encoding='utf-8') as file:
        if isinstance(data, str):
            # Directly write string data
            file.write(data)
        elif isinstance(data, list) or isinstance(data, dict):
            # Convert list or dictionary to JSON and write
            file.write(json.dumps(data, indent=4))
        else:
            raise ValueError("Unsupported data format for writing to file")

    print(f"Data successfully written to {file_path}.")


# Processing Functions
def process_browser_history(history_db_path):
    """Extract browsing history from a Chromium-based browser or Firefox."""
    if not os.path.exists(history_db_path):
        return []

    connection = sqlite3.connect(history_db_path)
    cursor = connection.cursor()

    # Query format changes based on browser type
    if "places.sqlite" in history_db_path:  # Firefox
        query = "SELECT url, last_visit_date FROM moz_places WHERE url IS NOT NULL"
        timestamp_adjustment = 0  # Firefox timestamps don't need adjustment
    else:  # Chromium-based (Brave, Opera)
        query = "SELECT url, last_visit_time FROM urls"
        timestamp_adjustment = 11644473600000000  # Chromium timestamp adjustment

    cursor.execute(query)
    history_data = cursor.fetchall()
    connection.close()

    results = []
    for url, timestamp in history_data:
        if timestamp is None:  # Skip entries with no timestamp
            continue
        try:
            readable_time = datetime.datetime.fromtimestamp(
                (timestamp - timestamp_adjustment) / 1000000
            ).strftime('%Y-%m-%d %H:%M:%S')
            results.append(f"URL: {url}, Last Visited: {readable_time}")
        except Exception as e:
            print(f"Error processing history entry: {url}, Error: {str(e)}")
    return results

def process_browser_bookmarks(bookmarks_file_path, is_firefox=False):
    """Extract bookmarks from a Chromium-based browser or Firefox."""
    if not os.path.exists(bookmarks_file_path):
        return []

    if is_firefox:  # Firefox bookmarks are stored in SQLite
        connection = sqlite3.connect(bookmarks_file_path)
        cursor = connection.cursor()
        cursor.execute(
            "SELECT moz_bookmarks.title, moz_places.url "
            "FROM moz_bookmarks JOIN moz_places ON moz_bookmarks.fk = moz_places.id "
            "WHERE moz_places.url IS NOT NULL"
        )
        bookmarks = cursor.fetchall()
        connection.close()

        return [f"Title: {title}, URL: {url}" for title, url in bookmarks]
    else:  # Chromium-based bookmarks are in JSON format
        with open(bookmarks_file_path, 'r', encoding='utf-8') as file:
            bookmarks_data = json.load(file)

        results = []

        def extract_bookmarks(bookmark_items):
            for item in bookmark_items:
                if item.get('type') == 'url':
                    results.append(f"Title: {item['name']}, URL: {item['url']}")
                elif item.get('type') == 'folder':
                    extract_bookmarks(item['children'])

        extract_bookmarks(bookmarks_data['roots']['bookmark_bar']['children'])
        extract_bookmarks(bookmarks_data['roots']['other']['children'])
        return results

def process_browser_passwords(local_state_path, login_data_path):
    """Extract stored passwords from a Chromium-based browser."""
    if not os.path.exists(local_state_path) or not os.path.exists(login_data_path):
        return ["Browser's local state or Login Data file not found."]

    try:
        # Connect to the Login Data SQLite database
        connection = sqlite3.connect(login_data_path)
        cursor = connection.cursor()

        # Query the logins table for stored credentials
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        credentials = cursor.fetchall()
        connection.close()

        # Store the encrypted passwords
        results = []
        for origin_url, username, encrypted_password in credentials:
            if encrypted_password:
                # Convert encrypted password to hex string for storage
                hex_password = encrypted_password.hex() if isinstance(encrypted_password, bytes) else str(encrypted_password)
                results.append(
                    f"URL: {origin_url}, Username: {username}, Encrypted Password: {hex_password}"
                )
            else:
                results.append(f"URL: {origin_url}, Username: {username}, Password: <No password stored>")
        return results

    except Exception as e:
        return [f"Error processing passwords: {str(e)}"]

def process_firefox_passwords(logins_json_path, key4_db_path):
    """Extract stored passwords from Firefox."""
    if not os.path.exists(logins_json_path) or not os.path.exists(key4_db_path):
        return ["Firefox's logins.json or key4.db file not found."]

    try:
        # Read the encrypted data directly from logins.json
        with open(logins_json_path, 'r', encoding='utf-8') as file:
            logins_data = json.load(file)

        results = []
        for login in logins_data.get('logins', []):
            results.append(
                f"URL: {login.get('hostname', 'N/A')}, "
                f"Username (encrypted): {login.get('encryptedUsername', 'N/A')}, "
                f"Password (encrypted): {login.get('encryptedPassword', 'N/A')}"
            )
        return results

    except Exception as e:
        return [f"Error processing Firefox passwords: {str(e)}"]

def scan_temp_files(temp_dir):
    """Scan temporary files in a directory."""
    if not os.path.exists(temp_dir):
        return []

    results = []
    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file.endswith(('.tmp', '.cache')):
                results.append(os.path.join(root, file))
    return results

def analyze_registry_and_prefetch(output_dir):
    """Analyze registry and prefetch for browser traces and write directly to file."""
    results = []

    # Analyze registry for installed browsers
    try:
        import winreg  # For Windows registry analysis
        browsers_key_path = r"SOFTWARE\Clients\StartMenuInternet"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, browsers_key_path) as key:
            i = 0
            while True:
                try:
                    browser = winreg.EnumKey(key, i)
                    results.append(f"Installed Browser: {browser}")
                    i += 1
                except OSError:
                    break
    except Exception as e:
        results.append(f"Error accessing registry: {str(e)}")

    # Analyze prefetch files
    prefetch_dir = r"C:\Windows\Prefetch"
    if os.path.exists(prefetch_dir):
        try:
            for file in os.listdir(prefetch_dir):
                if "chrome" in file.lower() or "firefox" in file.lower() or "brave" in file.lower():
                    results.append(f"Prefetch File: {file}")
        except PermissionError as e:
            results.append(f"Permission error accessing prefetch files: {str(e)}")
        except Exception as e:
            results.append(f"Error accessing prefetch directory: {str(e)}")
    else:
        results.append("Prefetch directory does not exist.")

    # Write results to file
    write_to_file(output_dir, "registry_prefetch_analysis.txt", results)
    
def process_browser_cache(cache_dir):
    """Extract cached files and metadata from the browser cache directory."""
    if not os.path.exists(cache_dir):
        return ["Cache directory not found."]

    results = []
    for root, _, files in os.walk(cache_dir):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                file_size = os.path.getsize(file_path)
                last_modified = datetime.datetime.fromtimestamp(
                    os.path.getmtime(file_path)
                ).strftime('%Y-%m-%d %H:%M:%S')
                results.append(f"File: {file_path}, Size: {file_size} bytes, Last Modified: {last_modified}")
            except Exception as e:
                results.append(f"Error reading file: {file_path}, Error: {str(e)}")

    return results

def analyze_password_strength(password):
    """Analyzes the strength of a password based on various criteria."""
    score = 0
    criteria = {
        'length': len(password) >= 8,
        'uppercase': any(c.isupper() for c in password),
        'lowercase': any(c.islower() for c in password),
        'numbers': any(c.isdigit() for c in password),
        'special': any(not c.isalnum() for c in password)
    }
    
    for criterion, is_met in criteria.items():
        if is_met:
            score += 1
    
    strength_levels = {
        0: "Very Weak",
        1: "Weak",
        2: "Moderate",
        3: "Strong",
        4: "Very Strong",
        5: "Excellent"
    }
    
    return {
        'score': score,
        'strength': strength_levels[score],
        'criteria_met': {k: v for k, v in criteria.items()}
    }

def analyze_stored_passwords(browser_paths, output_dir):
    """Analyzes all stored passwords and generates a security report."""
    try:
        passwords = process_browser_passwords(browser_paths["local_state"], browser_paths["passwords"])
        analysis_results = []
        
        for entry in passwords:
            if isinstance(entry, str) and "Password:" in entry:
                password = entry.split("Password: ")[-1].strip()
                analysis = analyze_password_strength(password)
                analysis_results.append({
                    'password_entry': entry,
                    'analysis': analysis
                })
        
        # Write analysis to file
        with open(os.path.join(output_dir, "password_security_analysis.txt"), 'w', encoding='utf-8') as f:
            f.write("Password Security Analysis Report\n")
            f.write("=" * 50 + "\n\n")
            
            for result in analysis_results:
                f.write(f"Entry: {result['password_entry']}\n")
                f.write(f"Strength: {result['analysis']['strength']}\n")
                f.write("Criteria Met:\n")
                for criterion, is_met in result['analysis']['criteria_met'].items():
                    f.write(f"- {criterion}: {'✓' if is_met else '✗'}\n")
                f.write("\n")
                
        return "Password security analysis completed successfully!"
    except Exception as e:
        return f"Error analyzing passwords: {str(e)}"

def process_browser_extensions(browser_data_path, is_firefox=False):
    """Extract installed browser extensions from Chromium-based or Firefox browsers."""
    if not os.path.exists(browser_data_path):
        return []

    results = []

    if is_firefox:  # Firefox extensions are stored in the profiles' extensions folder
        extensions_path = os.path.join(browser_data_path, 'extensions')
        if os.path.exists(extensions_path):
            for ext_dir in os.listdir(extensions_path):
                ext_path = os.path.join(extensions_path, ext_dir)
                if os.path.isdir(ext_path):
                    results.append(f"Firefox Extension: {ext_dir}")
    else:  # Chromium-based (Brave, Opera) extensions are in the 'Extensions' folder
        extensions_path = os.path.join(browser_data_path, 'Extensions')
        if os.path.exists(extensions_path):
            for ext_dir in os.listdir(extensions_path):
                if len(ext_dir) == 32:  # Chromium extension IDs are 32 characters long
                    results.append(f"Chromium Extension: {ext_dir}")

    return results

def process_browser_cookies(local_state_path, cookies_path):
    """Extract cookies from a Chromium-based browser."""
    if not os.path.exists(local_state_path) or not os.path.exists(cookies_path):
        return ["Browser's local state or Cookies file not found."]

    try:
        # Get the decryption key
        key = get_decryption_key(local_state_path)

        # Connect to the Cookies SQLite database
        connection = sqlite3.connect(cookies_path)
        cursor = connection.cursor()

        # Query the cookies table for stored cookies
        cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
        cookies = cursor.fetchall()
        connection.close()

        # Decrypt the cookies
        results = []
        for host, name, encrypted_value in cookies:
            try:
                decrypted_value = decrypt_data(encrypted_value, key)
            except Exception as e:
                decrypted_value = f"Error decrypting cookie: {str(e)}"

            results.append(f"Host: {host}, Name: {name}, Value: {decrypted_value}")
        return results

    except Exception as e:
        return [f"Error processing cookies: {str(e)}"]

def process_browser_downloads(history_db_path):
    """Extract download history from a Chromium-based browser."""
    if not os.path.exists(history_db_path):
        return ["History file not found."]

    try:
        connection = sqlite3.connect(history_db_path)
        cursor = connection.cursor()

        # Query the downloads table for download data
        cursor.execute("SELECT target_path, start_time FROM downloads")
        downloads = cursor.fetchall()
        connection.close()

        # Process timestamps and results
        results = []
        timestamp_adjustment = 11644473600000000  # Chromium timestamp adjustment
        for path, start_time in downloads:
            try:
                readable_time = datetime.datetime.fromtimestamp(
                    (start_time - timestamp_adjustment) / 1000000
                ).strftime('%Y-%m-%d %H:%M:%S')
                results.append(f"Downloaded File: {path}, Start Time: {readable_time}")
            except Exception as e:
                results.append(f"Error processing download entry: {path}, Error: {str(e)}")
        return results

    except Exception as e:
        return [f"Error processing downloads: {str(e)}"]

firefox_profile =get_firefox_paths()
brave_profile = get_brave_paths()
opera_profile = get_opera_paths()
firefox_crash_path = r"C:\Users\Main\AppData\Roaming\Mozilla\Firefox"
opera_crash_path = r"C:\Users\Main\AppData\Roaming\Opera Software\Opera Stable\Default\Crash Reports"
brave_crash_path = r"C:\Users\Main\AppData\Local\BraveSoftware\Brave-Browser\User Data\Crashpad"

# Utility Functions
def write_to_file(output_dir, filename, data):
    """Write data to a file in the specified output directory."""
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, filename), 'w', encoding='utf-8') as file:
        for line in data:
            file.write(line + '\n\n')

# Processing Functions
def process_firefox_downloads(profile_path):
    """Extract download history from Firefox."""
    # Check if places.sqlite exists
    places_db = os.path.join(profile_path, "places.sqlite")
    if not os.path.exists(places_db):
        return ["places.sqlite not found."]

    try:
        connection = sqlite3.connect(places_db)
        cursor = connection.cursor()

        # Query the moz_downloads table for download data
        query = """
            SELECT sourceURL, targetPath, startTime, endTime
            FROM moz_downloads
        """
        cursor.execute(query)
        downloads = cursor.fetchall()
        connection.close()

        if not downloads:
            return ["No downloads data found in moz_downloads."]

        results = []
        for source_url, target_path, start_time, end_time in downloads:
            start_time = datetime.datetime.fromtimestamp(start_time / 1000).strftime('%Y-%m-%d %H:%M:%S')  # Convert milliseconds
            end_time = datetime.datetime.fromtimestamp(end_time / 1000).strftime('%Y-%m-%d %H:%M:%S')  # Convert milliseconds
            results.append(f"Downloaded File: {target_path}, Source URL: {source_url}, Start Time: {start_time}, End Time: {end_time}")
        return results

    except Exception as e:
        return [f"Error processing Firefox downloads: {str(e)}"]

def process_firefox_cookies(profile_path):
    """Extract cookies from Firefox."""
    cookies_db = os.path.join(profile_path, "cookies.sqlite")
    if not os.path.exists(cookies_db):
        return ["Firefox cookies database not found."]

    try:
        connection = sqlite3.connect(cookies_db)
        cursor = connection.cursor()

        # Query the cookies table for cookie data
        cursor.execute("SELECT host, name, value, expiry FROM moz_cookies")
        cookies = cursor.fetchall()
        connection.close()

        results = []
        for host, name, value, expiry in cookies:
            expiry_date = datetime.datetime.fromtimestamp(expiry).strftime('%Y-%m-%d %H:%M:%S')
            results.append(f"Host: {host}, Name: {name}, Value: {value}, Expires: {expiry_date}")
        return results

    except Exception as e:
        return [f"Error processing Firefox cookies: {str(e)}"]


def analyze_crash_reports(profile_path, output_file):
    """
    Analyzes Firefox crash reports and writes the output to a file only if crash reports are found.
    """
    crash_reports_dir = os.path.join(profile_path, 'Crash Reports')  # Path to crashreports directory
    crash_report_data = []
    
    if not os.path.exists(crash_reports_dir):
        print("No crash reports directory found.")
        return
    
    # Scan for any crash report files (typically *.json files or minidumps)
    for root, dirs, files in os.walk(crash_reports_dir):
        for file in files:
            if file.endswith('.json'):  # Firefox crash report in json format
                file_path = os.path.join(root, file)
                
                # Open and parse the JSON file for crash details
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        crash_data = json.load(f)
                        crash_report_data.append(crash_data)
                except Exception as e:
                    print(f"Error reading crash report {file_path}: {e}")
    
    # If there are any crash reports, write them to the output file
    if crash_report_data:
        print(f"Found {len(crash_report_data)} crash reports. Writing to file...")
        
        # Convert crash report data to string format for writing
        output_data = json.dumps(crash_report_data, indent=4)
        write_to_file(output_file, output_data)
    else:
        print("No valid crash reports found. No file will be created.")
        

def analyze_crash_reports2(profile_path, output_file):
    """
    Analyzes Firefox crash reports and writes the output to a file only if crash reports are found.
    """
    crash_reports_dir = os.path.join(profile_path, 'reports')  # Path to crashreports directory
    crash_report_data = []
    
    if not os.path.exists(crash_reports_dir):
        print("No crash reports directory found.")
        return
    
    # Scan for any crash report files (typically *.json files or minidumps)
    for root, dirs, files in os.walk(crash_reports_dir):
        for file in files:
            if file.endswith('.json'):  # Firefox crash report in json format
                file_path = os.path.join(root, file)
                
                # Open and parse the JSON file for crash details
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        crash_data = json.load(f)
                        crash_report_data.append(crash_data)
                except Exception as e:
                    print(f"Error reading crash report {file_path}: {e}")
    
    # If there are any crash reports, write them to the output file
    if crash_report_data:
        print(f"Found {len(crash_report_data)} crash reports. Writing to file...")
        
        # Convert crash report data to string format for writing
        output_data = json.dumps(crash_report_data, indent=4)
        write_to_file(output_file, output_data)
    else:
        print("No valid crash reports found. No file will be created.")

def extract_chromium_network_data(browser_name):
    """
    Extract network-related data from Chromium-based browser profiles.
    Dynamically identifies the profile path based on the browser name.
    """
    if browser_name.lower() == "brave":
        paths = get_brave_paths()
    elif browser_name.lower() == "opera":
        paths = get_opera_paths()
    else:
        return f"Unsupported browser: {browser_name}"

    if paths and "local_state" in paths:
        config_file = paths["local_state"]
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config_data = json.load(f)

                # Extract proxy settings and related data
                proxy_settings = config_data.get("proxy", {})
                dns_over_https = config_data.get("dns_over_https", {}).get("enabled", False)

                network_summary = {
                    "ProxySettings": proxy_settings,
                    "DNSOverHTTPS": dns_over_https
                }
                return network_summary
            except Exception as e:
                return f"Error reading Preferences file for {browser_name}: {e}"
        else:
            return f"No Preferences file found for {browser_name}."
    else:
        return f"Profile path for {browser_name} could not be located."

def extract_firefox_network_data(profile_path):
    prefs_file = os.path.join(profile_path, "prefs.js")
    if os.path.exists(prefs_file):
        proxy_settings = {}
        dns_over_https = None

        try:
            # Open prefs.js with utf-8 encoding
            with open(prefs_file, 'r', encoding='utf-8') as f:
                for line in f:
                    if 'network.proxy.' in line:
                        key, value = parse_prefs_js_line(line)
                        proxy_settings[key] = value
                    elif 'network.trr.mode' in line:  # DNS-over-HTTPS setting
                        _, dns_over_https = parse_prefs_js_line(line)

            network_summary = {
                "ProxySettings": proxy_settings,
                "DNSOverHTTPS": dns_over_https
            }
            return network_summary

        except UnicodeDecodeError as e:
            return f"Error reading prefs.js: {e}"

    else:
        return "No prefs.js file found for Firefox."


def parse_prefs_js_line(line):
    # Parse prefs.js lines to extract key-value pairs
    parts = line.split(", ")
    key = parts[0].split("network.proxy.")[-1].strip('"')
    value = parts[1].strip('");\n')
    return key, value

def analyze_incognito_data():
    """
    Analyzes traces from Firefox, Brave, and Opera incognito/private mode
    and returns the extracted data.
    """
    incognito_data = []

    # Analyze Firefox private mode traces
    firefox_paths = get_firefox_paths()
    if firefox_paths:
        session_file = os.path.join(
            os.path.dirname(firefox_paths["places_db"]), 'sessionstore-backups', 'recovery.jsonlz4'
        )
        if os.path.exists(session_file):
            try:
                firefox_data = parse_firefox_session_data(session_file)
                if firefox_data:
                    incognito_data.append({'firefox_private_data': firefox_data})
            except Exception as e:
                print(f"Error analyzing Firefox incognito data: {e}")

    # Analyze Brave private mode traces
    brave_paths = get_brave_paths()
    if brave_paths:
        private_session_cache = os.path.join(
            os.path.dirname(brave_paths["local_state"]), 'Cache'
        )
        if os.path.exists(private_session_cache):
            try:
                brave_data = parse_brave_cache(private_session_cache)
                if brave_data:
                    incognito_data.append({'brave_private_data': brave_data})
            except Exception as e:
                print(f"Error analyzing Brave incognito data: {e}")

    # Analyze Opera private mode traces
    opera_paths = get_opera_paths()
    if opera_paths:
        private_cache_path = os.path.join(
            os.path.dirname(opera_paths["local_state"]), 'Private Cache'
        )
        if os.path.exists(private_cache_path):
            try:
                opera_data = parse_opera_cache(private_cache_path)
                if opera_data:
                    incognito_data.append({'opera_private_data': opera_data})
            except Exception as e:
                print(f"Error analyzing Opera incognito data: {e}")

    # Return collected incognito data
    if incognito_data:
        print("Found incognito/private browsing data.")
        return incognito_data
    else:
        print("No incognito/private browsing data found.")
        return None


def parse_firefox_session_data(session_file):
    """
    Parses Firefox sessionstore-backups recovery file for private browsing traces.
    """
    parsed_data = []
    try:
        with open(session_file, 'rb') as f:
            compressed_data = f.read()
            if compressed_data[:8] == b'mozLz40\0':
                decompressed_data = lz4.block.decompress(compressed_data[8:])
                session_data = json.loads(decompressed_data)
                # Extract specific useful data from session data
                for window in session_data.get('windows', []):
                    for tab in window.get('tabs', []):
                        # Extract active URL and history for each tab
                        tab_entries = tab.get('entries', [])
                        for entry in tab_entries:
                            parsed_data.append({
                                'url': entry.get('url', 'N/A'),
                                'title': entry.get('title', 'N/A'),
                                'last_visited': entry.get('lastAccessed', 'N/A')
                            })
    except Exception as e:
        print(f"Error parsing Firefox session file: {e}")
    return parsed_data

def parse_brave_cache(cache_path):
    parsed_data = []
    for root, dirs, files in os.walk(cache_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    parsed_data.append({'file_name': file, 'content': content[:100].decode('utf-8', 'ignore')})
            except Exception as e:
                print(f"Error reading Brave cache file {file_path}: {e}")
    return parsed_data

def parse_opera_cache(cache_path):
    parsed_data = []
    for root, dirs, files in os.walk(cache_path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'rb') as f:
                    content = f.read()
                    parsed_data.append({'file_name': file, 'content': content[:100].decode('utf-8', 'ignore')})
            except Exception as e:
                print(f"Error reading Opera cache file {file_path}: {e}")
    return parsed_data

import os

def write_incognito_data_to_file(data, directory, filename="incognito_data.txt"):
    """
    Writes the incognito/private browsing data to a text file in the specified directory.
    
    Parameters:
        data (list): The data returned by the `analyze_incognito_data` function.
        directory (str): The directory where the file will be saved.
        filename (str): The name of the file to be created (default is 'incognito_data.txt').
    """
    try:
        # Ensure the directory exists
        os.makedirs(directory, exist_ok=True)

        # Create the full path for the file
        file_path = os.path.join(directory, filename)

        # Write data to the file
        with open(file_path, 'w', encoding='utf-8') as file:
            if data:
                file.write("Incognito/Private Browsing Data Analysis Report\n")
                file.write("=" * 50 + "\n\n")
                for entry in data:
                    for browser, browser_data in entry.items():
                        file.write(f"Browser: {browser.capitalize()}\n")
                        file.write("-" * 50 + "\n")
                        if isinstance(browser_data, dict):
                            for key, value in browser_data.items():
                                file.write(f"{key}: {value}\n")
                        elif isinstance(browser_data, list):
                            for item in browser_data:
                                file.write(f"- {item}\n")
                        else:
                            file.write(str(browser_data) + "\n")
                        file.write("\n")
            else:
                file.write("No incognito/private browsing data found.\n")
        
        print(f"Data successfully written to {file_path}")
    except Exception as e:
        print(f"Error writing data to file: {e}")


firefox_crash_path = r"C:\Users\Main\AppData\Roaming\Mozilla\Firefox"
opera_crash_path = r"C:\Users\Main\AppData\Roaming\Opera Software\Opera Stable\Default\Crash Reports"
brave_crash_path = r"C:\Users\Main\AppData\Local\BraveSoftware\Brave-Browser\User Data\Crashpad"

def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_main_menu():
    """Displays the main menu for selecting a browser."""
    print("=== Browser Data Extraction Tool ===")
    print("1. Brave")
    print("2. Opera")
    print("3. Firefox")
    print("4. Exit")

def display_artifact_menu():
    """Displays the menu for selecting browser artifacts."""
    print("=== Artifact Extraction Menu ===")
    print("1. History")
    print("2. Bookmarks")
    print("3. Passwords")
    print("4. Cache")
    print("5. Cookies")
    print("6. Downloads")
    print("7. Extensions")
    print("8. Network Data For Brave & Opera")
    print("9. Network Data For Firefox")
    print("10. Incognito Data")
    print("11. Temp Files")
    print("12. Registry & Prefetch")
    print("13. All Artifacts")
    print("14. Password Security Analysis")
    print("15. Browser Timeline")
    print("16. Search Term Analysis")
    print("17. Go Back")
    print("18. Exit")

def extract_artifact(browser, choice, paths, output_dir):
    """Handles artifact extraction based on user choice."""
    if choice == 1:
        history = process_browser_history(paths["history"])
        write_to_file(output_dir, f"{browser}_history.txt", history)
        print(f"{browser} history extracted successfully!")
    elif choice == 2:
        bookmarks = process_browser_bookmarks(paths["bookmarks"])
        write_to_file(output_dir, f"{browser}_bookmarks.txt", bookmarks)
        print(f"{browser} bookmarks extracted successfully!")
    elif choice == 3:
        passwords = process_browser_passwords(paths["local_state"], paths["passwords"])
        write_to_file(output_dir, f"{browser}_passwords.txt", passwords)
        print(f"{browser} passwords extracted successfully!")
    elif choice == 4:
        cache = process_browser_cache(paths["cache"])
        write_to_file(output_dir, f"{browser}_cache.txt", cache)
        print(f"{browser} cache extracted successfully!")
    elif choice == 5:
        cookies = process_browser_cookies(paths["local_state"], paths["cookies"])
        write_to_file(output_dir, f"{browser}_cookies.txt", cookies)
        print(f"{browser} cookies extracted successfully!")
    elif choice == 6:
        downloads = process_browser_downloads(paths["downloads"])
        write_to_file(output_dir, f"{browser}_downloads.txt", downloads)
        print(f"{browser} downloads extracted successfully!")
    elif choice == 7:
        extensions = process_browser_extensions(paths["extensions"])
        write_to_file(output_dir, f"{browser}_extensions.txt", extensions)
        print(f"{browser} extensions extracted successfully!")
        
    elif choice == 8:
        network_data = extract_chromium_network_data(paths["network_data"])
        write_to_file(output_dir, f"{browser}_network_data.txt", network_data)
        print(f"{browser} network data extracted successfully!")
    elif choice == 9:
        network_data = extract_firefox_network_data(paths["network_data"])
        write_to_file(output_dir, f"{browser}_network_data.txt", network_data)
        print(f"{browser} network data extracted successfully!")
    elif choice == 10:
        incognito = analyze_incognito_data()
        write_incognito_data_to_file(incognito, output_dir)
        print(f"{browser} incognito data extracted successfully!")
    elif choice == 11:
        temp_files = scan_temp_files(paths["temp_files"])
        write_to_file(output_dir, f"{browser}_temp_files.txt", temp_files)
        print(f"{browser} temp files extracted successfully!")
    elif choice == 12:
        analyze_registry_and_prefetch(output_dir)
        print(f"{browser} temp files extracted successfully!")
    elif choice == 13:
        extract_all_artifacts(browser, paths, output_dir)
    elif choice == 14:
        result = analyze_stored_passwords(paths, output_dir)
        print(result)
    elif choice == 15:
        result = create_browser_timeline(paths, output_dir)
        print(result)
    elif choice == 16:
        result = analyze_search_terms(paths, output_dir)
        print(result)
    elif choice == 17:
        return "BACK"
    elif choice == 18:
        print("Exiting the program. Goodbye!")
        sys.exit(0)
    else:
        print("Invalid choice. Please select a valid option.")
    return "CONTINUE"

def extract_all_artifacts(browser, paths, output_dir):
    """Extracts all artifacts for the selected browser."""
    print(f"Extracting all artifacts for {browser}...")
    history = process_browser_history(paths["history"])
    write_to_file(output_dir, f"{browser}_history.txt", history)
    bookmarks = process_browser_bookmarks(paths["bookmarks"])
    write_to_file(output_dir, f"{browser}_bookmarks.txt", bookmarks)
    passwords = process_browser_passwords(paths["local_state"], paths["passwords"])
    write_to_file(output_dir, f"{browser}_passwords.txt", passwords)
    cache = process_browser_cache(paths["cache"])
    write_to_file(output_dir, f"{browser}_cache.txt", cache)
    cookies = process_browser_cookies(paths["local_state"], paths["cookies"])
    write_to_file(output_dir, f"{browser}_cookies.txt", cookies)
    downloads = process_browser_downloads(paths["downloads"])
    write_to_file(output_dir, f"{browser}_downloads.txt", downloads)
    extensions = process_browser_extensions(paths["extensions"])
    write_to_file(output_dir, f"{browser}_extensions.txt", extensions)
    network_data = extract_chromium_network_data(paths["network_data"])
    write_to_file(output_dir, f"{browser}_network_data.txt", network_data)
    
    if browser == "Firefox":
        network_data = extract_firefox_network_data(paths["network_data"])
        write_to_file(output_dir, f"{browser}_network_data.txt", network_data)
        
    incognito = analyze_incognito_data()
    write_incognito_data_to_file(incognito, output_dir)
    temp_files = scan_temp_files(paths["temp_files"])
    write_to_file(output_dir, f"{browser}_temp_files.txt", temp_files)
    analyze_registry_and_prefetch(output_dir)
        
    print(f"All {browser} artifacts extracted successfully!")

def create_browser_timeline(browser_paths, output_dir):
    """Creates a timeline of browser activities combining history, downloads, and other events."""
    timeline_events = []
    
    try:
        # Get history events
        history = process_browser_history(browser_paths["history"])
        for entry in history:
            if isinstance(entry, str) and "Last Visited:" in entry:
                url = entry.split("URL: ")[1].split(", Last")[0]
                timestamp = entry.split("Last Visited: ")[1]
                timeline_events.append({
                    'timestamp': timestamp,
                    'event_type': 'Page Visit',
                    'details': url
                })
        
        # Get download events
        downloads = process_browser_downloads(browser_paths["downloads"])
        for entry in downloads:
            if isinstance(entry, str) and "Start Time:" in entry:
                file = entry.split("Downloaded File: ")[1].split(", Start")[0]
                timestamp = entry.split("Start Time: ")[1]
                timeline_events.append({
                    'timestamp': timestamp,
                    'event_type': 'Download',
                    'details': file
                })
        
        # Sort events by timestamp
        timeline_events.sort(key=lambda x: x['timestamp'])
        
        # Write timeline to file
        with open(os.path.join(output_dir, "browser_timeline.txt"), 'w', encoding='utf-8') as f:
            f.write("Browser Activity Timeline\n")
            f.write("=" * 50 + "\n\n")
            
            for event in timeline_events:
                f.write(f"[{event['timestamp']}] {event['event_type']}: {event['details']}\n")
                
        return "Browser timeline created successfully!"
    except Exception as e:
        return f"Error creating timeline: {str(e)}"

def analyze_search_terms(browser_paths, output_dir):
    """Analyzes search terms from browser history."""
    search_engines = {
        'google': 'google.com/search?q=',
        'bing': 'bing.com/search?q=',
        'yahoo': 'search.yahoo.com/search?p=',
        'duckduckgo': 'duckduckgo.com/?q='
    }
    
    search_terms = []
    try:
        history = process_browser_history(browser_paths["history"])
        
        for entry in history:
            if isinstance(entry, str) and "URL:" in entry:
                url = entry.split("URL: ")[1].split(", Last")[0]
                
                # Extract search terms from URLs
                for engine, pattern in search_engines.items():
                    if pattern in url:
                        query_start = url.find(pattern) + len(pattern)
                        query_end = url.find('&', query_start) if '&' in url[query_start:] else len(url)
                        search_term = url[query_start:query_end].replace('+', ' ')
                        
                        search_terms.append({
                            'engine': engine,
                            'term': search_term,
                            'timestamp': entry.split("Last Visited: ")[1] if "Last Visited:" in entry else "Unknown"
                        })
        
        # Analyze and write results
        with open(os.path.join(output_dir, "search_term_analysis.txt"), 'w', encoding='utf-8') as f:
            f.write("Search Term Analysis Report\n")
            f.write("=" * 50 + "\n\n")
            
            # Group by search engine
            for engine in search_engines.keys():
                engine_searches = [s for s in search_terms if s['engine'] == engine]
                if engine_searches:
                    f.write(f"\n{engine.title()} Searches:\n")
                    f.write("-" * 30 + "\n")
                    for search in engine_searches:
                        f.write(f"Term: {search['term']}\n")
                        f.write(f"Time: {search['timestamp']}\n\n")
            
            # Basic statistics
            f.write("\nSearch Statistics:\n")
            f.write("-" * 30 + "\n")
            f.write(f"Total Searches: {len(search_terms)}\n")
            for engine in search_engines.keys():
                count = len([s for s in search_terms if s['engine'] == engine])
                f.write(f"{engine.title()}: {count} searches\n")
                
        return "Search term analysis completed successfully!"
    except Exception as e:
        return f"Error analyzing search terms: {str(e)}"

def main():
    """Main function to handle menu-driven interaction."""
    # Parse arguments
    parser = argparse.ArgumentParser(description="Browser Data Extraction Tool")
    parser.add_argument('--output_dir', type=str, required=True, help="Directory to store extracted browser data.")
    args = parser.parse_args()
    output_dir = args.output_dir

    browsers = {
        "Brave": get_brave_paths(),
        "Opera": get_opera_paths(),
        "Firefox": get_firefox_paths()
    }

    while True:
        clear_screen()
        display_main_menu()
        try:
            browser_choice = int(input("Select a browser: "))
        except ValueError:
            print("Invalid input. Please enter a number.")
            continue

        if browser_choice == 4:
            print("Exiting the program. Goodbye!")
            sys.exit(0)
        
        selected_browser = list(browsers.keys())[browser_choice - 1]
        paths = browsers[selected_browser]

        if not paths:
            print(f"\n{selected_browser} browser not found.")
            input("\nPress Enter to return to the main menu.")
            continue

        while True:
            clear_screen()
            display_artifact_menu()
            try:
                artifact_choice = int(input(f"Select an option for {selected_browser}: "))
            except ValueError:
                print("Invalid input. Please enter a number.")
                continue

            status = extract_artifact(selected_browser, artifact_choice, paths, output_dir)
            if status == "BACK":
                break

if __name__ == "__main__":
    main()
