import os
import sys
import requests
import pwd
import grp
import stat
from bs4 import BeautifulSoup
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor
import argparse
import logging
from colorlog import ColoredFormatter


# TODO: Setup verbose/debug logging
# TODO: Add caching for duplicate tool hits
# TODO: Reimplement logging

def get_gtfobins():
    """
    Parses GTFObins website to get the list of binaries.
    This saves us from having to maintain a local copy of the GTFObins list or DDoSing the site.
    """
    
    req = requests.get(ENDPOINT)
    
    soup = BeautifulSoup(req.text, 'html.parser')
    gftobins = {}
    
    for row in soup.find_all("tr"):
        
        bin_tag = row.find("a", class_="bin-name")
        if not bin_tag:
            continue
        
        bin_name = bin_tag.text.strip()    
        functions = [li.text.strip() for li in row.find_all("li")]
        
        gftobins[bin_name] = functions

    return gftobins

def setup_logger(debug, verbose):
    """
    Sets up verbose/debug logging with colour formatting.
    """
    
    formatter = ColoredFormatter(
    "[%(log_color)s%(levelname)s%(reset)s] %(message)s",
    log_colors={
        "DEBUG":    "cyan",
        "INFO":     "green",
        "WARNING":  "yellow",
        "ERROR":    "red",
        "CRITICAL": "bold_red",
    })
    
    logger = logging.getLogger()
    
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.handlers = []  # Clear existing handlers
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING))

def main():
    
    global ENDPOINT, THREADS, vulnerable_only, cache, gtfobins
    
    ENDPOINT = 'https://gtfobins.github.io/'
    THREADS = 10
    
    parser = argparse.ArgumentParser(description="Check for GTFOBins in the PATH or from stdin.")
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug logging.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable debug logging.')
    parser.add_argument('-t', '--threads', type=int, default=THREADS, help='Number of threads to use for checking binaries.')
    parser.add_argument('-u', '--url', type=str, default=ENDPOINT, help='Base URL for GTFObins (default: http://gtfobins.github.io/). Useful for proxying.')
    parser.add_argument('-f', '--function', type=str, help='Function to check for in the binaries')    
    parser.add_argument('--offline', action='store_true', help='Run in offline mode - will not return descriptions/examples')
    parser.add_argument('--vulnerable', action='store_true', help='Only return confirmed vulnerable binaries that have S[U|G]ID bit or CAP_SET[U|G]ID capabilities enabled.')
    parser.add_argument('files', nargs='*', help='Files to check. If not provided, will read from stdin or PATH.')
    

    args = parser.parse_args()
    
    setup_logger(args.debug, args.verbose)
    
    ENDPOINT = args.url or ENDPOINT
    THREADS = args.threads or THREADS
    function = args.function or None
    vulnerable_only = args.vulnerable
    cache = {}

    files = []    
    gtfobins = get_gtfobins()
    
    if not sys.stdin.isatty():
        files.extend(sys.stdin.read().splitlines())
    else:
        paths = ':'.join(args.files) or os.getenv('PATH')
        for path in paths.split(os.pathsep):
            if os.path.isdir(path):
                all_files = []
                for dirpath, _, filenames in os.walk(path):
                    for file in filenames:
                        
                        file_path = os.path.join(dirpath, file)
                        try:
                            st = os.stat(file_path)
                        except Exception:
                            continue
                        if os.path.isfile(file_path) and os.access(file_path, os.X_OK) and file in gtfobins.keys():
                            if not function or any(function.lower() in f.lower() for f in gtfobins[file]):           
                                all_files.append(file_path)
                    
                files.extend(all_files)
            elif os.path.isfile(path) and os.access(path, os.X_OK) and file in gtfobins.keys():
                if not function or any(function.lower() in f.lower() for f in gtfobins[file]):
                    files.append(path)

    logger = logging.getLogger()
    logger.debug(f"Collected {len(files)} potential GTFObins. Retrieving details and running checks...")
    
    from concurrent.futures import ThreadPoolExecutor, as_completed
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        for file in files:
            executor.submit(check_file, file)            
    
def check_suid_enabled(file, elem, output):
    """
    Checks if the SUID bit is set on the given filename - if it exists.
    """

    elem = elem.get_text(strip=True) if elem is not None else "" 
    output = output or []

    if os.path.exists(file):
        if os.stat(file).st_mode & stat.S_ISUID: # If SUID set
            output.append(colored(elem + f" - Enabled with owner {pwd.getpwuid(os.stat(file).st_uid).pw_name}", "red", attrs=['bold']))
            return True
        elif os.stat(file).st_mode & stat.S_ISGID: # If SGID set
            output.append(colored(elem + f" - Enabled with owner group {grp.getgrgid(os.stat(file).st_gid).gr_name}", "red", attrs=['bold']))
            return True
        
        output.append(colored(elem, 'yellow', attrs=['bold']))
    return False

def check_cap_enabled(file, elem, output):
    """
    Checks if the CAP_SETUID and CAP_SETGID capabilities are enabled on the file.
    """

    import struct

    elem = elem.get_text(strip=True) if elem is not None else "" 
    output = output or []

    try:
        caps_attr = os.getxattr(file, "security.capability") # Throws exception when no caps
        caps = []

        # Assume capabilities is v2/3
        magic_etc = struct.unpack_from("I", caps_attr, 0)[0]
        perm_low, inher_low, perm_high, inher_high = struct.unpack_from("IIII", caps_attr, 4)
        permitted = (perm_high << 32) | perm_low
        inheritable = (inher_high << 32) | inher_low
        setuid_masks = {
         "CAP_SETUID": 1 << 7,
         "CAP_SETGID": 1 << 6
         }

        for capability in setuid_masks.keys():
            flags = ""
            if magic_etc & 1: # If caps are enabled, the LSB of the cap header
                flags += "e"
            if inheritable & setuid_masks[capability]:
                flags += "i"
            if permitted & setuid_masks[capability]:
                flags += "p"
            if flags.replace('e', ''):
                caps.append(f"{capability}+{flags}")
        
        if caps:
            output.append(colored(elem + f" - Enabled with {', '.join(caps)}", "red", attrs=['bold']))
            return True
        
    except OSError:
        # Log here
        pass    
    
    output.append(colored(elem, 'yellow', attrs=['bold']))    
    return False

def check_file(file):

    logger = logging.getLogger()

    global cache, vulnerable_only, gtfobins

    # Build out URI
    bin = file.split("/")[-1]
    url = ENDPOINT + 'gtfobins/' + bin + '/'

    # Prelim checks
    proceed = not vulnerable_only 
    proceed |= check_suid_enabled(file, None, None) and any([bit in gtfobins[bin] for bit in ["SUID", "SGID"]]) 
    proceed |= check_cap_enabled(file, None, None) and ("Capabilities" in gtfobins[bin]) 
    
    if proceed:
        
        # Check if this file is cached
        if bin in cache.keys():
            data = cache[bin]
            logger.debug(f"Cache hit for {bin}!")
        else:
            req = requests.get(url)
            if req.status_code != 200:
                return

            data = req.text
            cache[bin] = data
            logger.debug(f"Added {bin} to cache.")

        soup = BeautifulSoup(data, 'html.parser')

        output = []
        output.append(f"+{'-' * 100}+" + f"\n\033]8;;{url}\033\\{colored(file, 'green', attrs=['bold'])}\033]8;;\033\\\n" + f"+{'-' * 100}+")
        
        for elem in soup.find_all(["h2", "h3", "p", "pre", "code"]):
            
            # Parse them headers
            if elem.name in ["h2", "h3"]:

                # Special checks
                match elem.get_text(strip=True):

                    # TODO: Check vulnerability BEFORE we make the request to reduce traffic.
                    case "SUID" | "Limited SUID":
                        check_suid_enabled(file, elem, output)
                    case "Capabilities":
                        check_cap_enabled(file, elem, output)
                
                # case "Sudo": <- Not possible! 

                    case _:
                        
                        output.append(colored(elem.get_text(strip=True), 'yellow', attrs=['bold']))

            # Parse plaintext
            elif elem.name == "p":
                text_parts = []
                for child in elem.children:
                    if child.name == "code":
                        text_parts.append(f" {colored(child.get_text(), 'white', attrs=['bold'])} ")
                    else:
                        text_parts.append(child.get_text(strip=True))
                output.append("".join(text_parts))

            # Parse code
            elif elem.name == "pre":
                code_elem = elem.find("code")
                if code_elem:
                    code_text = code_elem.get_text()
                    bolded_block = "\n" + "".join(
                        [f"{colored(line, 'white', 'on_grey', attrs=['bold'])}\n" for line in code_text.splitlines() if line.strip() != ""]
                    )
                    output.append(bolded_block)

        print("\n".join(output))
        

if __name__ == "__main__":
    main()