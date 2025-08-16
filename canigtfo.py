import os
import sys
import requests
import pwd
import grp
import markdown
import socket
import stat
from bs4 import BeautifulSoup
from termcolor import colored
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import time 

WRITABLE_ONLY = False
ENDPOINT= f'http://gtfobins.github.io/gtfobins/'
DELAY = 3


# TODO: Persistent cache
cache = {}

def main():
    
    
    # TODO: Add logs
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    files = []
    
    if not sys.stdin.isatty():
        files.extend(sys.stdin.read().splitlines())
    else:
        paths = sys.argv[1] if len(sys.argv) > 1 else None
        paths = paths or os.getenv('PATH')
        for path in paths.split(os.pathsep):
            if os.path.isdir(path):
                all_files = []
                for dirpath, dirnames, filenames in os.walk(path):
                    for file in filenames:
                        
                        file_path = os.path.join(dirpath, file)
                        try:
                            # TODO: Filter on Sudo, SUID, etc
                            st = os.stat(file_path)
                        except Exception:
                            continue
                        if os.path.isfile(file_path) and os.access(file_path, os.X_OK) and '.' not in file:
                            all_files.append(file_path)
                    
                files.extend(all_files)
            else:
                files.extend(path)
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        for file in files:
            executor.submit(check_file, file)            
    

def check_file(file):
    
    # Build out URI
    bin = file.split("/")[-1]
    url = ENDPOINT + bin + '/'
    
    # Check for a cache hit
    if bin in cache.keys():
        data = cache[bin]
    else:    
        req = requests.get(url, headers={'Host: gtfobins.github.io'}, follow_redirects=True)
        if req.status_code != 200:
            print(req)
            if req.status_code == 403:
                DELAY *= 2
                logging.error(f"We're getting rate limited. Doubling delay to {DELAY} seconds.")
                
            time.sleep(DELAY)
            return
        cache[bin] = req.text
        data = req.text
                
    soup = BeautifulSoup(data, 'html.parser')
    
    output = []
    output.append(f"+{'-' * 100}+" + f"\n\033]8;;{url}\033\\{colored(file, 'green', attrs=['bold'])}\033]8;;\033\\\n" + f"+{'-' * 100}+")
    
    for elem in soup.find_all(["h2", "h3", "p", "pre", "code"]):
        
        # Parse them headers
        if elem.name in ["h2", "h3"]:
            
            # SUID/SGID bit check
            if "SUID" in elem.get_text(strip=True) and os.path.exists(file) and (os.stat(file).st_mode & (stat.S_ISGID | stat.S_ISUID)):
                if os.stat(file).st_mode & stat.S_ISUID:
                    output.append(colored(elem.get_text(strip=True) + f" - ENABLED with owner {pwd.getpwuid(os.stat(file).st_uid).pw_name}", 'red', attrs=['bold']))
                elif os.stat(file).st_mode & stat.S_ISGID:
                    output.append(colored(elem.get_text(strip=True) + f" - ENABLED with owners {grp.getgrgid(os.stat(file).st_gid).gr_name}", 'red', attrs=['bold']))    
                
            else:
                output.append(colored(elem.get_text(strip=True), 'yellow', attrs=['bold']))

        elif elem.name == "p":
            text_parts = []
            for child in elem.children:
                if child.name == "code":
                    text_parts.append(f" {colored(child.get_text(), 'white', attrs=['bold'])} ")
                else:
                    text_parts.append(child.get_text(strip=True))
            output.append("".join(text_parts))

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