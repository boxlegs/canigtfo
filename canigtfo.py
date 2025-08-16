import os
import sys
import requests
import pwd
import grp
import markdown
import stat
from bs4 import BeautifulSoup
from termcolor import colored

ENDPOINT= 'https://gtfobins.github.io/gtfobins/'

def main():
    
    files = []
    
    if not sys.stdin.isatty():
        files.extend(sys.stdin.read().splitlines())
    
    
    if len(sys.argv) > 1:
    
        if os.path.isdir(sys.argv[1]):
            all_files = []
            for dirpath, dirnames, filenames in os.walk(sys.argv[1]):
                for file in filenames:
                    all_files.append(os.path.join(dirpath, file))
            files.extend(all_files)
        else:
            files.extend(sys.argv[1:])
        
        
    # Check if directory exists 
    
    for file in files:
        url = f'{ENDPOINT + file.split("/")[-1]}/'
        req = requests.get(url)
        if req.status_code == 200:
            soup = BeautifulSoup(req.text, 'html.parser')
   
            print(f"+{'-' * 100}+" + f"\n\033]8;;{url}\033\\{colored(file, 'green', attrs=['bold'])}\033]8;;\033\\\n" + f"+{'-' * 100}+")
            
            output = []
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