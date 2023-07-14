from pwn import *
import sys

# Function to display the banner
def display_banner():
    banner = """
 .d8888b.                            888            888    888                   888      
d88P  Y88b                           888            888    888                   888      
888    888                           888            888    888                   888      
888        888d888  8888b.   .d8888b 888  888       8888888888  8888b.  .d8888b  88888b.  
888        888P"       "88b d88P"    888 .88P       888    888     "88b 88K      888 "88b 
888    888 888     .d888888 888      888888K        888    888 .d888888 "Y8888b. 888  888 
Y88b  d88P 888     888  888 Y88b.    888 "88b       888    888 888  888      X88 888  888 
 "Y8888P"  888     "Y888888  "Y8888P 888  888       888    888 "Y888888  88888P' 888  888 
                                                                                          
                                                                                          
"""

    print(banner)

if len(sys.argv) != 2:
    print("INVALID Arguments")
    print(">> {} <sha256sum>".format(sys.argv[0]))
    exit()

wanted_hash = sys.argv[1]
password_file = "/usr/share/wordlists/rockyou.txt"
attempts = 0

display_banner()

with log.progress("Attempting to crack: {}!\n".format(wanted_hash)) as p:
    with open(password_file, "r", encoding='latin-1') as password_list:
        for password in password_list:
            password = password.strip("\n").encode('latin-1')
            password_hash = sha256sumhex(password)

            p.status("[{}] {} = {}".format(attempts, password.decode('latin-1'), password_hash))

            if password_hash == wanted_hash:
                p.success("[+] Password hash found after {} attempts!\n [+] Plaintext found: {}\n [+] from the hash {}!".format(attempts, password.decode('latin-1'), password_hash))
                exit()

            attempts += 1

    p.failure("[-] Password Hash Not Found")
