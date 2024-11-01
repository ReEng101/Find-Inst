import r2pipe
import os
import re
import platform
import subprocess
import sys

def clear_console():
    os.system('cls' if platform.system() == 'Windows' else 'clear')

clear_console()

def install_and_import(package):
    try:
        __import__(package)
    except ImportError:
        print(f"'{package}' is not installed. Installing now...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"'{package}' has been installed successfully.")
    finally:
        globals()[package] = __import__(package)

install_and_import('r2pipe')

wlcm_msg = """\033[38;5;208m
 _____ _           _   ___           _   
|  ___(_)_ __   __| | |_ _|_ __  ___| |_ 
| |_  | | '_ \ / _` |  | || '_ \/ __| __|
|  _| | | | | | (_| |  | || | | \__ \ |_ 
|_|   |_|_| |_|\__,_| |___|_| |_|___/\__|   V1.1\033[0m"""

print(wlcm_msg)
print("\033[34m\n↯ Big Thanks to sir Kirlif' For pptool\033[0m")
print("\033[34m➜ This Tool Is Designed By Mohamed Abozaid To Help Patching libapp.so In Obfuscated Flutter Apps.\n\033[0m")


def get_app_so_path():
    path = input("\033[93m◉ Please enter the path to libapp.so\n(or press Enter to use the default path): \033[0m").strip()
    if not path:
        path = "/storage/emulated/0/MT2/apks/libapp.so"
        print("\033[93m\n☛ Default path selected: /storage/emulated/0/MT2/apks/libapp.so\n\033[0m")
    return path

def get_string_address():
    str_addr = input("\033[1;36m◉ Please enter the string address from pp.txt file: \033[0m").strip()
    return str_addr
    
def reg_choice():
    choices = '''
\033[35mWhat do you want to search for (choose by number) ?
[1] add x0, x22, 0x30 (specified)
[2] add reg1, reg2, 0x30 (global)
⇒ \033[0m'''
    choice = input(choices).strip()
    if choice == '1':
        return r'add\s+x0,\s+x22,\s+0x30'
    elif choice == '2':
        return r'add\s+x\d+,\s+x\d+,\s+0x30'
    else:
        print('\033[91m\n⚠ Wrong Choice\033[0m')
        return None

def run_pptool(app_so, str_addr):
    cmd = f"pptool -cd {app_so} {str_addr}"
    result = os.popen(cmd).read()
    return result

def get_func_addr(ppout):
    pattern = r'･\d+\s+(0x[0-9a-fA-F]+)'
    return re.findall(pattern, ppout)

def analyze(r2, funcs_addrs, regex):
    results = []
    for addr in funcs_addrs:
        try:
            r2.cmd(f's {addr}')
            r2.cmd('af')
            instruction_srch = r2.cmd("pdr")
            for line in instruction_srch.splitlines():
                if re.search(regex, line):
                    instruction_addr = re.search(r"0x[0-9A-Fa-f]{,10}", line)
                    if instruction_addr:
                        results.append((addr, instruction_addr.group()))
        except Exception as err:
            print(f'\033[91m\n⚠ An error occurred during analysis: {err}\033[0m')
    return results

def main():
    app_so = get_app_so_path()
    str_addr = get_string_address()
    ppout = run_pptool(app_so, str_addr)
    funcs_offsets = get_func_addr(ppout)
    regex = reg_choice()

    if regex is None:
        return 

    if not funcs_offsets:
        print("\n\033[4;91m\n⚠ No valid offsets found in pptool output.\033[4;0m")
        return
    
    try:
        r2 = r2pipe.open(app_so, flags=['-2', '-w', '-e bin.cache=true'])
    except Exception as e:
        print(f"\n\033[91m\n⚠ Failed to open the binary with r2pipe: {e}\033[0m")
        return
    
    results = analyze(r2, funcs_offsets, regex)
    if results:
        print("\n\033[92m➩ Matching Instructions:\033[0m")
        for addr, instr in results:
            print(f"➢ \033[92mFunction Address:\033[0m {addr}, \033[92mInstruction:\033[0m {instr}")
    else:
        print("\n\033[91m⚠ No matching instructions found.\033[0m")

if __name__ == "__main__":
    main()