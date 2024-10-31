import os
import r2pipe
import re
import platform

def clear_console():
    os.system('cls' if platform.system() == 'Windows' else 'clear')

clear_console()

wlcm_msg = """\033[38;5;208m
 _____ _           _   ___           _   
|  ___(_)_ __   __| | |_ _|_ __  ___| |_ 
| |_  | | '_ \ / _` |  | || '_ \/ __| __|
|  _| | | | | | (_| |  | || | | \__ \ |_ 
|_|   |_|_| |_|\__,_| |___|_| |_|___/\__|   V1\033[0m"""

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
\033[35mWhat do you want to search for (chose by number) ?
[1] add x0, x22, 0x30 (specified)
[2] add reg1, reg2, 0x30 (global)
⇒ \033[0m'''
    choice = str(input(choices).strip())
    if choice == '1' :
        regex = r'(?P<offset>0x[0-9a-fA-F]+)\s+.*add\s+x0,\s+x22,\s+0x30'
        return regex
    elif choice == '2' :
        regex = r'(?P<offset>0x[0-9a-fA-F]+)\s+.*add\s+x\d+,\s+x\d+,\s+0x30'
        return regex
    else :
        print('\033[91m\n⚠Wrong Choice\033')

def run_pptool(app_so, str_addr):
    cmd = f"pptool -cd {app_so} {str_addr}"
    result = os.popen(cmd).read()
    return result

def get_func_addr(ppout):
    pattern = r'･\d+\s+(0x[0-9a-fA-F]+)'
    funcs_addrs = re.findall(pattern, ppout)
    return funcs_addrs

def analyze(r2, funcs_addrs, regex):
    results = []
    try:
        for addr in funcs_addrs:
            r2.cmd(f's {addr}')
            r2.cmd('af')
            disassembly = r2.cmd("pdr")
            instruction_pattern = re.compile(f'{regex}')
            match = instruction_pattern.search(disassembly)
            if match:
                results.append((addr, match.group('offset')))
    except Exception as err:
        print(f'\033[91m\n⚠ An error occurred during analysis: {err}\033[0m')
    return results

def main():
    app_so = get_app_so_path()
    str_addr = get_string_address()
    ppout = run_pptool(app_so, str_addr)
    funcs_offsets = get_func_addr(ppout)
    regex = reg_choice()
    if regex == r'(?P<offset>0x[0-9a-fA-F]+)\s+.*add\s+x0,\s+x22,\s+0x30':
        msg = '↯ add x0, x22, 0x30'
    elif regex == r'(?P<offset>0x[0-9a-fA-F]+)\s+.*add\s+x\d+,\s+x\d+,\s+0x30':
        msg = '↯ add reg1, reg2, 0x30'
    msg = msg
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
        for func_addr, instruction_offset in results:
            print(f"\n\033[1;92m{msg} found at offset: {instruction_offset} in Function: {func_addr}\033[1;0m")
    else:
        print("\033[4;91m\n⚠ Search results: 0 for this instruction\033[0m")

if __name__ == "__main__":
    main()