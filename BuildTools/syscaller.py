import os
import subprocess
import sys
import time

class Colors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def display_logo():
    logo = r"""
                 ++****+++====                              
             =++++****++++===---:                           
             =++++****+++===---:::                          
            =++++****++++===---:::  +%                      
            =++++****+++===----::  -:---               ++=# 
           ==+++****++++===---:::  +:---===+++#=**#***++=:  
           =++++****+++===---:::  -:---====+++*******+++=:  
          *=+++****++++===---:::  +:---===++++***#***++=:   
          =++++****+++===----::+ -:---====+++*******+++=:   
          =+++****++++===---:::  +:---===++++***#***++=:    
         =++++****+++====---::: -:---====+++*******+++=:    
         =+++****:::=+==---:::  +:---===++++***#***+++:     
        =+::             :-::: =:---====+++********++=:     
             -***++++-      :  =:---===++++***#***++=:      
        ===++***++++===---     ::---===+++********++=:      
       -==+++***++++==---::.    :=-===++++***#***++-:       
      -===++***++++===--::..  *#    :++++*****=:::          
      -==+++***++++==---::.  +--==*              %**-       
     -===++***++++===--::..  *-===++++****####*****-        
     -==+++***++++==---::.   --===++++****###******-        
    ====++***++++===--::..  +-===++++****####*****-         
    -==+++***++++==---::.   --===++++****###******-         
    ===++****+++===--:::.  +-===++++****####*****-          
   -==+++***++++==---::.:  --===++++****###******-          
   ===++*****+++==--:::.  +-====+++****####*****-           
  -=+...         ..-::..  --===++++****###******-           
                     ..  =-====+++*****###*****=            
                         =-===++++****###******-            
                           :==+++*****###****=:             
                              ::*****##++:: 
    """
    print(f"{Colors.OKBLUE}{logo}{Colors.ENDC}")

def run_validation_check():
    print(f"{Colors.OKBLUE}Running Validation Check...{Colors.ENDC}")
    result = subprocess.run(['python', 'Validator/validator.py'], capture_output=True, text=True)
    print(result.stdout)
    input(f"{Colors.OKBLUE}Press Enter to Continue...{Colors.ENDC}")

def run_compatibility_check():
    print(f"{Colors.OKBLUE}Running Compatibility Check...{Colors.ENDC}")
    result = subprocess.run(['python', 'Compatibility/compatibility.py'], capture_output=True, text=True)
    print(result.stdout)
    input(f"{Colors.OKBLUE}Press Enter to Continue...{Colors.ENDC}")

def run_syscall_verification():
    print(f"{Colors.OKBLUE}Running Syscall Verification...{Colors.ENDC}")
    result = subprocess.run(['python', 'Verify/sysverify.py'])
    input(f"\n{Colors.OKBLUE}Press Enter to Continue...{Colors.ENDC}")

def run_syscall_obfuscation():
    print(f"{Colors.OKBLUE}Running Syscall Obfuscation...{Colors.ENDC}")
    result = subprocess.run(['python', 'Protection/sysobfuscate.py'], capture_output=True, text=True)
    print(result.stdout)
    input(f"{Colors.OKBLUE}Press Enter to Continue...{Colors.ENDC}")

def launch_gui():
    print(f"{Colors.OKBLUE}Launching SysCaller GUI...{Colors.ENDC}")
    subprocess.Popen(['python', 'GUI/sysgui.py'])
    sys.exit(0)

def main_menu():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        display_logo()
        print(f"{Colors.OKBLUE}=== SysCaller BuildTools CLI ==={Colors.ENDC}")
        print(f"{Colors.OKGREEN}1. Run Validation Check{Colors.ENDC}")
        print(f"{Colors.OKGREEN}2. Run Compatibility Check{Colors.ENDC}")
        print(f"{Colors.OKGREEN}3. Run Syscall Verification{Colors.ENDC}")
        print(f"{Colors.OKGREEN}4. Run Syscall Obfuscation{Colors.ENDC}")
        print(f"{Colors.OKGREEN}5. Launch SysCaller GUI{Colors.ENDC}")
        print(f"{Colors.OKGREEN}6. Exit{Colors.ENDC}")
        choice = input(f"{Colors.BOLD}Select an Option (1-6): {Colors.ENDC}")
        if choice == '1':
            run_validation_check()
        elif choice == '2':
            run_compatibility_check()
        elif choice == '3':
            run_syscall_verification()
        elif choice == '4':
            run_syscall_obfuscation()
        elif choice == '5':
            launch_gui()
        elif choice == '6':
            print(f"{Colors.FAIL}Exiting...{Colors.ENDC}")
            time.sleep(1)
            break
        else:
            print(f"{Colors.WARNING}Invalid Option. Please try Again.{Colors.ENDC}")
            time.sleep(1)

if __name__ == "__main__":
    main_menu()
