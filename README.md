# ntlmpwnd
Check NTLM password hashes against haveibeenpwned list

Source code for free pascal (fpc) https://www.freepascal.org/ which takes
a list of NTLM hashes from https://haveibeenpwned.com/Passwords and compares
with your own list of NTLM hashes.

The program has been designed to require low memory and CPU, currently it does
not need more than +/- 400 MB of RAM and it runs in single core, so no threads 
library is needed.

Some details on performance, running the program in a 2012 Intel i7 with a
mechanic harddisk.

Time to preprocess source hashes list:  
    10 mins and 30 seconds. Mostly bound by HD performance.  
Final database size:  
    10 Gigabytes in 32 files.  

This first process is needed to be done once.  

User NTLM hashes checking speed (all positive):  
    On a cold drive 237,500 hashes checked in 92 seconds @ 2550 h/s  
    On a warm drive 237,500 hashes checked in 20 seconds @ 11800 h/s  

****

    NTLM hashes PWND check. (c) 2020 joshyfun (at host) gmail.com. License LGPL.

    Usage: ntlmpwnd.exe -h --help --generate-blocks --check-users [--bits={n}] [--hashes-path={path}]  

    -h --help               Show this help page (help a bit longer).  
    --generate-blocks       Generate blocks of PWND hashes.  
      --pwndlist={file}     List of PWND hashes.  
    --check-users           Generate blocks of PWND hashes.  
      --userslist={file}    List of user names:hashes.  
    --check-password={pass} Check one password against the pwndlist.  
    --bits                  Bits used to split the PWND list and reduce memory,  
                            by default 5 bits, so 32 slices.  
    --hashes-path={path}    Where hashes post-processed will be stored or loaded,  
                            stored when "--generate-blocks" and loaded for "check-users".  
    --get-ntlm-hash={pass}  Calculate the NTLM password hash.  

    pwndlist file format:
    
    0123456789ABCDEF0123456789ABCDEF:nnnnn
    
    Where "0123456789ABCDEF0123456789ABCDEF" is NTLM hash in hexadecimal
    and "nnnnn" is a number related with the hash.
    
    userlist file format.
    
    john.doe:0123456789ABCDEF0123456789ABCDEF
    
    Where "john.doe" is the user name (":" is prohibited)
    and "0123456789ABCDEF0123456789ABCDEF" is the user's NTLM hash in hexadecimal.  
