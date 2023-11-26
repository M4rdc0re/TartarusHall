# TartarusHall: EDR Evasion

### Features
* API Hashing using CRC32
* Indirect syscalls, utilizing HellHall with ROP gadgets (for the unhooking part).
* DLL unhooking from \KnwonDlls\ directory, with no RWX sections.
* RC4 payload encryption
* Brute forcing the decryption key
* No CRT library imports

### Usage
* Hasher to calculate syscall hashes
* ProtectedKey to generate a encrypted key
* KeyGuard to encrypt payload

### Credits
* Maldev Academy (https://maldevacademy.com/)
* HellsGate (https://github.com/am0nsec/HellsGate)
* TartarusGate (https://github.com/trickster0/TartarusGate)
* HellsHall (https://github.com/Maldev-Academy/HellHall)
* AtomLdr (https://github.com/NUL0x4C/AtomLdr)
* APCLdr (https://github.com/NUL0x4C/APCLdr)
