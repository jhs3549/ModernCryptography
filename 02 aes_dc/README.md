# AES Differential Cryptanalysis (DC)

This directory contains example code for a simplified differential cryptanalysis experiment.  
It demonstrates how ciphertext pairs with specific input differences can be used to recover key bits in a reduced-round AES-like cipher.

## Overview
- The code was written for educational use in a Windows (MSVC) environment.
- The implementation uses substitution and permutation layers similar to a toy SPN cipher.
- The main routine generates plaintext pairs, encrypts them, and counts how often output differences match the expected pattern.
- Key candidates are ranked by their differential count.

## Files
- `StdAfx.h`, `StdAfx.cpp` : precompiled header files used by MSVC.
- `TestAppDll.cpp` : main program containing S-box definitions, permutation logic, and the statistical counting procedure.

## Build
Open a new Visual Studio console project and add these files.  
Remove or adjust `__declspec(dllexport)` or `__declspec(dllimport)` declarations if not building a DLL.

## Usage
Run the compiled program in a console.  
It prints the count distribution for each subkey candidate and identifies the most probable key nibble.

## Note
This project is for demonstration and learning only.  
It does not implement full AES and must not be used for any practical cryptographic purpose.
