# AES Linear Cryptanalysis (LC)

This directory contains code for a simplified linear cryptanalysis experiment.  
It explores how linear masks and parity statistics can reveal information about key bits in a toy AES-like cipher.

## Overview
- The code uses 4-bit S-box and bit permutation layers to build a small SPN structure.
- A large number of plaintexts are encrypted, and output bits are analyzed under selected input and output masks.
- For each subkey candidate, the program counts how often the parity of the masked bits satisfies the expected linear relation.
- The candidate with the highest bias indicates the most likely subkey.

## Files
- `StdAfx.h`, `StdAfx.cpp` : precompiled header files for MSVC.
- `TestAppDll.cpp` : main code performing the masking and counting procedure.

## Build
Build in Visual Studio as a console application.  
If necessary, remove DLL import/export directives and include a local `Encryption()` function for standalone use.

## Usage
Run the program to perform linear analysis.  
It outputs the count for each subkey hypothesis and shows which candidate best matches the expected correlation.

## Note
This project is an educational implementation for understanding linear cryptanalysis.  
It is not a complete AES implementation and should not be used for real encryption or key recovery outside a lab context.
