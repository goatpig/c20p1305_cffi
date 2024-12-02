**

## c20p1305_cffi

**

**About**

c20p1305_cffi is a Python package offering CFFI chacha20poly1305 and secp256k1.

It uses OpenLDAP's c20p1305 implementation (carried in BitcoinArmory) and Bitcoin Core's secp256k1 library, via libbtc (https://github.com/libbtc/libbtc).

It is used to implement AEAD over the communication sockets between the ArmoryQt client and CppBridge child process in the BitcoinArmory project (https://github.com/goatpig/BitcoinArmory)

## Build Instructions

**Dependencies**

To build this package, you first need to grab its dependencies:
- libbtc: https://github.com/libbtc/libbtc
- BitcoinArmory: https://github.com/goatpig/BitcoinArmory

By default the build system looks for the dependencies in the parent folder:

    parent
	    |- libbtc
	    |- BitcoinArmory
	    |- c20p1305_cffi

You can give it the absolute paths using `--libbtc-path` and `--armory-path`

NOTE:
- You will have to build libbtc prior to building this package.
- You will first have to build a shim library (c20p1305_deps), which is then fed to CFFI to produce the python library. That final library has to be copied in the BitcoinArmory/armoryengine to complete the process.
- There is no need to rebuild this package across different versions of BitcoinArmory, this code rarely if ever changes.

**Steps for building on Linux**


You will need the following tools installed:
- cmake
- autotools
- python3 with cffi

1. From the libbtc folder, build it with -fPIC:

```
	sh autogen.sh
    CFLAGS="-fPIC -g" ./configure
    make
```

2. From the c20p1305_cffi folder, build the shim library:
```
   mkdir build
   cd build
   cmake ..
   make
```
3. From c20p1305_cffi/cffi, build the Python package:
```
python c20p1305_cffi.py
```
4. You should now have a file named c20p1305-cpython-*your-py-version*-linux-gnu.so, which you can copy to BitcoinArmory/engine

**Steps for building on Windows**

NOTE: The Python runtime is .py script compiler and interpreter written in C. It can only make use of C code (bound via CFFI) that was built with the same compiler. On Windows, Python is built with the official Microsoft compiler, MSVC. However, the cryptographic libraries used in this project do not build on MSVC.
The solution is to first build a shim static library with all the useful code via MSYS2, then build a definition build file for it that MSVC can read from to generate the CFFI library.

- MSVC: 
	We need the native Windows C/C++ toolset. Grab MSCV Community here: https://visualstudio.microsoft.com/downloads/
- MSYS2: 
	We build libbtc and the shim library via msys2: https://www.msys2.org/
	We exclusively use the MINGW64 environment. Make sure you have the following packages installed before progressing further:
	- cmake
	- ninja
	- autotools
	
- Python3:
	You need to setup python3 on your Windows machine and install cffi (consider using a venv and pip)
	
1. Building the shim library
	From the MSYS2 MINGW64 prompt, browse to the libbtc source and build it:
	```
	sh autogen.sh
	./configure
	make
	```
	Then browse to the c20p1305 source and build the shim lib:
	```
	mkdir build
	cd build
	cmake ..
	ninja	
	```
2. Build the definition file
	From Windows PowerShell, within the c20p1305/build/src folder:
	`lib.exe /MACHINE:x64 /def:c20p1305_deps.def`
3. Build the CFFI package
	Still from Windows PowerShell, within the c20p1305/cffi folder:
	`python c20p1305_cffi.py`
4. You should have a c20p1305.cpython-*your-py-version*-mscv.dll, copy it to BitcoinArmory/armoryengine
	
