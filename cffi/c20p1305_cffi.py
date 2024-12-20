################################################################################
#                                                                              #
# Copyright (C) 2021, goatpig.                                                 #
#  Distributed under the MIT license                                           #
#  See LICENSE-MIT or https://opensource.org/licenses/MIT                      #
#                                                                              #
################################################################################

"""
This is the CFFI setup file. Here all C methods and structs/typedefs that
need python access are first declared. The C code is then made available to
CFFI, which will invoke gcc to build the corresponding shared library. There
is also a feature to link to system and discoverable shared libs.

The CFFI model seems to favor shared libraries. It is preferable to only let
it build the narrow set of C functions that need exposed to Python and let it
link to the internal code dynamically.

The other option is to build the entire code as part of the CFFI shared lib,
which is longer and most likely innefficient if the C/C++ side needs access
to those definitions too.
"""

import cffi
import os
import optparse
import logging
import sys
import platform

parser = optparse.OptionParser(usage="%prog [options]\n")
parser.add_option("--libbtc_path", dest="libbtc_path", default="../../libbtc", type="str", help="path to libbtc source")
parser.add_option("--armory_path", dest="armory_path", default="../../BitcoinArmory", type="str", help="path to BitcoinArmory source")

CLI_OPTIONS = None
CLI_ARGS = None
(CLI_OPTIONS, CLI_ARGS) = parser.parse_args()

hkdf_path = "cppForSwig/hkdf"

#libbtc path
libbtc_path = os.path.join(CLI_OPTIONS.libbtc_path, "include")
libbtc_libpath = os.path.join(CLI_OPTIONS.libbtc_path, ".libs")
libbtca_path = os.path.join(libbtc_libpath, "libbtc.a")
secp256k1_path = os.path.join(CLI_OPTIONS.libbtc_path, "src/secp256k1/include")
if not os.path.exists(libbtc_path):
    sys.exit(f"could not find libbtc source (looked for: \"{libbtc_path}\")")

#armory path
armory_path = os.path.join(CLI_OPTIONS.armory_path, "cppForSwig")
if not os.path.exists(armory_path):
    sys.exit(f"could not find BitcoinArmory source (looked for: \"{armory_path}\")")

#chachapoly path
chachapoly_path = os.path.join(armory_path, "chacha20poly1305")

#hkdf path
hkdf_path = os.path.join(armory_path, "hkdf")

"""
cffi.FFI.cdef() takes the C declarations of the functions to pythonize (
one declaration per line).

It takes structures and typedefs as well but does not make them directly
available to Python. Custom make_new like functions that return the desired
struct/type have to be added. It's preferable to add those to a dedicated
C header for cffi's purposes, or declare them inline in the setup file, so
as to avoid polluting the original C headers.

The typical approach is to read the relevant C header files, strip them of
all precompiler directives and feed them to cdef as is. I am not comfortable
with this wide net approach. It is more work but manual inline declaration
of the strict set of functions that Python needs to see is a lot cleaner,
and less opaque for reviewers.
"""

ffi = cffi.FFI()
with open('cffi_declarations.cffi') as f:
    data = ''
    for line in f:
        if line.startswith('#'):
            continue
        data += line

    ffi.cdef(data)

# distutils in windows and linux take slightly different args
kwargs = {}
if platform.system() == 'Windows':
    kwargs = {
        "library_dirs" : [
            "../build/src",
        ],
        "libraries" : [
            "libc20p1305deps"
        ]
    }
else:
    kwargs = {
        "library_dirs" : [
            "../build/src",
            libbtc_libpath
        ],
        "runtime_library_dirs" : ["."],
        "libraries" : [
            "c20p1305deps",
            "btc"
        ]
    }

#set_source receives the distutils args
ffi.set_source(
    "c20p1305",
    r'''
    #include "cffi_cdecl.h"
    ''',

    #source file for the dedicated cffi code
    sources = ["cffi_cdef.c"],

    #include paths
    include_dirs = [
        "../src",
        libbtc_path,
        secp256k1_path,
        chachapoly_path,
        hkdf_path
    ],
    **kwargs
)

#this call generates c20p1305.c then feeds it to distutils
ffi.compile(verbose=True)
