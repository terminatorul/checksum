# checksum
Compute various digest SHA-256, MD5, for files

# Usage

Checksum application to compute digests like SHA256 or MD5 for given file or input data. By repeating the options you can compute multiple digests for multiple files, and different digests for different files.
No input files on the command line means the standard input should be digested, unless it is a character device (the terminal), when the syntax will be shown. A file name of "-" also means standard input.
Use "--" on the command line to allow an input files with names like "--md5", that would otherwise be parsed as an option.

```
Sytax:
        checksum.exe --<digest> [passphrase] <input-files>...

Compute specified digest (checksum) for given input data
Where --<digest> [passphrase] can be one of:

      --hmac-md5 <passphrase>
      --hmac-sha1 <passphrase>
      --hmac-sha256 <passphrase>
      --md4
      --md5
      --pbkdf2-md5 <salt>
      --pbkdf2-sha1 <salt>
      --pbkdf2-sha256 <salt>
      --sha1
      --sha224
      --sha256
      --sha384
      --sha512
      --sha512-224
      --sha512-256

The default checksum is SHA256
```

# Building
## Prerequisites
    - conan
    - cmake
    - poco and dependencies (will be installed by conan if needed)

## Build commands
After `git clone` run the following commands. You may need to set up a conan profile first, if you never used the conan C++ package manager. Check the tutorial on https://docs.conan.io/ if for more info, or follow the instructions output by the `conan` command.
```
    mkdir build
    cd build
    conan install .. --output-folder . --build=missing --settings build_type=Release
    cmake .. -DCMAKE_TOOLCHAIN_FILE=conan_toolchain.cmake
    cmake --build . --config Release
