#!/bin/bash
#
# This script is meant to uninstall Cipher installed on a Linux, Mac, or MinGW distribution.
#
# NOTE - cipher_remove_manifest_files below deletes every file listed in install_manifest.txt.
# The manifest lists files only, never directories, so the two directories Cipher creates for
# itself have to be derived from it and removed separately:
#
#   - the header tree,       <includedir>/cipher
#   - the CMake package dir, <libdir>/Cipher (or <prefix>/CMake on Windows)
#
# Neither location can be assumed: they follow CMAKE_INSTALL_INCLUDEDIR and CMAKE_INSTALL_LIBDIR,
# so the library directory may be lib, lib64 or lib/<arch-triplet>. Both are therefore derived by
# locating a file that Cipher is known to install and stripping that file's known trailing path,
# which leaves the directory to remove no matter how the prefix is laid out.
#
# Searching for a path component instead would not be safe: a component such as "/Cipher" can
# also occur inside the install prefix (-DCMAKE_INSTALL_PREFIX=$HOME/Cipher), and cutting there
# names a directory far above the install tree.
#
# The two are then removed differently, because only one of them is certainly ours:
#
#   - <includedir>/cipher is CMAKE_INSTALL_INCLUDEDIR plus a hardcoded "cipher" component, so
#     no setting can aim it at a directory another package shares. It is taken with everything
#     below it, which also clears headers an earlier install left behind.
#
#   - the CMake package directory is Cipher_INSTALL_CMAKEDIR verbatim, which the user chooses freely
#     and which find_package is happy to locate in a shared directory: -DCipher_INSTALL_CMAKEDIR=cmake,
#     or "." for the install prefix itself, are both working layouts. Removing that recursively
#     would take unrelated packages - or the entire prefix - with it, so only the directories the
#     manifest has already emptied are pruned and anything else found there is left alone.
#
# The enclosing <includedir>, <libdir> and <bindir> are deliberately left in place: they are
# shared with other packages, and their Cipher contents are already gone with the manifest.
# ---------------------------------------------------------------------------------------------------------------------

# install_manifest.txt is newline-separated and its entries may contain spaces (a Windows
# install under "C:\Program Files\..." for one), so it has to be read a line at a time. "xargs"
# cannot be used: it splits on spaces as well as newlines, and with "rm -f" the resulting
# failures are silent, leaving those files installed. A trailing CR is stripped in case the
# manifest was written with CRLF line endings.
function cipher_manifest_line() {
    local line
    while IFS= read -r line || [[ -n "${line}" ]]; do
        line="${line%$'\r'}"
        [[ -n "${line}" ]] && printf '%s\n' "${line}"
    done
}

function cipher_remove_manifest_files() {
    local line count=0
    while IFS= read -r line; do
        rm -vf -- "${line}"
        count=$((count + 1))
    done < <(cipher_manifest_line < install_manifest.txt)
    echo "Removed ${count} file(s) listed in install_manifest.txt"
}

# Print the directory holding the first manifest entry that ends in $1, with $1 stripped off.
# Prints nothing when the manifest has no such entry or the directory is already gone.
function cipher_dir_of() {
    local suffix="$1"
    local line match
    while IFS= read -r line; do
        if [[ "${line}" == *"${suffix}" ]]; then
            match="${line%"${suffix}"}"
            break
        fi
    done < <(cipher_manifest_line < install_manifest.txt)

    if [[ -n "${match}" && -d "${match}" ]]; then
        printf '%s\n' "${match}"
    fi
}

# Remove that directory and everything below it. Only for a directory Cipher owns outright.
function cipher_remove_dir_of() {
    local match
    match="$(cipher_dir_of "$1")"
    if [[ -n "${match}" ]]; then
        echo "Removing: ${match}"
        rm -vr -- "${match}"
    else
        echo "Nothing to remove for *$1"
    fi
}

# Remove that directory only as far as it is empty, for a directory that may be shared with other
# packages. -depth visits children first, so nested directories the manifest emptied go before
# their parents; rmdir refuses the rest, and its complaints about them are the expected case.
function cipher_prune_dir_of() {
    local match
    match="$(cipher_dir_of "$1")"
    if [[ -z "${match}" ]]; then
        echo "Nothing to remove for *$1"
        return
    fi

    echo "Pruning: ${match}"
    find "${match}" -depth -type d -exec rmdir -- {} + 2>/dev/null
    if [[ -d "${match}" ]]; then
        echo "Kept: ${match} still holds files this install did not put there"
    fi
}

# config.h is installed as <includedir>/cipher/config.h, and CipherConfig.cmake
# sits directly in the CMake package directory.
function cipher_remove_dirs() {
    cipher_remove_dir_of "/config.h"
    cipher_prune_dir_of "/CipherConfig.cmake"
}

function uninstall_unix() {
    cipher_remove_manifest_files
    cipher_remove_dirs
}


function uninstall_mingw() {
    echo "WARNING - Running uninstall on MinGW requires admin priviledges"

    # Delete the installed files first. This branch used to remove whole directories instead,
    # which relied on the import libraries and the DLLs sharing one directory; the DLLs now go
    # to CMAKE_INSTALL_BINDIR, so go by the manifest as the unix branch does.
    cipher_remove_manifest_files
    cipher_remove_dirs

    echo "Be sure to cleanup your env PATH"
}

# Everything below reads install_manifest.txt, so stop here if there is nothing to act on. This
# script runs with root privileges and deletes directories, so bail out rather than continue with
# paths derived from a manifest that could not be read.
if [[ ! -s install_manifest.txt ]]; then
    echo "Nothing in install_manifest.txt to be uninstalled!"
    echo "Run this from the build directory that was used for 'make install'."
    exit 0
fi

# On MinGW sudo is not a valid command, and the user needs to run this in a mingw terminal with
# admin priviledges. Match the Windows-like environments explicitly rather than testing for
# Linux/Darwin, so that any other unix (FreeBSD, SunOS, ...) takes the unix path. Note that the
# previous form, [[ "$osname" -eq "Linux" ]], compared the strings numerically: -eq evaluates
# both sides as arithmetic, where an undefined name such as Linux is 0, so it matched anything
# that also evaluated to 0 and raised an arithmetic syntax error on the rest.
osname=$(uname -s)
case "${osname}" in
    MINGW*|MSYS*|CYGWIN*) uninstall_mingw ;;
    *)                    uninstall_unix ;;
esac

unset osname
