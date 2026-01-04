# Psychic Paper

AMFI/amfid entitlements check bypass, iOS sandbox escape.  
Patched in iOS 13.5 beta 3.

Write-up [here](https://siguza.github.io/psychicpaper/).

### Building

This repo also contains a tool I called `plparse`, that can be used to invoke three different XML/plist parsers present on macOS & iOS. Build with:

    make

And run as:

    plparse -c file.plist
    plparse -i file.plist
    plparse -x file.plist
    plparse -cix file.plist

### Linux, Windows, etc.

`plparse` can now be built for platforms other than Darwin, though only the IOKit plist flavour (`-i`) is supported.

This requires the `IOCFBootleg` submodule to be checked out:

    git submodule update --init

Then, for native builds:

    make

For cross-compiling, you might have to adjust compiler and flags:

    HOST_OS=... CC=... CFLAGS=... make

### License

[MPL2](https://github.com/Siguza/psychicpaper/blob/master/LICENSE) with Exhibit B.
