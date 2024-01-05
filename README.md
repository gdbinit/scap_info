```
   ____________   ___    ____     ___
  / __/ ___/ _ | / _ \  /  _/__  / _/__
 _\ \/ /__/ __ |/ ___/ _/ // _ \/ _/ _ \
/___/\___/_/ |_/_/    /___/_//_/_/ \___/
```
SCAP Info  
(c) fG! 2024 - reverser@put.as - https://reverse.put.as

A small utility to extract version information from Apple EFI SCAP files.

Latest Apple SCAP file names don't contain version information anymore so this util is able to extract it directly from the files.

Older versions don't contain the Apple ROM Information file and only the EFI BIOS version.

The ROM Version which was used in filenames also seems stuck in the same number and now EFI version is used to distinguish the versions.

A complete mess for which I don't know the reason.

Not much error checking found in this code so not ready to deal with hostile files. We just want to verify official Apple files anyway.

It is able to verify the RSA signature to validate if the files have been tampered with.

Outputs JSON either to console or file, can parse individual files or folders containing SCAP files. It will walk the whole folder tree below the given path.

Tested on macOS with Go 1.20+. Should work at least on Linux :-).

Have fun,  
fG!
