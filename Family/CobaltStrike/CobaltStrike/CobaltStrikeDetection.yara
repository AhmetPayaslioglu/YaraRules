rule Cobaltstrike1 {

   meta:
      author = "Ahmet Payaslioglu | Binalyze DFIR LAB"
      date = "2022-08-02"
      description = "Cobalt Strike Detection"

   strings:
      $x1 = "powershell -nop -exec bypass -EncodedCommand \"%s\"" fullword ascii
      $s2 = "%d is an x86 process (can't inject x64 content)" fullword ascii
      $s3 = "%d is an x64 process (can't inject x86 content)" fullword ascii
      $s4 = "Could not open process token: %d (%u)" fullword ascii
      $s5 = "could not open process %d: %d" fullword ascii
      $s6 = "Failed to impersonate logged on user %d (%u)" fullword ascii
      $s7 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/'); %s" fullword ascii
      $s8 = "IEX (New-Object Net.Webclient).DownloadString('http://127.0.0.1:%u/')" fullword ascii
      $s9 = "Could not open process: %d (%u)" fullword ascii
      $s10 = "could not run command (w/ token) because of its length of %d bytes!" fullword ascii
      $s11 = "could not spawn %s (token): %d" fullword ascii
      $s12 = "could not create remote thread in %d: %d" fullword ascii
      $s13 = "could not spawn %s: %d" fullword ascii
      $s14 = "Failed to get token" fullword ascii
      $s15 = "could not write to process memory: %d" fullword ascii
      $s16 = "Failed to impersonate token from %d (%u)" fullword ascii
      $s17 = "Command length (%d) too long" fullword ascii
      $s18 = "could not allocate %d bytes in process: %d" fullword ascii
      $s19 = "Could not connect to pipe (%s): %d" fullword ascii
      $s20 = "Could not open service control manager on %s: %d" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and ( 1 of ($x*) and 4 of them )
      ) or ( all of them )
}

rule Cobaltstrike2  {

   meta:
      author = "Ahmet Payaslioglu | Binalyze DFIR LAB"
      date = "2022-08-02"
      description = "Cobalt Strike Detection"

   strings:
      $s1 = "ppid %d is in a different desktop session (spawned jobs may fail). Use 'ppid' to reset." fullword ascii
      $s2 = "could not adjust permissions in process: %d" fullword ascii
      $s3 = "Could not set PPID to %d: %d" fullword ascii
      $s4 = "move failed: %d" fullword ascii
      $s5 = "copy failed: %d" fullword ascii 
      $s6 = "Could not set PPID to %d" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and ( all of them )
      ) or ( all of them )
}


rule Cobaltstrike3 {

   meta:
      author = "Ahmet Payaslioglu | Binalyze DFIR LAB"
      date = "2022-08-02"
      description = "Cobalt Strike Detection"

   strings:
      $s2 = " constructor or from DllMain." fullword ascii
      $s5 = "%s as %s\\%s: %d" fullword ascii
      $s6 = "AQAPRQVH1" fullword ascii
      $s13 = "he appropriate bitmask.  For example:  " fullword ascii
      $s14 = "LibTomMath" fullword ascii
      $s15 = "%s&%s=%s" fullword ascii 
      $s16 = "sysnative" fullword ascii 
      $s17 = "tSVWjD^V3" fullword ascii
      $s18 = "?%s=%s" fullword ascii 
      $s19 = "AXAX^YZAXAYAZH" fullword ascii
      $s20 = "%02d/%02d/%02d %02d:%02d:%02d" fullword ascii 
      $s25 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii
      $s26 = "  VirtualProtect failed with code 0x%x" fullword ascii
      $s27 = "  Unknown pseudo relocation protocol version %d." fullword ascii
      $s29 = "  Unknown pseudo relocation bit size %d." fullword ascii
      $s30 = "libgcj-12.dll" fullword ascii 
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and ( 8 of them )
      ) or ( all of them )
}