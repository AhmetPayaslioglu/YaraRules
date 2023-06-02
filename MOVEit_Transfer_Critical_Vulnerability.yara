rule MOVEit_Transfer_exploit_webshell_aspx {

    meta:

        date = "2023-06-01"
        description = "Detects indicators of compromise in MOVEit Transfer exploitation."
        author = "Ahmet Payaslioglu - Binalyze DFIR Lab"
        hash1 = "44d8e68c7c4e04ed3adacb5a88450552"
        hash2 = "a85299f78ab5dd05e7f0f11ecea165ea"
        reference1 = "https://www.reddit.com/r/msp/comments/13xjs1y/tracking_emerging_moveit_transfer_critical/"
        reference2 = "https://www.bleepingcomputer.com/news/security/new-moveit-transfer-zero-day-mass-exploited-in-data-theft-attacks/"
        reference3 = "https://gist.github.com/JohnHammond/44ce8556f798b7f6a7574148b679c643"
        verdict = "dangerous"
      	mitre = "T1505.003"
        platform = "windows"
        search_context = "filesystem"
        
    strings:

        $a1 = "MOVEit.DMZ"
        $a2 = "Request.Headers[\"X-siLock-Comment\"]"
        $a3 = "Delete FROM users WHERE RealName='Health Check Service'"
        $a4 = "set[\"Username\"]"
        $a5 = "INSERT INTO users (Username, LoginName, InstID, Permission, RealName"
        $a6 = "Encryption.OpenFileForDecryption(dataFilePath, siGlobs.FileSystemFactory.Create()"
        $a7 = "Response.StatusCode = 404;"

    condition:
        
        filesize < 10KB
        and all of them 

}

rule MOVEit_Transfer_exploit_webshell_dll {

    meta:

        date = "2023-06-01"
        description = "Detects indicators of compromise in MOVEit Transfer exploitation."
        author = "Djordje Lukic - Binalyze DFIR Lab"
        hash1 = "7d7349e51a9bdcdd8b5daeeefe6772b5"
        hash2 = "2387be2afe2250c20d4e7a8c185be8d9"
        reference1 = "https://www.reddit.com/r/msp/comments/13xjs1y/tracking_emerging_moveit_transfer_critical/"
        reference2 = "https://www.bleepingcomputer.com/news/security/new-moveit-transfer-zero-day-mass-exploited-in-data-theft-attacks/"
        reference3 = "https://gist.github.com/JohnHammond/44ce8556f798b7f6a7574148b679c643"
        verdict = "dangerous"
      	mitre = "T1505.003"
        platform = "windows"
        search_context = "filesystem"
        
    strings:

        $a1 = "human2.aspx" wide
        $a2 = "Delete FROM users WHERE RealName='Health Check Service'" wide
        $a3 = "X-siLock-Comment" wide

    condition:
        
        uint16(0) == 0x5A4D and filesize < 20KB
        and all of them 

}
