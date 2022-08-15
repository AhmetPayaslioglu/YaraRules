rule DLL_SideLoading_For_Teams_And_OneDriveProcess {
	meta:
		author ="Ahmet Payaslioglu | Binalyze DFIR LAB"
		date = "2022-08-15"
		referance ="https://blog.cyble.com/2022/07/27/targeted-attacks-being-carried-out-via-dll-sideloading/"
		description ="DLL sideloading technique to load the malicious libraries into the context of Teams and OneDrive processes"
		
	strings:
		$a1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Electron/3.1.13 Safari/537.36 " wide ascii 
		$a2 = "MSTeams.Synchronization.Primitive.2.0" wide ascii
		$b3 = "iphlpapi.dll" wide ascii 
		$b4 = "testtest" wide ascii 
		$b5 = "yyyyTTTT%%%%;;" wide ascii 


	condition:
		uint16 ( 0 ) == 0x5a4d and (filesize<600KB) and ((2 of ($a*) or 4 of them)) 
}
