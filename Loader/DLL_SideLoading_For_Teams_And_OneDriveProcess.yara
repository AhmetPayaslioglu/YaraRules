rule DLL_SideLoading_For_Teams_And_OneDriveProcess
{
	meta:
		author = "Ahmet Payaslioglu | Binalyze DFIR LAB"
		date = "2022-08-15"
		referance = "https://blog.cyble.com/2022/07/27/targeted-attacks-being-carried-out-via-dll-sideloading/"
		description = "DLL sideloading technique to load the malicious libraries into the context of Teams and OneDrive processes"
		hash1 = "35f8ab7776fbb3f989ac6c76a9600f8f5cac695d1a1b33a06edd5905fb901627"
		hash2 = "cc95da27bd9703bd4f3c51b3db13635e72fbc38a1015d952c0dc833479f16a0a"
		hash3 = "ee56e43ed64e90d41ea22435baf89e97e9238d8e670fc7ed3a2971b41ce9ffaf"

	strings:
		$a1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Electron/3.1.13 Safari/537.36 " wide ascii
		$a2 = "MSTeams.Synchronization.Primitive.2.0" wide ascii
		$b3 = "iphlpapi.dll" wide ascii
		$b4 = "testtest" wide ascii
		$b5 = "yyyyTTTT%%%%;;" wide ascii

	condition:
		uint16(0)==0x5a4d and ( filesize <700KB) and (( any of ($a*) or 4 of them ))
}
