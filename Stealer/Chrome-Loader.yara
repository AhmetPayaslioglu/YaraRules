rule Chrome_Loader_Mal {
meta:
	description = "Detects ChromeLoader Malware"
	author = "Ahmet Payaslioglu | Binalyze DFIR LAB"
	reference = "https://redcanary.com/blog/chromeloader/"
	hash1 = "ded20df574b843aaa3c8e977c2040e1498ae17c12924a19868df5b12dee6dfdd"
	date = "2022/05/26"

strings: 
	$a1 = "CS_installer.pdb" wide ascii 
	$b1 = "CS_installer.exe" wide ascii 
	$b2 = "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -E" wide ascii 
	
condition: uint16(0) == 0x5a4d and filesize < 500KB and ( 2 of them ) }


