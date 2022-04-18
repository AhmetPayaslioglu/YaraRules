rule Stealer_Mal {
meta:
	description = "Detects Stealer Malware"
	author = "Ahmet Payaslioglu @Computeus7"
	reference = "https://app.any.run/tasks/fce258f3-6f06-4702-84e4-f52b649f599c/"
	hash1 = "b4084d254f10d1236d23c9df15257d0a7ce4922f641d179046216bad63b37cdc"
	hash2 = "5054926f1e5550d0fa2ac5890efd3fef8975d45d90a92c55e0754bdac7231489"
	date = "2022/04/08"
    	maltype = "Stealer"


strings:
	//Make computer beep when done
	$a1 = {4D 61 6B 65 20 63 6F 6D 70 75 74 65 72 20 62 65 65 70 20 77 68 65 6E 20 64 6F 6E 65}

	//Create new directory 
	$a2 = {0A 4D 6B 44 69 72 20 2E 5C 25 63 6F 6D 70 75 74 65 72 6E 61 6D 65 25 5C 2E 65 78 65}
	
	//Discovering new files
	$a3 = {46 4F 52 20 2F 52 20 22 25 55 53 45 52 50 52 4F 46 49 4C 45 25 5C 4D 79 20 44 6F 63 75 6D 65 6E 74 73 22 20 25 25 69}

condition: uint16(0) == 0x5a4d and filesize < 500KB and ( 2 of them ) }
