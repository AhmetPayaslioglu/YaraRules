rule Schedule_Runner {
meta:
	description = "Detects Persistence Tools - This tool does customize scheduled tasks for both persistence and lateral movement in a red team operation."
	author = "Ahmet Payaslioglu @Computeus7"
	reference = "https://github.com/netero1010/ScheduleRunner"
	hash = "A8C8574700E33A0EECDF5D584EEC1469"
	hash = "DC83C726A02BF8B6D5443B3F1677CEE40BFDF8BD1A199851F9AA8B5715BBB000"
	date = "2022/04/16"
  	maltype = "Persistence"


strings:
	$a1 = "Executing technique - hiding scheduled task" wide ascii
	$a2 = "Removing scheduled task on disk artifact" wide ascii
	$a3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree" wide ascii 
  	$a4 = "Error when hiding the scheduled task." wide ascii
  	$a5 = "ScheduleRunner.exe" wide ascii
  	$a6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks" wide ascii
  	$a7 = "You do not have sufficient permission to hide the scheduled task" wide ascii

condition: uint16(0) == 0x5a4d and filesize < 500KB and ( 5 of them ) }
