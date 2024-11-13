1. For New Packets, Replace The "exported-packets.txt" and delete "input.txt" (if present) in "data" folder. 
	For Processed Packets, you can replace the "input.txt" file.
2. For Capturing Packets in Wire Shark,
	i. Filter with " ip.version == 4 && udp && !(udp.port == 53 || udp.port == 137 || udp.port == 138 || udp.port == 1900 || udp.port == 5353 || udp.port == 5355 || udp.port == 443) "
	ii. Then Edit -> Mark All Displayed
	iii. Then File -> Export Packet Dissections -> As Plain Text
	iv. Then choose “Marked packets” and “Packet Bytes” only.
	v. Save as "exported-packets.txt"
3. If you Define DEBUG in compile time then All informations of a packet will be shown.


