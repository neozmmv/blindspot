package network

const (
	PacketHello byte = 0x01
	PacketPing  byte = 0x02
	PacketPong  byte = 0x03
	PacketData  byte = 0x04
	PacketDead  byte = 0x05
	PacketACK   byte = 0x06
)
