package cache;

import java.net.InetAddress;

import packet.DNS_Packet;

public class Cache_Entry {
	private int TTD;
	private InetAddress IP;
	private String name;
	private DNS_Packet packet;
	
	public Cache_Entry(int TTD, InetAddress IP, String name) {
		this.TTD = TTD;
		this.IP = IP;
		this.name = name;
	}
	
	public Cache_Entry(int TTD, InetAddress IP, String name, DNS_Packet p) {
		this.TTD = TTD;
		this.IP = IP;
		this.name = name;
		packet = p;
	}
	
	public int getTTD() {
		return TTD;
	}
	
	public InetAddress getIP() {
		return IP;
	}
	
	public String getName() {
		return name;
	}
	
	public DNS_Packet getPacket() {
		return packet;
	}
}
