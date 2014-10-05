package cache;

import java.net.InetAddress;

public class Cache_Entry {
	private int TTD;
	private InetAddress IP;
	private String name;
	
	public Cache_Entry(int TTD, InetAddress IP, String name) {
		this.TTD = TTD;
		this.IP = IP;
		this.name = name;
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
}
