package cache;

import java.net.InetAddress;
import java.util.ArrayList;

import packet.DNS_Answer;
import packet.DNS_Packet;

public class Cache_Entry {
	private int TTL;
	private long TTD;
	private InetAddress IP;
	private String name;
	private DNS_Packet packet;
	
	public Cache_Entry(int TTL, long TTD, InetAddress IP, String name) {
		this.TTL = TTL;
		this.TTD = TTD;
		this.IP = IP;
		this.name = name;
	}
	
	public Cache_Entry(int TTL, long TTD, String name, DNS_Packet p) {
		this.TTL = TTL;
		this.TTD = TTD;
		this.name = name;
		packet = p;
	}
	
	public int getTTL() {
		return TTL;
	}
	
	public long getTTD() {
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
	
	public String toString() {
		if (packet == null) {
			String ip = IP.getHostAddress();
			return String.format("%10d  %18s  %15s", TTL, name, ip);
		} else {
			String str = "";
			ArrayList<DNS_Answer> answers = packet.getAnswers();
			
			for (DNS_Answer answ : answers) {
				int ttl = answ.getTTL();
				String name = answ.getName();
				String ip = answ.getRDATA();
				str += String.format("\n%15d  %18s  %15s", 
						ttl, name, ip);
			}
			
			return str;
		}
	}
}
