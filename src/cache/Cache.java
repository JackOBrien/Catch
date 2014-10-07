package cache;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;

import com.sun.xml.internal.bind.v2.runtime.unmarshaller.XsiNilLoader.Array;

import packet.DNS_Answer;
import packet.DNS_Packet;

public class Cache {
	private ArrayList<Cache_Entry> cache;
	private ArrayList<Cache_Entry> answers;
	
	public Cache() {
		cache = new ArrayList<Cache_Entry>();
		answers = new ArrayList<Cache_Entry>();
	}
	
	public void addPacket(DNS_Packet packet, long time) {
		ArrayList<DNS_Answer> aTypes = packet.getAnswers(DNS_Answer.A_TYPE);
		ArrayList<DNS_Answer> nsTypes = packet.getAnswers(DNS_Answer.NS_TYPE);
		
		if (aTypes.isEmpty() || nsTypes.isEmpty()) return;
		
		for (DNS_Answer a : aTypes) {
			String aName = a.getName();
			String nsName = "";
			
			for (DNS_Answer ns : nsTypes) {
				String nsRDATA = ns.getRDATA();
				
				if (aName.equals(nsRDATA)) {
					nsName = ns.getName();
					break;
				}
			}
			
			if (nsName.isEmpty()) continue;
			
			int TTL = a.getTTL();
			long TTD = (time + TTL);
			InetAddress IP = null;
			
			try {
				IP = InetAddress.getByName(a.getRDATA());
			} catch (UnknownHostException e) {
				continue;
			}
						
			cache.add(new Cache_Entry(TTL, TTD, IP, nsName));
		}
	}
	
	public void addAnswer(DNS_Packet packet, long time) {
		ArrayList<DNS_Answer> responses = packet.getResponses();
		int numAnswers = packet.getHeader().getANCOUNT();
		
		long TTD = Long.MAX_VALUE;
		int TTL = 0;
		
		for (int i = 0; i < numAnswers; i++) {
			DNS_Answer answ = responses.get(i);
			
			TTL = answ.getTTL();
			long currentTTD = (time + TTL);	
			
			if (currentTTD < TTD) {
				TTD = currentTTD;
			}
		} 
		
		String name = responses.get(0).getName();
		
		answers.add(new Cache_Entry(TTL, TTD, name, packet));
	}
	
	public ArrayList<InetAddress> findName(String name, long time) {
		
		ArrayList<InetAddress> ipArr = new ArrayList<InetAddress>();

		checkForExpired(time);
		
		for (Cache_Entry entry : cache) {
			if (entry.getName().equals(name)) {
				
				ipArr.add(entry.getIP());
			}
		}
		
		if (ipArr.isEmpty()) {
			String[] strArr = name.split("\\.");
			
			if (strArr.length < 2) {
				return ipArr;
			}
			
			int length = strArr[0].length() + 1;
			return findName(name.substring(length), time);
		}
				
		return ipArr;
	}
	
	public DNS_Packet findAnswer(String name, long time) {
		
		DNS_Packet packet = null;
		
		checkForExpired(time);
		
		for (Cache_Entry entry : answers) {
			if (entry.getName().equals(name)) {
				
				packet = entry.getPacket();
				break;
			}
		}
				
		return packet;
	}
	
	private void checkForExpired(long time) {
		ArrayList<Cache_Entry> toRemove = new ArrayList<Cache_Entry>();
		
		for (Cache_Entry entry : cache) {
			if (entry.getTTD() <= time) {
				toRemove.add(entry);
			}
		}
		
		cache.removeAll(toRemove);
		
		for (Cache_Entry entry : answers) {
			if (entry.getTTD() <= time) {
				toRemove.add(entry);
			}
		}
		
		answers.removeAll(toRemove);
	}
		
	public String toString() {
		String str = "\n--Cache Entries--";
		str += String.format("\n #  |%10s  %18s  %15s", "TTL", "Name", "IPv4");
		int count = 1;
		
		checkForExpired(System.currentTimeMillis() / 1000);
		
		if (!cache.isEmpty()) {
			str += "\n" + new String(new char[52]).replace("\0", "-");
			for (Cache_Entry entry : cache) {
				str += String.format("\n%03d |", count);
				str += entry.toString();

				count++;
			}
		} 
		
		if (!answers.isEmpty()){
			str += "\n" + new String(new char[52]).replace("\0", "-");
			str += String.format("\n%30s", "Answers");
			str += String.format("\n%15s  %18s  %15s", "TTL", "Name", "RDATA");
			str += "\n" + new String(new char[52]).replace("\0", "-");
			for (Cache_Entry entry : answers) {
				str += entry.toString();
			}

		} else if (cache.isEmpty()) {
			str = "-No entries in the cache-";
		}
		return str;
	}
}
