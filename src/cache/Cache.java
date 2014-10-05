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
			
			int TTD = (int) (time + a.getTTL());
			InetAddress IP = null;
			
			try {
				IP = InetAddress.getByName(a.getRDATA());
			} catch (UnknownHostException e) {
				continue;
			}
						
			cache.add(new Cache_Entry(TTD, IP, nsName));
		}
	}
	
	public void addAnswer(DNS_Packet packet, long time) {
		ArrayList<DNS_Answer> responses = packet.getResponses();
		int numAnswers = packet.getHeader().getANCOUNT();
		
		for (int i = 0; i < numAnswers; i++) {
			DNS_Answer answ = responses.get(i);
			
			int TTD = (int) (time + answ.getTTL());

			InetAddress IP = null;

			try {
				IP = InetAddress.getByName(answ.getRDATA());
			} catch (UnknownHostException e) {
				continue;
			}
			
			String name = answ.getName();
			
			answers.add(new Cache_Entry(TTD, IP, name));
		}
		
	}
	
	public ArrayList<InetAddress> findName(String name) {
		
		ArrayList<InetAddress> ipArr = new ArrayList<InetAddress>();
		
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
			return findName(name.substring(length));
		}
		
		return ipArr;
	}
		
	public String toString() {
		for (Cache_Entry entry : cache) {
			
		}
		
		return "";
	}
}
