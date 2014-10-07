package cache;

import java.net.InetAddress;
import java.util.ArrayList;

import packet.DNS_Answer;
import packet.DNS_Packet;

/********************************************************************
 * Cache_Entry.java
 *
 * @author Jack O'Brien
 * @author Megan Maher
 * @author Tyler McCarthy
 * 
 * @version Oct 7, 2014
 *******************************************************************/
public class Cache_Entry {
	
	/** Time to live in seconds. */
	private int TTL;
	
	/** Time to die in seconds. */
	private long TTD;
	
	/** IP address associated with this entry. */
	private InetAddress IP;
	
	/** Name associated with this entry. */
	private String name;
	
	/** Packet associated with this entry. */
	private DNS_Packet packet;
	
	/****************************************************************
	 * Constructor used for steps in the resolving process.
	 * 
	 * @param TTL time to live.
	 * @param TTD time to die.
	 * @param IP IP address associated with this entry
	 * @param name Name associated with this entry
	 ***************************************************************/
	public Cache_Entry(int TTL, long TTD, InetAddress IP, String name) {
		this.TTL = TTL;
		this.TTD = TTD;
		this.IP = IP;
		this.name = name;
	}
	
	/****************************************************************
	 * Constructor used for answers.
	 * 
	 * @param TTL time to live.
	 * @param TTD time to die.
	 * @param name Name associated with this entry
	 * @param p Packet associated with this entry
	 ***************************************************************/
	public Cache_Entry(int TTL, long TTD, String name, DNS_Packet p) {
		this.TTL = TTL;
		this.TTD = TTD;
		this.name = name;
		packet = p;
	}
	
	/****************************************************************
	 * @return time to live
	 ***************************************************************/
	public int getTTL() {
		return TTL;
	}
	
	/****************************************************************
	 * @return time to die
	 ***************************************************************/
	public long getTTD() {
		return TTD;
	}
	
	/****************************************************************
	 * @return IP address associated with this entry. 
	 ***************************************************************/
	public InetAddress getIP() {
		return IP;
	}
	
	/****************************************************************
	 * @return Name associated with this entry. 
	 ***************************************************************/
	public String getName() {
		return name;
	}
	
	/****************************************************************
	 * @return Packet associated with this entry. 
	 ***************************************************************/
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
				str += String.format("\n%15d  %22s  %23s", 
						ttl, name, ip);
			}
			
			return str;
		}
	}
}
