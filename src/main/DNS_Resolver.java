package main;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.*;
import java.util.ArrayList;
import java.util.regex.*;

import cache.Cache;
import packet.DNS_Answer;
import packet.DNS_Header;
import packet.DNS_Packet;


/********************************************************************
 * Catch Server - Recursive Caching DNS Resolver
 * Project 3 - CIS 457-10
 *
 * @author Jack O'Brien
 * @author Megan Maher
 * @author Tyler McCarthy
 * 
 * @version Oct 7, 2014
 *******************************************************************/
public class DNS_Resolver {
	
	/** The port to query a DNS is  */
	final int DNS_PORT = 53;
	
	/** Path to the root hints file. */
	private final String PATH = "src/packet/dns.root";
	
	/** Time out in seconds */
	private final int TIMEOUT = 3500;
	
	/** The port used to host this server */
	private int SERVER_PORT;
	
	/** The address of this resolver. */
	private InetAddress SERVER_IP;
	
	/** Te socket of this server. */
	private DatagramSocket serverSocket;
		
	/** List of all the root IPs */
	private ArrayList<InetAddress> rootIPs;
	
	/** The IP of the person who sent the original query. */
	private InetAddress initialIP;
	
	/** The port of the person who sent the original query. */
	private int initialPort;
	
	/** The packet created from the initial query. */
	private DNS_Packet initialPacket;
		
	/** The name of the initial query. */
	private String initialName;
	
	/** Tells if the recursive query method is in the process of
	 * resolving a CNAME */
	private boolean resolvingCNAME;
	
	/** The list of answers resolved for the CNAME */
	private ArrayList<DNS_Answer> cnameAnswers;
	
	/** This resolver's cache. */
	private Cache cache;
		
	/****************************************************************
	 * Constructor for DNS_Resolver. Sets the port.
	 * 
	 * @param port Port for the server to bind to.
	 * @throws UnknownHostException
	 ***************************************************************/
	public DNS_Resolver(int port) throws Exception {
		SERVER_PORT = port;
		setLocalIP();
		initializeServer();
		rootIPs = readRootFile(PATH);
		
		cache = new Cache();
		
		welcomeMessage();
	}
	
	/****************************************************************
	 * Adds message to UnkownHostException if thrown.
	 * 
	 * @throws UnknownHostException throws when unable
	 * to resolve localhost IPv4 address.
	 ***************************************************************/
	private void setLocalIP() throws UnknownHostException{
		try {
			SERVER_IP = InetAddress.getLocalHost();
		} catch (UnknownHostException he) {
			String message = "Unable to resolve server IP";
			throw new UnknownHostException(message);
		}
	}
	
	/****************************************************************
	 * Initializes the Server's socket, binding it to the
	 * port given to the constructor. 
	 * 
	 * @throws SocketException if there is an issue creating
	 * the serverSocket. Likely the port is already in use.
	 ***************************************************************/
	private void initializeServer() throws SocketException {
		try {
			serverSocket = new DatagramSocket(SERVER_PORT);
		} catch (SocketException be) {
			String message = "Problem hosting server on port " + SERVER_PORT;
			message += "\nIs there another instance of this server?";
			throw new SocketException(message);
		}
		
		serverSocket.setSoTimeout(TIMEOUT);
	}
	
	/****************************************************************
	 * Prints a message indicating the server was created properly.
	 ***************************************************************/
	private void welcomeMessage() {
		String msg = "Started DNS Resolver on ";
		msg += SERVER_IP.getHostAddress() + ":" + SERVER_PORT;
		System.out.println(msg);
	}
	
	/****************************************************************
	 * Reads a file containing a list of root DNSs. Searches for all 
	 * IPv4 addresses and adds them to an array of type InetAddress.
	 * 
	 * @param path
	 * @return
	 * @throws FileNotFoundException
	 * @throws IOException
	 ***************************************************************/
	private ArrayList<InetAddress> readRootFile(String path) 
			throws FileNotFoundException, IOException {
				
		ArrayList<InetAddress> ipArr = new ArrayList<InetAddress>();
		
		BufferedReader br = new BufferedReader(new FileReader(path));
		String line;
		
		/* Loops through root DNS file by line looking for IP addresses
		 * to add to the array of root IPs. */
		while ((line = br.readLine()) != null) {
			String regex = "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b";
			
			Pattern pattern = Pattern.compile(regex);
			Matcher matcher = pattern.matcher(line);
			
			/* Checks if an IP has been found. */
			if (matcher.find()) {
				String ipStr = matcher.group(0);
				InetAddress ip = InetAddress.getByName(ipStr);
				ipArr.add(ip);
			}
		}
		
		br.close();
		
		return ipArr;
	}
	
	/****************************************************************
	 * Sends the bytes from the given DNS_PACKET to the given 
	 * InetAddress. 
	 * 
	 * @param packet contains the bytes to be sent.
	 * @param ip the IPv4 address to send the data to.
	 * @throws IOException if there is an error sending the packet.
	 ***************************************************************/
	private void sendMessage(DNS_Packet packet, InetAddress ip, int port) 
			throws IOException {
		byte[] sendData = packet.getBytes();
		DatagramPacket sendPacket = new DatagramPacket(sendData,
				packet.getLength(), ip, port);
		
		serverSocket.send(sendPacket);
	}

	/****************************************************************
	 * Creates a DatagramPacket for the server to use to
	 * receive data. Once the data is received, the packet
	 * is returned. 
	 * 
	 * @return packet containing received data.
	 * @throws IOException if something goes wrong in receiving.
	 * @throws SocketTimeoutException if a packet is not received 
	 * before the specified timeout.
	 ***************************************************************/
	private DatagramPacket receiveMessage() throws IOException, 
		SocketTimeoutException{
				
		byte[] recvData = new byte[1024];
		
		DatagramPacket recvPacket = 
				new DatagramPacket(recvData,recvData.length);
		
		serverSocket.receive(recvPacket);

		return recvPacket;
	}
	
	/****************************************************************
	 * Receive method that handles retries and only accepts packets
	 * from the given IP address.
	 * 
	 * @param attempts number of attempts to make if failed.
	 * @param addr IPv4 of the expected sender.
	 * @param packet packet to send.
	 * @param port port to send on.
	 * @return the UDP packet that was received
	 * @throws IOException if there was a problem with receiving.
	 ***************************************************************/
	private DatagramPacket receiveMessage(int attempts, InetAddress addr, 
			DNS_Packet packet, int port) throws IOException {

		DatagramPacket recvPacket = null;
		
		for (int i = 0; i < attempts; i++) {

			if (i > 0) {
				String message = "Retrying receive from: ";
				System.err.println(message + addr.getHostAddress());
				sendMessage(packet, addr, port);
			}
			
			try {
				recvPacket = receiveMessage();
				
				InetAddress recvAddr = recvPacket.getAddress();
				
				/* Checks if server receives from another sender. */
				if (!recvAddr.getHostAddress().equals(addr.getHostAddress())) {
					System.err.println("Ignoring packet from: " + 
							recvAddr.getHostAddress());
					i--;
					recvPacket = null;
					continue;
				}
				
				break;
			} catch (SocketTimeoutException to) {
				continue;
			}
		}
		return recvPacket;
	}
	
	/****************************************************************
	 * @return a string representation of the resolver's cache.
	 ***************************************************************/
	public String printCache() {
		return cache.toString();
	}
	
	/****************************************************************
	 * Checks if the packet has an error flag marked.
	 * 
	 * @param rcode the error code.
	 * @param name name of the domain being resolved.
	 * @return true if there is an error.
	 ***************************************************************/
	private boolean checkError(int rcode, String name) {
		if (rcode != DNS_Header.NO_ERROR) {
			
			/* Checks for Name error */
			if (rcode == DNS_Header.NAME_ERROR) {
				System.err.println("Name " + name + " does not exsist");
				return true;
			}
			
			System.err.println("Error in DNS query. RCODE: " + rcode);
			return true;
		}
		
		return false;
	}
	
	/****************************************************************
	 * Sends the given packet containing the final answers to the 
	 * address which the initial query was received from.
	 * 
	 * @param dnsPacket packet containing the answers to send.
	 * @throws IOException if there was an error sending the packet.
	 ***************************************************************/
	private void sendAnswers(DNS_Packet dnsPacket) throws IOException {
		System.out.println("--Answers--");
		for (String addr : dnsPacket.getFinalAnswers()) {
			
			/* Checks for non A type */
			if (addr.isEmpty()) {
				addr = "<NON A TYPE>";
			}
			
			System.out.println("->  " + addr);
		}
		
		/* Add to cache */
		long currentTime = System.currentTimeMillis() / 1000;
		cache.addAnswer(dnsPacket, currentTime);
						
		dnsPacket.setID(initialPacket.getBytes());
		
		sendMessage(dnsPacket, initialIP, initialPort);
	}
	
	/****************************************************************
	 * Resolver starts listening for UDP packets with DNS queries.
	 ***************************************************************/
	public void begin() {
		DatagramPacket recvPacket = null;
				
		/* Once a packet is found it will recursively loop until it
		 * retrieves in answer or an error. Then, the while loops will
		 * start listing for more queries. */
		while (true) {
						
			/* Starts listening for data sent to the server.
			 * Restarts the loops and prints error message if
			 * there is an error receiving the packet. */
			try {
				recvPacket = receiveMessage();
			} catch (SocketTimeoutException to) {
				
				continue;
			} catch (IOException e) {
				String message = "Error receiving packet";
				System.err.println(message);
				continue;
			}
			
			initialIP = recvPacket.getAddress();
			initialPort = recvPacket.getPort();
			
			resolvingCNAME = false;
			
			DNS_Packet dnsPacket = new DNS_Packet(
					recvPacket.getData(), recvPacket.getLength());
			
			DNS_Header header = dnsPacket.getHeader();
			int rcode = header.getRCODE();
			
			// Print separator
			String s = new String(new char[65]).replace("\0", "-");
			System.out.println("\n" + s);
			
			// Prints out Sender ID
			System.out.println(">> Received query from: " + 
					header.getID() + " <<");
			
			// Prints out name(s) being queried.
			initialName = dnsPacket.getNames();
			System.out.println("Question: " + initialName);
			
			// Prints out header information
			System.out.println(header);
			
			// Print separator
			System.out.println(s);
		
			/* Checks for error */
			boolean error = checkError(rcode, dnsPacket.getNames());
			if (error) continue;
			
			// Flips the RD bit
			header.setRecursionDesired(false);
						
			initialPacket = dnsPacket;
			
			try {
				recursiveQuery(dnsPacket);
			} catch (IndexOutOfBoundsException iob) {
				String message = "No response from server";
				System.err.println(message);
			} catch (Exception e) {
				String message = "Error when attempting to contact " + 
						"DNS server";
				System.err.println(message);
				continue;
			}
		}
	}
	
	/****************************************************************
	 * Checks cache for the given packet, then queries the cached IP
	 * or root DNS.
	 * 
	 * @param dnsPacket packet containing query
	 * @throws Exception if no servers could be reached or if there
	 * is any type of sending or receiving error.
	 ***************************************************************/
	private void recursiveQuery(DNS_Packet dnsPacket) throws Exception {
		
		/* Check for answers */
		long currentTime = System.currentTimeMillis() / 1000;
		DNS_Packet answPacket = cache.findAnswer(initialName, currentTime);
		if (answPacket != null) {
			
			System.out.println("-Cached answer for: " + initialName + "-");
			
			sendAnswers(answPacket);
			return;
		}
		
		/* Check cache */
		ArrayList<InetAddress> cachedIps = 
				cache.findName(initialName, currentTime);
		
		if (!cachedIps.isEmpty()) {
			String ip = cachedIps.get(0).getHostAddress();
			System.out.println("-Cache entry for: " + ip + "-");
			recursiveQuery(dnsPacket, 0, cachedIps);	
			return;
		}
				
		System.out.println("-Forwarding query to Root DNS-");
		recursiveQuery(dnsPacket, 0, rootIPs);	
	}
	
	/****************************************************************
	 * Recursively sends query to the IPs given in the array, moving 
	 * to the next index when the former fails.
	 * 
	 * @param dnsPacket packet containing query.
	 * @param index current index in IP array to try.
	 * @param ipArr array list of IPs for the next hop.
	 * @throws Exception if no servers could be reached or if there
	 * is any type of sending or receiving error.
	 ***************************************************************/
	private void recursiveQuery(DNS_Packet dnsPacket, int index,
			ArrayList<InetAddress> ipArr) throws Exception {
		
		DNS_Header header = dnsPacket.getHeader();
		
		/* If there is an answer in the packet. */
		if (header.getANCOUNT() > 0) {
			
			String cname = dnsPacket.getCNAME();
			
			/* Checks if the answer contains a CNAME indicating it
			 * needs to be resolved further. */
			if (!cname.isEmpty()) {
				System.out.println("-Resolving CNAME: " + cname + "-\n");
				
				resolvingCNAME = true;
				initialPacket.setQuestionName(cname);
				recursiveQuery(initialPacket);
				
				for (DNS_Answer answ : cnameAnswers) {
					dnsPacket.addAnswer(answ);
				}
								
				sendAnswers(dnsPacket);
				return;
			}
			
			/* Checks if this is the last stop in resolving a CNAME */
			if (resolvingCNAME) {
				cnameAnswers = dnsPacket.getAnswers();
				return;
			}
			
			sendAnswers(dnsPacket);
			
		/* If there is no answer in the packet. */
		} else {	
			
			/* Checks for an error code. */
			if (checkError(header.getRCODE(), initialName)) {
				sendMessage(dnsPacket, initialIP, initialPort);
				return;
			}
			
			/* Checks for an empty list of IPs. */
			if (ipArr.isEmpty()) {
				String message = "No A type responses given";
				System.err.println(message);
				return;
			}
			
			InetAddress ip = ipArr.get(index);
			
			System.out.println("Sending query to: " + ip.getHostAddress());
			sendMessage(initialPacket, ip, DNS_PORT);
			
			DatagramPacket recvPacket = 
					receiveMessage(2, ip, dnsPacket, DNS_PORT);	
			
			/* Checks if the server was unable to receive from the given IP */
			if (recvPacket == null) {
				recursiveQuery(dnsPacket, index + 1, ipArr);
				return;
			}
			
			byte[] recvData = recvPacket.getData();
			
			dnsPacket = new DNS_Packet(recvData, recvPacket.getLength());
			header = dnsPacket.getHeader();	
			
			System.out.println("Got from " + 
					recvPacket.getAddress().getHostAddress() + ":");
			System.out.println(dnsPacket.getHeader());
			System.out.println();			
			
			/* Add to cache */
			long currentTime = System.currentTimeMillis() / 1000;
			cache.addPacket(dnsPacket, currentTime);
			
			recursiveQuery(dnsPacket, 0, dnsPacket.getResponseIPs());
		}
		
	}
	
	
	/****************************************************************
	 * Main method which initializes and runs the DNS Resolver
	 * 
	 * @param args port to host the server on. 
	 ***************************************************************/
	public static void main(String args[]) {
    	
		int port = 0;
		
		if (args.length < 1) {
			String message = "Port number required";
			throw new IllegalArgumentException(message);
		} else {
			try{
				port = Integer.parseInt(args[0]);
			} catch (NumberFormatException ne) {
				String message = "Port must be an integer";
				throw new IllegalArgumentException(message);
			}
		}
		
		DNS_Resolver resolver = null;
		
		try {
			resolver = new DNS_Resolver(port);
		} catch (Exception e) {
			System.err.println(e.getMessage());
			System.exit(1);
		}
    	
		// Runs the server.
		resolver.begin();	
    }
}
