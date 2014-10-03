package main;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;
import java.util.regex.*;

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
 * @version Sep 29, 2014
 *******************************************************************/
public class DNS_Resolver {
	
	/** Default root DNS to use in case there is an error reading
	 * the file containing the list of root DNS. */
	private final InetAddress DEFAULT_ROOT_DNS = 
			InetAddress.getByName("199.7.91.13");
	
	/** The port to query a DNS is  */
	final int DNS_PORT = 53;
	
	private final String PATH = "src/packet/dns.root";
	
	private final int TIMEOUT = 2000;
	
	/** The port used to host this server */
	private int SERVER_PORT;
	
	private InetAddress SERVER_IP;
	
	private DatagramSocket serverSocket;
	
	private InetAddress ROOT_IP;
	
	private ArrayList<InetAddress> rootIPs;
	
	private InetAddress initialIP;
	
	private int initialPort;
	
	private DNS_Packet initialPacket;

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
		pickRootDNS();
		
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
	 * Randomly picks a DNS to be used as the root from the given
	 * root hints file.
	 ***************************************************************/
	private void pickRootDNS() {
		ArrayList<InetAddress> ipArr = null;
		
		try {
			ipArr = readRootFile(PATH);
		} catch (FileNotFoundException fnf) {
			System.err.println("File not found at: " + PATH);
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		/* Checks for null array. */
		if (ipArr == null) {
			ipArr = new ArrayList<InetAddress>();
		}
		
		/* Checks for empty array. */
		if(ipArr.isEmpty()) {
			ipArr.add(DEFAULT_ROOT_DNS);
		}
		
		Random rand = new Random();
		int index = rand.nextInt(ipArr.size());
		ROOT_IP = ipArr.get(index);
		
		rootIPs = ipArr;
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
				sendData.length, ip, port);
		
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
	
	private DatagramPacket receiveMessage(int attempts, InetAddress addr) 
			throws IOException {

		DatagramPacket recvPacket = null;
		
		for (int i = 0; i < attempts; i++) {

			if (i > 0) {
				String message = "Retring receive from: ";
				System.err.println(message + addr.getHostAddress());
			}
			
			try {
				recvPacket = receiveMessage();
				InetAddress recvAddr = recvPacket.getAddress();
				
				/* Checks if server receives from another sender. */
				if (!recvAddr.getHostAddress().equals(addr.getHostAddress())) {
					System.err.println("Ignoring packet from: " + 
							recvAddr.getHostAddress());
					i--;
					continue;
				}
				
				break;
			} catch (SocketTimeoutException to) {
				continue;
			}
		}
		return recvPacket;
	}
	
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
			
			DNS_Packet dnsPacket = new DNS_Packet(recvPacket.getData());
			
			DNS_Header header = dnsPacket.getHeader();
			int rcode = header.getRCODE();
			
			// Print separator
			String s = new String(new char[65]).replace("\0", "-");
			System.out.println("\n" + s);
			
			// Prints out Sender ID
			System.out.println(">> Received query from: " + 
					header.getID() + " <<");
			
			// Prints out name(s) being queried.
			System.out.println("Question:" + dnsPacket.getNames());
			
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
	
	private void recursiveQuery(DNS_Packet dnsPacket) throws Exception {
		System.out.println("-Forwarding query to Root DNS-");
		
		recursiveQuery(dnsPacket, 0, rootIPs);	
	}
	
	private void recursiveQuery(DNS_Packet dnsPacket, int index,
			ArrayList<InetAddress> ipArr) throws Exception {
		DNS_Header header = dnsPacket.getHeader();
		
		if (header.getANCOUNT() > 0) {
			
			System.out.println("--Answers--");
			for (String addr : dnsPacket.getFinalAnswers()) {
				
				if (addr.isEmpty()) {
					addr = "<NON A TYPE>";
				}
				
				System.out.println("->  " + addr);
			}
			
			sendMessage(dnsPacket, initialIP, initialPort);
			
		} else {
			InetAddress ip = ipArr.get(index);
			
			System.out.println("Sending query to: " + ip.getHostAddress());
			sendMessage(initialPacket, ip, DNS_PORT);
			
			DatagramPacket recvPacket = receiveMessage(2, ip);	
			
			/* Checks if the server was unable to receive from the given IP */
			if (recvPacket == null) {
				recursiveQuery(dnsPacket, index + 1, ipArr);
				return;
			}
			
			byte[] recvData = recvPacket.getData();
			
			dnsPacket = new DNS_Packet(recvData);
			header = dnsPacket.getHeader();	
			
			System.out.println("Got from " + ip.getHostAddress() + ":");
			System.out.println(dnsPacket.getHeader());
			System.out.println();			
			
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
    	
		resolver.begin();
		
    }
	
	
	/****************************************************************
	 * Takes an array of bytes and prints out the binary.
	 * Bytes are separated by '-'.
	 * 
	 * TODO : Remove this method before release.
	 * 
	 * @param data the bytes to be converted to binary.
	 ***************************************************************/
	public static void printBinary(byte[] data){
		for (int i = 0; i < data.length; i++){
			byte n = data[i];
			System.out.print(
					String.format("%8s", 
							Integer.toBinaryString(n & 0xFF)).replace(' ', '0'));
			System.out.print("-");
		}
		
		System.out.println("\nEND");
	}

}
