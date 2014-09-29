package main;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.net.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.*;

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
	final InetAddress DEFAULT_ROOT_DNS = 
			InetAddress.getByName("199.7.91.13");
	
	/** The port to query a DNS is  */
	final static int DNS_PORT = 53;
	
	/** The port used to host this server */
	private int SERVER_PORT;
	
	private InetAddress SERVER_IP;
	
	private DatagramSocket serverSocket;
	

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
	}
	
	/****************************************************************
	 * Prints a message indicating the server was created properly.
	 ***************************************************************/
	private void welcomeMessage() {
		String msg = "Started DNS Resolver on ";
		msg += SERVER_IP.getHostAddress() + ":" + SERVER_PORT;
		System.out.println(msg);
	}
	
	private InetAddress[] readRootFile(String path) {
				
		BufferedReader br = new BufferedReader(new FileReader(path));
		
		String line;
		while ((line = br.readLine()) != null) {
			
		}
		br.close();
		
//		try {
//			byte[] encodedFile = Files.readAllBytes(Paths.get(path));
//			rootFile = new String(encodedFile, Charset.defaultCharset());
//		} catch (IOException e) {
//			String message = "Error reading file at " + path;
//			System.err.println(message);
//			
//		}
		
		String regex = "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b";
		
		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(rootFile);
		
		return new InetAddress[] {DEFAULT_ROOT_DNS};
		//return null;
	}
	
	/****************************************************************
	 * Creates a DatagramPacket for the server to use to
	 * receive data. Once the data is received, the packet
	 * is returned. 
	 * 
	 * @return packet containing received data.
	 * @throws IOException if something goes wrong in receiving.
	 ***************************************************************/
	private DatagramPacket receiveMessage() throws IOException {
		byte[] recvData = new byte[1024];
		
		DatagramPacket recvPacket = 
				new DatagramPacket(recvData,recvData.length);
		
		serverSocket.receive(recvPacket);
		
		return recvPacket;
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
			} catch (IOException e) {
				String message = "Error receiving packet";
				System.err.println(message);
				continue;
			}
			
			// TODO : Interpret data 
			DNS_Packet dnsPacket = new DNS_Packet(recvPacket.getData());
			
			DNS_Header header = dnsPacket.getHeader();
			int rcode = header.getRCODE();
			
			
			/* Checks for error */
			if (rcode != DNS_Header.NO_ERROR) {
				
				/* Checks for Name error */
				if (rcode == DNS_Header.NAME_ERROR) {
					// TODO print error message including referenced name.
				}
				
				System.err.println("Error in DNS query. RCODE: " + rcode);
				continue;
			}
			
			header.setRecursionDesired(false);
			
			// TODO : Remove this
			// Prints flags for testing
			//System.out.println(
			//	Arrays.toString(dnsPacket.getHeader().getFlags()));

			
			// TODO : Message next in line DNS recursively until answer > 0
			recursiveQuery(dnsPacket);
		}
	}
	
	private void recursiveQuery(DNS_Packet packet) {
		DNS_Header header = packet.getHeader();
		
		if (header.getANCOUNT() > 0) {
			// end case
		} else {
			// recursive
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
