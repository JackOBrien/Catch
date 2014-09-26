package main;

import java.io.IOException;
import java.net.*;
import java.util.Arrays;

import com.sun.xml.internal.ws.util.StringUtils;


/********************************************************************
 * Catch Server - Recursive Caching DNS Resolver
 * Project 3 - CIS 457-10
 *
 * @author Jack O'Brien
 * @author Megan Maher
 * @author Tyler McCarthy
 * 
 * @version Sep 26, 2014
 *******************************************************************/
public class DNS_Resolver {
	
	/** The port to query a DNS is  */
	final static int DNS_PORT = 53;
	
	/** The port used to host this server */
	public int SERVER_PORT;
	
	public InetAddress SERVER_IP;
	
	public DatagramSocket serverSocket;
	

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
	public void setLocalIP() throws UnknownHostException{
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
	public void initializeServer() throws SocketException {
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
	public void welcomeMessage() {
		String msg = "Started DNS Resolver on ";
		msg += SERVER_IP.getHostAddress() + ":" + SERVER_PORT;
		System.out.println(msg);
	}
	
	/****************************************************************
	 * Creates a DatagramPacket for the server to use to
	 * receive data. Once the data is received, the packet
	 * is returned. 
	 * 
	 * @return packet containing received data.
	 * @throws IOException if something goes wrong in receiving.
	 ***************************************************************/
	public DatagramPacket receiveMessage() throws IOException {
		byte[] recvData = new byte[1024];
		
		DatagramPacket recvPacket = 
				new DatagramPacket(recvData,recvData.length);
		
		serverSocket.receive(recvPacket);
		
		return recvPacket;
	}
	
	public void begin() {
		DatagramPacket recvPacket = null;
		
		while (true) {
			
			/* Starts listening for data send to the server.
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
			interpretData(recvPacket);
			
			// TODO : Message next in line DNS recursively until answer > 0
			
		}
	}
	
	public void interpretData(DatagramPacket packet) {
		byte[] data = packet.getData();
		
		System.out.println(Arrays.toString(data));
		printBinary(data);
		
		/* First 16 bits are the ID */
		String id = "0x" + Integer.toHexString(data[0]) +
				Integer.toHexString(data[1]);
		
		/* Next 16 bits are the FLAGS */
		handleFlags(data);
		
	}
	
	/****************************************************************
	 * Interprets the second two bytes of the DNS packet header 
	 * containing different flags and codes.
	 * 
	 * @param data the array of bytes containing the DNS header
	 * @return int array containing flag and code values.
	 * The array is organized as follows: 
	 *   QR : 0 if query, 1 if response;
	 *   OPcode : Specifies type of query, 0 for standard;
	 *   AA : 0 if answer is authoritative;
	 *   TC : 1 if message was truncated due to UDP size constraints;
	 *   RD : 1 if recursion is desired;
	 *   RA : 1 if response server supports recursion;
	 *   Z : Reserved 3 Bits;
	 *   Rcode : 0 if query or no error. > 0 indicates error.
	 ***************************************************************/
	public int[] handleFlags(byte[] data) {
		byte b1 = data[2];
		byte b2 = data[3];
		
		// First and second flag byte as binary strings
		String s1 = Integer.toString(b1, 2);
		String s2 = Integer.toString(b2, 2);
		String buff = "00000000";
		
		// Combines the two flag bytes into one binary string. The
		// substring call is used so that each byte has length 8 
		// with leading zeros.
		String binaryFlags = (buff + s1).substring(s1.length()) + 
					   (buff + s2).substring(s2.length());
		
		// Set flags from the binary string
		int QR  = Integer.valueOf(binaryFlags.charAt(0)); 
		int OPCODE = Integer.valueOf(binaryFlags.substring(1, 5), 2);
		int AA = Integer.valueOf(binaryFlags.charAt(5));
		int TC = Integer.valueOf(binaryFlags.charAt(6));
		int RD = Integer.valueOf(binaryFlags.charAt(7));
		int RA = Integer.valueOf(binaryFlags.charAt(8));
		int Z = Integer.valueOf(binaryFlags.substring(9, 12), 2);
		int RCODE = Integer.valueOf(binaryFlags.substring(12, 16), 2);
		
		int[] flags = {QR, OPCODE, AA, TC, RD, RA, Z, RCODE};
		return flags;
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
