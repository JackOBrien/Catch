package packet;

import java.util.Arrays;

/********************************************************************
 * DNS Header
 * Project 3 - CIS 457-10
 * 
 * Object which interprets and contains the information stored in 
 * the DNS Packet header as variables for easy access.
 *
 * @author Tyler McCarthy
 * @author Megan Maher
 * @author Jack O'Brien
 * 
 * @version Sep 28, 2014
 *******************************************************************/
public class DNS_Header {

	/** A 16-bit identifier generated by the querying device. */
	private String ID;
	
	/** Query/Response flag. 0 for query, 1 for response. */
	private int QR;
	
	/** 4-bit operation code. 0 for standard query. */
	private int OPCODE;
	
	/** Authoritative Answer flag. 1 if the response is authoritative. */
	private int AA;
	
	/** Truncation flag. 1 if message was truncated due
	 *  to UDP size constraints. */
	private int TC;
	
	/** Recursion Desired flag. 1 if recursion is desired. */
	private int RD;
	
	/** Recursion Available flag. 1 if responding server
	 *  supports recursion. */
	private int RA;
	
	/** Response Code. Indicates if there was an error. 0 for no error. */
	private int RCODE;
	
	/** Number of entries in the question section of the packet. */
	private int QDCOUNT;
	
	/** Number of answers in the packet. */
	private int ANCOUNT;
	
	/** Number of name servers in the packet. */
	private int NSCOUNT;
	
	/** Number of entries in the addition records section of the packet. */
	private int ARCOUNT;
	
	/** Bytes that make up the DNS header. */
	private byte[] data;
	
	/****************************************************************
	 * Constructor for the DNS_Header.
	 * 
	 * @param d byte array containing the DNS header.
	 ***************************************************************/
	public DNS_Header(byte[] d) {
		data = d;
		interpretData();
	}
	
	/****************************************************************
	 * Interprets the bits in the DNS Header.
	 ***************************************************************/
	private void interpretData() {
		
		// TODO: remove this
		System.out.println("Header: " + Arrays.toString(data)); 
		
		/* First 16 bits are the ID */
		ID = "0x" + Integer.toHexString(data[0]) +
				Integer.toHexString(data[1]);
		
		/* Next 16 bits are the FLAGS */
		handleFlags();
		
		/* Next 16 bits tell the number of QUESTIONS */
		QDCOUNT = hexBytesToDecimal(new byte[]{data[4], data[5]});
		
		/* Next 16 bits tell the number of ANSWERS */
		ANCOUNT = hexBytesToDecimal(new byte[]{data[6], data[7]});
		
		/* Next 16 bits tell the number of NAME SERVERS */
		NSCOUNT = hexBytesToDecimal(new byte[]{data[8], data[9]});
		
		/* Next 16 bits tell the number of ADDITIONAL records */
		ARCOUNT = hexBytesToDecimal(new byte[]{data[10], data[11]});
	}
	
	/****************************************************************
	 * Interprets the second two bytes of the DNS packet header 
	 * containing different flags and codes.
	 ***************************************************************/
	private void handleFlags() {
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
		QR  = Integer.valueOf(binaryFlags.charAt(0)); 
		OPCODE = Integer.valueOf(binaryFlags.substring(1, 5), 2);
		AA = Integer.valueOf(binaryFlags.charAt(5));
		TC = Integer.valueOf(binaryFlags.charAt(6));
		RD = Integer.valueOf(binaryFlags.charAt(7));
		RA = Integer.valueOf(binaryFlags.charAt(8));
		RCODE = Integer.valueOf(binaryFlags.substring(12, 16), 2);

	}
	
	/****************************************************************
	 * Treats bytes given in the array as one hexadecimal number and
	 * returns the decimal representation.
	 * 
	 * @param hex array of bytes to be treated as a single hex number.
	 * @return the decimal representation of the given hex number.
	 ***************************************************************/
	private int hexBytesToDecimal(byte[] hex) {
		String str = "";
				
		for (byte b : hex) {
			str += Integer.toHexString(b);
		}
		
		return Integer.parseInt(str, 16);
	}
	
	/****************************************************************
	 * Returns the ID of the device that queried the DNS. Represented
	 * as string of a hexadecimal.
	 * 
	 * @return ID number of the device that initiated the DNS query.
	 ***************************************************************/
	public String getID() {
		return ID;
	}
	
	/****************************************************************
	 * Returns the value of the flags and codes stored in the second
	 * two bytes of the DNS header. 
	 * 
	 * @return array containing the value of the second two bytes 
	 * of the DNS header in the following order: 
	 *   {QR, OPCODE, AA, TC, RD, RA, RCODE}
	 ***************************************************************/
	public int[] getFlags() {
		return new int[] {QR, OPCODE, AA, TC, RD, RA, RCODE};
	}

	/****************************************************************
	 * Returns the number of entries in the question section 
	 * of the packet. 
	 * 
	 * @return number of entries in the question section of the packet. 
	 ***************************************************************/
	public int getQDCOUNT() {
		return QDCOUNT;
	}
	
	/****************************************************************
	 * Returns the number of answers in the packet. 
	 * 
	 * @return number of answers in the packet. 
	 ***************************************************************/
	public int getANCOUNT() {
		return ANCOUNT;
	}
	
	/****************************************************************
	 * Returns the number of name servers in the packet.  
	 * 
	 * @return number of name servers in the packet. 
	 ***************************************************************/
	public int getNSCOUNT() {
		return NSCOUNT;
	}
	
	/****************************************************************
	 * Returns the number of entries in the addition records 
	 * section of the packet.  
	 * 
	 * @return Number of entries in the addition records section 
	 * of the packet. 
	 ***************************************************************/
	public int getARCOUNT() {
		return ARCOUNT;
	}
}
