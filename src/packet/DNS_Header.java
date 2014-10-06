package packet;

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
 * @version Sep 29, 2014
 *******************************************************************/
public class DNS_Header {

	/** The length of a DNS header field in bytes. */
	protected final int LENGTH = 12;
	
	/** A 16-bit identifier generated by the querying device. */
	private String ID;
	
	private byte[] idArr;
	
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
	
	/** RCODE value for no error. */
	public static final int NO_ERROR = 0;
	
	/** RCODE value for a name error meaning the name referenced in the 
	 * query does not exist. */
	public static final int NAME_ERROR = 3;
	
	/** Bytes that make up the entire DNS packet. */
	private byte[] data;
	
	/****************************************************************
	 * Constructor for the DNS_Header.
	 * 
	 * @param d byte array containing the DNS packet.
	 ***************************************************************/
	public DNS_Header(byte[] d) {
		data = d;
		interpretData();
	}
	
	/****************************************************************
	 * Interprets the bits in the DNS Header.
	 ***************************************************************/
	private void interpretData() {
		
		/* First 16 bits are the ID */
		ID = Integer.toBinaryString(data[0] & 0xFF) +
				Integer.toBinaryString(data[1] & 0xFF);
		int id = Integer.parseInt(ID, 2);
		ID = Integer.toString(id);
		idArr = new byte[]{data[0], data[1]};
		
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
		String s1 = Integer.toString(b1 & 0xFF, 2);
		String s2 = Integer.toString(b2 & 0xFF, 2);
		String buff = "00000000";
		
		// Combines the two flag bytes into one binary string. The
		// substring call is used so that each byte has length 8 
		// with leading zeros.
		String binaryFlags = (buff + s1).substring(s1.length()) + 
					   (buff + s2).substring(s2.length());
				
		// Set flags from the binary string
		QR  = Character.getNumericValue(binaryFlags.charAt(0));
		OPCODE = Integer.valueOf(binaryFlags.substring(1, 5), 2);
		AA = Character.getNumericValue(binaryFlags.charAt(5));
		TC = Character.getNumericValue(binaryFlags.charAt(6));
		RD = Character.getNumericValue(binaryFlags.charAt(7));
		RA = Character.getNumericValue(binaryFlags.charAt(8));
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
			str += Integer.toHexString(b & 0xFF);
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
	 * @return the response code for this packet header.
	 ***************************************************************/
	public int getRCODE() {
		return RCODE;
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
	
	/****************************************************************
	 * Sets the Recursion Desired flag according to the parameter. 
	 * Set to 1 if true, 0 if false. 
	 * 
	 * @param flag tells if recursion is desired. 
	 ***************************************************************/
	public void setRecursionDesired(boolean desired) {
		
		byte flag1 = data[2];
		String bin = String.format("%8s", Integer.toBinaryString(
				flag1 & 0xFF)).replace(' ', '0');
		
		if (desired) {
			RD = 1;
		} else{
			RD = 0;
		}
		
		bin = bin.substring(0, 7) + RD;
		short f = Short.parseShort(bin, 2);
		flag1 = (byte) f;
		data[2] = flag1;
	}
	
	public void setQR(boolean response) {
		byte flag1 = data[2];
		String bin = String.format("%8s", Integer.toBinaryString(
				flag1 & 0xFF)).replace(' ', '0');
		
		if (response) {
			QR = 1;
		} else{
			QR = 0;
		}
		
		bin = QR + bin.substring(1, 8);
		short f = Short.parseShort(bin, 2);
		flag1 = (byte) f;
		data[2] = flag1;
	}
	
	public void setID(byte[] bytes) {		
		
		if (bytes.length != 2) {
			bytes = new byte[] {bytes[0], bytes[1]};
		}
		
		idArr = bytes;
		data[0] = bytes[0];
		data [1] = bytes[1];
	}
	
	public void setANCOUNT(int count) {
		ANCOUNT = count;
		
		String bin = String.format("%16s", Integer.toBinaryString(
				count)).replace(' ', '0');
		
		data[6] = (byte) Integer.parseInt(bin.substring(0, 8), 2);
		data[7] = (byte) Integer.parseInt(bin.substring(8, 16), 2);
	}
	
	public byte[] getIdArr() {
		return idArr;
	}
	
	public String toString() {
		String message = "Flags:";
		
		if (QR == 1) message += " QR";
		if (AA == 1) message += " AA";
		if (TC == 1) message += " TC";
		if (RD == 1) message += " RD";
		if (RA == 1) message += " RA";
		
		message += "; Queries: " + QDCOUNT + ", Answers: " + ANCOUNT;
		message += ", Authority: " + NSCOUNT + ", Additional: " + ARCOUNT;
		
		message += "\nOpcode: ";
		
		if (OPCODE == 0) message += "Query";
		else message += OPCODE;
		
		message += ", Rcode: ";
		
		if (RCODE == NO_ERROR) message += "No Error";
		else if (RCODE == NAME_ERROR) message += "Name Error";
		else message += RCODE;
		
		
		return message;
	}
}
