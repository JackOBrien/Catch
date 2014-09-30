package packet;

import java.nio.charset.Charset;

/********************************************************************
 * DNS Question
 * Project 3 - CIS 457-10
 * 
 *
 * @author Jack O'Brien
 * @author Megan Maher
 * @author Tyler McCarthy
 * 
 * @version Sep 29, 2014
 *******************************************************************/
public class DNS_Question {
		
	/** The first index of this question section. */
	private int sIndex;
	
	/** The index marking the end of this section of the packet. */
	private int endIndex;
	
	private int QTYPE;
	
	private int QCLASS;
	
	/** The name of the host the question is asking about.*/
	private String name;
	
	/** Bytes that make up the entire DNS packet. */
	private byte[] data;
	
	/****************************************************************
	 * Constructor for DNS_Question.
	 * 
	 * @param d byte array containing data for the entire DNS packet.
	 * @param start the index where this question starts.
	 ***************************************************************/
	public DNS_Question(byte[] d, int start) {
		data = d;
		sIndex = start;
		endIndex = start;
		interpretData();
	}
	
	/****************************************************************
	 * Interprets the bits in the DNS Header.
	 ***************************************************************/
	private void interpretData() {
		
		interpretName();
		QTYPE = hexBytesToDecimal(
				new byte[] {data[endIndex], data[endIndex + 1]});
		endIndex += 2; // Account for type field.
		QCLASS = hexBytesToDecimal(
				new byte[] {data[endIndex], data[endIndex + 1]});
		endIndex += 2; // Account for class field.
		
	}
	
	/****************************************************************
	 * @return the index marking the end of this section of the packet. 
	 ***************************************************************/
	public int getEndIndex() {
		return endIndex;
	}
	
	/****************************************************************
	 * @return the name of the host the question is asking about.
	 ***************************************************************/
	public String getName() {
		return name;
	}
	
	/****************************************************************
	 * Interprets the host name being questioned
	 ***************************************************************/
	private void interpretName() {
				
		name = "";
		
		for (int i = sIndex; i < data.length; i++) {
			int strLen = data[i]; // Length of the following label
						
			// End Case
			if (data[i] == 0) break;
			
			byte[] fragment = new byte[strLen];
			
			// Populate fragment array
			for (int k = i + 1; k < strLen + i + 1; k++) {
				fragment[k - (i + 1)] = data[k];
			}
			
			String label = new String(fragment, Charset.defaultCharset());
			
			/* If it's the first one, don't put a '.' */
			if (i == sIndex) {
				name += label;
			} else {
				name += "." + label;
			}
			
			i += strLen;
			endIndex += strLen + 1;
		}
				
		endIndex ++; // Account for the terminator
	}
	
	/****************************************************************
	 * @return they type of this question.
	 ***************************************************************/
	public int getQTYPE() {
		return QTYPE;
	}
	
	/****************************************************************
	 * @return the class of this question.
	 ***************************************************************/
	public int getQCLASS() {
		return QCLASS;
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
}
