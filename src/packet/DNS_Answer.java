package packet;

import java.nio.charset.Charset;

/********************************************************************
 * DNS Question
 * Project 3 - CIS 457-10
 * 
 * 
 * @author Megan Maher
 * @author Tyler McCarthy
 * @author Jack O'Brien
 * 
 * @version Sep 29, 2014
 *******************************************************************/
public class DNS_Answer {
	
	private int sIndex;
	
	private int endIndex;
	
	private int TYPE;
	
	private int CLASS;
	
	private int TTL;
	
	private final int A_TYPE = 1;
	
	private final int NS_TYPE = 2;
	
	/** Bytes that make up the DNS header. */
	private byte[] data;
	
	/****************************************************************
	 * Constructor for the DNS_Header.
	 * 
	 * @param d byte array containing the entire DNS packet.
	 * @param start the index where this section starts.
	 ***************************************************************/
	public DNS_Answer(byte[] d, int start) {
		data = d;
		sIndex = start;
		endIndex = start;
		interpretData();
	}

	private void interpretData() {
		
	}
	
	private void interpretName() {
		
		for (int i = sIndex; i < data.length; i++) {
			int strLen = data[i]; // Length of the following label
						
			// End Case TODO add pointer handling
			if (data[i] == 0) break;
			
			i += strLen;
			endIndex += strLen + 1;
		}
				
		endIndex ++; // Account for the terminator TODO add pointer handling
	}
	
	private void interpretRDATA() {
		
		/* This Resolver only handles type A and type NS */
		if (TYPE != A_TYPE && TYPE != NS_TYPE) return;
		
		for (int i = endIndex; i < data.length; i++) {
			int strLen = data[i]; // Length of the following label
						
			// End Case TODO add pointer handling
			if (data[i] == 0) break;
			
			// Converts current byte into binary to check for pointer
			String bin = String.format("%8s",
					Integer.toBinaryString(data[i] & 0xFF)).replace(' ', '0');
			
			/* Checks for pointer */
			if (bin.startsWith("11")) {
				
			}
			
			
			i += strLen;
			endIndex += strLen + 1;
		}
				
		endIndex ++; // Account for the terminator TODO add pointer handling
	}
}