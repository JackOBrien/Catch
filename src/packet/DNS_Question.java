package packet;

import java.util.Arrays;

/********************************************************************
 * DNS Question
 * Project 3 - CIS 457-10
 * 
 * 
 *
 * @author Jack O'Brien
 * @author Megan Maher
 * @author Tyler McCarthy
 * 
 * @version Sep 29, 2014
 *******************************************************************/
public class DNS_Question {
	
	/** The length of a DNS question field in bytes. */
	protected static final int LENGTH = 10;
	
	/** Bytes that make up the DNS question. */
	private byte[] data;
	
	/****************************************************************
	 * Constructor for DNS_Question.
	 * 
	 * @param d byte array containing data for the question section
	 * of the DNS packet.
	 ***************************************************************/
	public DNS_Question(byte[] d) {
		data = d;
		interpretData();
	}
	
	/****************************************************************
	 * Interprets the bits in the DNS Header.
	 ***************************************************************/
	private void interpretData() {
		
		// TODO: remove this. Prints Question bytes
		System.out.println("Question: " + Arrays.toString(data));
		
		
	}
}
