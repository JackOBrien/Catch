package packet;

import java.nio.charset.Charset;
import java.util.Arrays;

/********************************************************************
 * DNS Question
 * Project 3 - CIS 457-10
 * 
 * Object to handle the sections of the packet used for Answers, 
 * Authority, and Additional responses.
 * 
 * @author Megan Maher
 * @author Tyler McCarthy
 * @author Jack O'Brien
 * 
 * @version Oct 2, 2014
 *******************************************************************/
public class DNS_Answer {
	
	/** Starting index of this answer. */
	private int sIndex;
	
	/** The last index of this answer + 1. The next answer will start
	 * from this answer's endIndex. */
	private int endIndex;
	
	private String name;
	
	/** The type code for this answer.  */
	private int TYPE;
	
	/** The class code for this answer. */
	private int CLASS;
	
	/** The time to live in seconds for this answer. */
	private int TTL;
	
	/** The length of the RDATA field. */
	private int RDLENGTH;
	
	/** String representation of the data in the RDATA field. 
	 * Only implemented for the A type. All other types will be
	 * set to a blank string. */
	private String RDATA;
	
	/** The value for A type, which is IPv4 */
	public static final int A_TYPE = 1;
	
	/** The value for NS type */
	public static final int NS_TYPE = 2;
	
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

	/****************************************************************
	 * Sets the values of all this answer's codes and calculates the
	 * endIndex.
	 ***************************************************************/
	private void interpretData() {		
		findNameLength();
		
		name = readNameField(sIndex);
				
		TYPE = bytesToDecimal(
				new byte[] {data[endIndex], data[endIndex + 1]});
		endIndex += 2;
		
		CLASS = bytesToDecimal(
				new byte[] {data[endIndex], data[endIndex + 1]});
		endIndex += 2;
		
		TTL = bytesToDecimal(
				new byte[] {data[endIndex], data[endIndex + 1], 
							data[endIndex + 2], data[endIndex + 3]});
		endIndex +=4;
		
		RDLENGTH = bytesToDecimal(
				new byte[] {data[endIndex], data[endIndex + 1]});
		endIndex += 2;
		
		endIndex += RDLENGTH;
	}
	
	/****************************************************************
	 * Implemented only for A type. Will return a blank string for
	 * all other types. Finds and returns the string representation
	 * of the data stored in the RDATA field.
	 * 
	 * @return string representation of RDATA (IPv4 address).
	 ***************************************************************/
	private String interpretRDATA() {
		
		String rdata = "";
		int rdataIndex = endIndex - RDLENGTH;
		
		
		/* Checks for A type */
		if (TYPE == A_TYPE) {		
			
			/* Loops through the RDATA field and converts
			 * the bytes into integers followed by a period.
			 * Stops before the last byte in RDATA so that a period
			 * is not appended to the very end of the string. */
			for (int i = 0; i < RDLENGTH - 1; i++) {
				rdata += Integer.toString(data[rdataIndex + i] & 0xFF);
				rdata += ".";
			}

			/* Appends the last byte of the RDATA field to the String. */
			rdata += Integer.toString(data[rdataIndex + RDLENGTH -1] & 0xFF);
		} 
		
		/* Checks for NS type */
		else if (TYPE == NS_TYPE) {
			rdata = readNameField(rdataIndex);
		}
		
		return rdata;
	}
	
	/****************************************************************
	 * Goes through the name field and find the end. The endIndex is
	 * then set to the end of the name field.
	 ***************************************************************/
	private void findNameLength() {
		
		/* Loops through the entire packet from the start of
		 * this answer. */
		for (int i = sIndex; i < data.length; i++) {
			
			/* Breaks the loop when a 0 byte is found. */
			if (data[i] == 0) {
				endIndex ++;
				break;
			}
			
			// Converts current byte into binary to check for pointer
			String bin = String.format("%8s", Integer.toBinaryString(
					data[i] & 0xFF)).replace(' ', '0');

			/* Checks for pointer */
			if (bin.startsWith("11")) {
				endIndex += 2;
				break;
			}
			
			endIndex ++;
		}
	}

	private String readNameField(int index) {

		String name = readNameField(index, "");
		
		if (name.endsWith("."))
			name = name.substring(0, name.length() -1);
		
		return name;
	}

	private String readNameField(int index, String name) {

		int labelLen = data[index] & 0xFF;

		if (labelLen == 0) {
			return "";
		} else {


			// Converts current byte into binary to check for pointer
			String bin = String.format("%8s", Integer.toBinaryString(
					labelLen)).replace(' ', '0');

			/* Checks for pointer */
			if (bin.startsWith("11")) {

				// Takes the last 6 bits of the first byte and the entire
				// second byte in binary, converts it to decimal. The
				// resulting integer is the number 
				String binaryPtr = bin.substring(2);
				binaryPtr += String.format("%8s", Integer.toBinaryString(
						data[index + 1] & 0xFF)).replace(' ', '0');

				int offset = Integer.parseInt(binaryPtr, 2);

				String gotFromPointer = readNameField(offset, name);

				return gotFromPointer ;
			}

			byte[] fragment = new byte[labelLen];

			// Populate fragment array
			for (int k = index + 1; k < labelLen + index + 1; k++) {
				fragment[k - (index + 1)] = data[k];
			}

			String label = new String(fragment, Charset.defaultCharset());

			name += label + ".";

			index += labelLen + 1;

			return name += readNameField(index, "");
		}

	}
	
	/****************************************************************
	 * Treats bytes given in the array as one hexadecimal number and
	 * returns the decimal representation.
	 * 
	 * @param hex array of bytes to be treated as a single hex number.
	 * @return the decimal representation of the given hex number.
	 ***************************************************************/
	private int bytesToDecimal(byte[] hex) {
		String str = "";
		String buff = "00000000";		
		
		for (byte b : hex) {
			String current = Integer.toBinaryString(b & 0xFF);
			str += (buff + current).substring(current.length());
			
		}
		
		return Integer.parseInt(str, 2);
	}
	
	/****************************************************************
	 * Calls the method which interprets the RDATA field and returns
	 * its string. Blank string for all non A types.
	 * 
	 * @return the String representation of the RDATA field.
	 ***************************************************************/
	public String getRDATA() {
		return interpretRDATA();
	}

	/****************************************************************
	 * @return the last index used by this object + 1
	 ***************************************************************/
	public int getEndIndex() {
		return endIndex;
	}
	
	/****************************************************************
	 * @return the code of this answer's type.
	 ***************************************************************/
	public int getType() {
		return TYPE;
	}
	
	public int getTTL() {
		return TTL;
	}
	
	public String getName() {
		return name;
	}
}