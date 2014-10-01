package packet;

import java.net.InetAddress;
import java.net.UnknownHostException;
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
	
	private int RDLENGTH;
	
	private InetAddress RDATA;
	
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
//		readNameField(sIndex); // NAME field
		findNameLength();
		
		TYPE = hexBytesToDecimal(
				new byte[] {data[endIndex], data[endIndex + 1]});
		endIndex += 2;
		CLASS = hexBytesToDecimal(
				new byte[] {data[endIndex], data[endIndex + 1]});
		endIndex += 2;
		
		TTL = hexBytesToDecimal(
				new byte[] {data[endIndex], data[endIndex + 1], 
							data[endIndex + 2], data[endIndex + 2]});
		endIndex +=4;
		
		RDLENGTH = hexBytesToDecimal(
				new byte[] {data[endIndex], data[endIndex + 1]});
		endIndex += 2;
		
		RDATA = interpretRDATA();
		endIndex += RDLENGTH;
	}
	
	private InetAddress interpretRDATA() {

		int len = 0;
		
		if (TYPE == A_TYPE) {
			len = 4;
		} else if (TYPE == NS_TYPE){
			len = RDLENGTH;
		} else {
			return null;
		}
		
		byte[] ipArr = new byte[8];

		for (int i = 0; i < ipArr.length; i++) {
			ipArr[i] = data[endIndex + i];
		}

		InetAddress ip;
		try {
			ip = InetAddress.getByAddress(ipArr);
		} catch (UnknownHostException e) {
			ip = InetAddress.getLoopbackAddress();
		}

		return ip;			

	}
	
	private void findNameLength() {
		
		for (int i = sIndex; i < data.length; i++) {
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
		
		return readNameField(index, "");
	}
	
	private String readNameField(int index, String name) {
		
		int labelLen = data[index] & 0xFF;
		
		System.out.println(index + ":" + labelLen);
		
		if (labelLen == 0) {
			return "";
		} else {
			
			
			// Converts current byte into binary to check for pointer
			String bin = String.format("%8s", Integer.toBinaryString(
					labelLen)).replace(' ', '0');
			
			/* Checks for pointer */
			if (bin.startsWith("11")) {

				System.out.println("Pointer");
				
				// Takes the last 6 bits of the first byte and the entire
				// second byte in binary, converts it to decimal. The
				// resulting integer is the number 
				String binaryPtr = bin.substring(2);
				binaryPtr += String.format("%8s", Integer.toBinaryString(
						data[index + 1] & 0xFF)).replace(' ', '0');

				int offset = Integer.parseInt(binaryPtr, 2);
				
				System.out.println("Offset: " + offset);
				
				String gotFromPointer = readNameField(offset, name);
				System.out.println("GFP: " + gotFromPointer);
				
				endIndex += 2;
				
				return gotFromPointer ;
			}
			
			byte[] fragment = new byte[labelLen];

			// Populate fragment array
			for (int k = index + 1; k < labelLen + index + 1; k++) {
				fragment[k - (index + 1)] = data[k];
			}

			String label = new String(fragment, Charset.defaultCharset());

			name += "." + label;

			index += labelLen + 1;
						
			/* Won't update the endIndex if the method jumps back
			 * due to a pointer. */
			if (index > endIndex) {
				endIndex = index;
			}
			
			System.out.println("name: " + name);
			
			return name += readNameField(index, name);
		}

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
	
	public InetAddress getRDATA() {
		return RDATA;
	}

	public int getEndIndex() {
		return endIndex;
	}
}