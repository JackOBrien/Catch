package packet;

/********************************************************************
 * DNS Packet
 * Project 3 - CIS 457-10
 * 
 * Object which divides and contains all the information stored in 
 * the bytes of the DNS packet. 
 *
 * @author Tyler McCarthy
 * @author Jack O'Brien
 * @author Megan Maher
 * 
 * @version Sep 28, 2014
 *******************************************************************/
public class DNS_Packet {

	private DNS_Header header;
	
	/****************************************************************
	 * Constructor for DNS_Packet.
	 * 
	 * @param data bytes which make up the packet.
	 ***************************************************************/
	public DNS_Packet(byte[] data) {
		header = createHeader(data);
	}
	
	/****************************************************************
	 * Creates a DNS_Header object from the packet bytes.
	 * 
	 * @param data bytes representing the entire packet.
	 * @return new DNS_Header modeled from the given bytes.
	 ***************************************************************/
	private DNS_Header createHeader(byte[] data) {
		int headerLength = 12;
		byte[] headerData = new byte[headerLength];
		
		/* Creates a new byte array with only the data needed for the
		 * DNS header. */
		for (int i = 0; i < headerLength; i++) {
			headerData[i] = data[i];
		}
		
		return new DNS_Header(headerData);
	}
	
	/****************************************************************
	 * @return DNS_Header object representing the header of this packet.
	 ***************************************************************/
	public DNS_Header getHeader() {
		return header;
		
	}
}
