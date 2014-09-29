package packet;

/********************************************************************
 * DNS Packet
 * Project 3 - CIS 457-10
 * 
 * Object which divides and contains all the information stored in 
 * the bytes of the DNS packet. 
 *
 * @author Megan Maher
 * @author Tyler McCarthy
 * @author Jack O'Brien
 * 
 * @version Sep 28, 2014
 *******************************************************************/
public class DNS_Packet {

	private DNS_Header header;
	
	private DNS_Question question;
	
	/****************************************************************
	 * Constructor for DNS_Packet.
	 * 
	 * @param data bytes which make up the packet.
	 ***************************************************************/
	public DNS_Packet(byte[] data) {
		header = createHeader(data);
		question = createQuestion(data);
	}
	
	/****************************************************************
	 * Creates a DNS_Header object from the packet bytes.
	 * 
	 * @param data bytes representing the entire packet.
	 * @return new DNS_Header modeled from the given bytes.
	 ***************************************************************/
	private DNS_Header createHeader(byte[] data) {
		int headerLength = 12; // In bytes
		byte[] headerData = new byte[headerLength];
		
		/* Creates a new byte array with only the data needed for the
		 * DNS header. */
		for (int i = 0; i < headerLength; i++) {
			headerData[i] = data[i];
		}
		
		return new DNS_Header(headerData);
	}
	
	/****************************************************************
	 * Creates a DNS_Question object from the packet bytes.
	 * 
	 * @param data bytes representing the entire packet.
	 * @return new DNS_Question modeled from the given bytes.
	 ***************************************************************/
	private DNS_Question createQuestion(byte[] data) {
		int questionLength = 10; // In bytes
		int startIndex = 12;
		byte[] questionData = new byte[questionLength];
		
		/* Creates a new byte array with only the data needed for the
		 * DNS question. */
		for (int i = startIndex; i < startIndex + questionLength; i++) {
			questionData[i - startIndex] = data[i];
		}
		
		return new DNS_Question(questionData);
	}
	
	/****************************************************************
	 * @return DNS_Header object representing the header of this packet.
	 ***************************************************************/
	public DNS_Header getHeader() {
		return header;
	}
}
