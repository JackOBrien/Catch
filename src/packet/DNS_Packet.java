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
	
	private DNS_Answer answer;
	
	private byte[] data;
	
	/****************************************************************
	 * Constructor for DNS_Packet.
	 * 
	 * @param data bytes which make up the packet.
	 ***************************************************************/
	public DNS_Packet(byte[] d) {
		data = d;
		header = createHeader();
//		question = createQuestion();
//		answer = createAnswer();
	}
	
	/****************************************************************
	 * Creates a DNS_Header object from the packet bytes.
	 * 
	 * @return new DNS_Header modeled from the given bytes.
	 ***************************************************************/
	private DNS_Header createHeader() {
		byte[] headerData = new byte[DNS_Header.LENGTH];
		
		/* Creates a new byte array with only the data needed for the
		 * DNS header. */
		for (int i = 0; i < DNS_Header.LENGTH; i++) {
			headerData[i] = data[i];
		}
		
		return new DNS_Header(headerData);
	}
	
	/****************************************************************
	 * Creates a DNS_Question object from the packet bytes.
	 * 
	 * @return new DNS_Question modeled from the given bytes.
	 ***************************************************************/
	private DNS_Question createQuestion() {
		int start = DNS_Header.LENGTH;
		byte[] questionData = new byte[DNS_Question.LENGTH];
		
		/* Creates a new byte array with only the data needed for the
		 * DNS question. */
		for (int i = start; i < start + DNS_Question.LENGTH; i++) {
			questionData[i - start] = data[i];
		}
		
		return new DNS_Question(questionData);
	}
	
	/****************************************************************
	 * Creates a DNS_Answer object from the packet bytes.
	 * 
	 * @return new DNS_Answer modeled from the given bytes.
	 ***************************************************************/
	private DNS_Answer createAnswer() {
		int startIndex = DNS_Header.LENGTH + DNS_Question.LENGTH;
		int recordsLength = data.length - startIndex;
		byte[] recordsData = new byte[recordsLength];
		
		/* Creates a new byte array with only the data needed for the
		 * DNS question. */
		for (int i = startIndex; i < startIndex + recordsLength; i++) {
			recordsData[i - startIndex] = data[i];
		}
		
		return new DNS_Answer(recordsData);
	}
	
	/****************************************************************
	 * @return DNS_Header object representing the header of this packet.
	 ***************************************************************/
	public DNS_Header getHeader() {
		return header;
	}
	
	/****************************************************************
	 * @return bytes which make up this DNS packet.
	 ***************************************************************/
	public byte[] getBytes() {
		return data;
	}
}
