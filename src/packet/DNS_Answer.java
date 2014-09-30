package packet;

/********************************************************************
 * DNS Answer
 * Project 3 - CIS 457-10
 * 
 * Object which interprets and stores the information stored in the
 * Answer Resource Record structure of the DNS packet.
 *
 * @author Jack O'Brien
 * @author Megan Maher
 * @author Tyler McCarthy
 * 
 * @version Sep 29, 2014
 *******************************************************************/
public class DNS_Answer {

	/** Bytes that make up the entire resource record section
	 * of the packet. */
	private byte[] data;
	
	private int length;
	
	public DNS_Answer(byte[] d) {
		data = d;
	}
	
//	private void 
	
	/****************************************************************
	 * TODO find the length
	 * @return
	 ***************************************************************/
	public int getLength() {
		return length;
	}
}
