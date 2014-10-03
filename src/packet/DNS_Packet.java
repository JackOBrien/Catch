package packet;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;

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
	
	private ArrayList<DNS_Question> questions;
	
	private ArrayList<DNS_Answer> responses;
	
	private byte[] data;
	
	/****************************************************************
	 * Constructor for DNS_Packet.
	 * 
	 * @param data bytes which make up the packet.
	 ***************************************************************/
	public DNS_Packet(byte[] d) {
		data = d;
		header = new DNS_Header(d);
		createQuestions();
		createResponses();
	}
	
	private void createResponses() {
		responses = new ArrayList<DNS_Answer>();
		int numResponses = header.getANCOUNT() + header.getNSCOUNT() + 
				header.getARCOUNT();
		
		if (numResponses > 0) {
			
			int index = header.LENGTH;
			
			if (!questions.isEmpty()) {
				index = questions.get(questions.size()-1).getEndIndex();
			}
			
			
			for (int i = 0; i < numResponses; i++) {
				DNS_Answer answer = new DNS_Answer(data, index);
				index = answer.getEndIndex();
				responses.add(answer);
			}
		}
	}
	
	/****************************************************************
	 * Populate the ArrayList of type DNS_Question with all the 
	 * questions found in this DNS_Packet
	 ***************************************************************/
	private void createQuestions() {
		int numQuestions = header.getQDCOUNT();
		questions = new ArrayList<DNS_Question>();
		
		int endIndex = header.LENGTH;
		for (int i = 0; i < numQuestions; i++) {
			DNS_Question q = new DNS_Question(data, endIndex);
			questions.add(q);
			endIndex = q.getEndIndex();
		}
	}
	
	/****************************************************************
	 * @return DNS_Header object representing the header of this packet.
	 ***************************************************************/
	public DNS_Header getHeader() {
		return header;
	}
	
	/****************************************************************
	 * @return list of the questions in this packet.
	 ***************************************************************/
	public ArrayList<DNS_Question> getQuestion() {
		return questions;
	}
	
	public ArrayList<DNS_Answer> getResponses() {
		return responses;
	}
	
	/****************************************************************
	 * @return a string of all the host names being questioned
	 * in this packet, separated by spaces.
	 ***************************************************************/
	public String getNames() {
		String names = "";
		
		for (DNS_Question q : questions) {
			names += " " +  q.getName();
		}
		
		return names;
	}
	
	public InetAddress getResponseIP() throws UnknownHostException {
		String str = "";
		
		for (DNS_Answer answ : responses) {
			if (answ.getType() == answ.A_TYPE) {
				str = answ.getRDATA();
				break;
			}
		}
		
		return InetAddress.getByName(str);
	}
	
	/****************************************************************
	 * @return bytes which make up this DNS packet.
	 ***************************************************************/
	public byte[] getBytes() {
		return data;
	}
}
