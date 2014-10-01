package packet;

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
	
	private ArrayList<DNS_Answer> answers;
	
	private ArrayList<DNS_Answer> authorities;
	
	private ArrayList<DNS_Answer> additionals;
	
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
		createAnswers();
		createAuthorities();
		createAdditionals();
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
	 * Populate the ArrayList of type DNS_Answer with all the 
	 * answers found in this DNS_Packet
	 ***************************************************************/
	private void createAnswers() {
		int numAnswers = header.getANCOUNT();
		answers = new ArrayList<DNS_Answer>();
		
		int endIndex = 0;
		
		if (questions.isEmpty()) 
			endIndex = header.LENGTH;
		else
			endIndex = questions.get(questions.size() - 1).getEndIndex();
		
		for (int i = 0; i < numAnswers; i++) {
			DNS_Answer a = new DNS_Answer(data, endIndex);
			answers.add(a);
			endIndex = a.getEndIndex();
		}
	}
	
	/****************************************************************
	 * Populate the ArrayList of type DNS_Answer with all the 
	 * authority serves found in this DNS_Packet
	 ***************************************************************/
	private void createAuthorities() {
		int numAuthorities = header.getNSCOUNT();
		authorities = new ArrayList<DNS_Answer>();
		
		// Gets the end index of the last answer.
		int endIndex = 0;
		if (answers.isEmpty()) {
			if (questions.isEmpty()) {
				endIndex = header.LENGTH;
			} else {
				endIndex = questions.get(questions.size() - 1).getEndIndex();
			}
		} else {
			endIndex = answers.get(answers.size() - 1).getEndIndex();
		}
		
		for (int i = 0; i < numAuthorities; i++) {
			DNS_Answer a = new DNS_Answer(data, endIndex);
			authorities.add(a);
			endIndex = a.getEndIndex();
		}
	}
	
	/****************************************************************
	 * Populate the ArrayList of type DNS_Answer with all the 
	 * additional sections found in this DNS_Packet
	 ***************************************************************/
	private void createAdditionals() {
		int numAdditional = header.getARCOUNT();
		additionals = new ArrayList<DNS_Answer>();
		
		// Gets the end index of the last answer.
		// Goes up the line if the above field is empty. I'm sorry it's ugly.
		int endIndex = 0;
		if (authorities.isEmpty()) {
			if (answers.isEmpty()) {
				if (questions.isEmpty()) {
					endIndex = header.LENGTH;
				} else {
					endIndex = questions.get(questions.size()-1).getEndIndex();
				}
			} else {
				endIndex = answers.get(answers.size()-1).getEndIndex();
			}
		} else {
			endIndex = authorities.get(authorities.size() - 1).getEndIndex();
		}

		for (int i = 0; i < numAdditional; i++) {
			DNS_Answer a = new DNS_Answer(data, endIndex);
			additionals.add(a);
			endIndex = a.getEndIndex();
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
	
	/****************************************************************
	 * @return list of the answers in this packet.
	 ***************************************************************/
	public ArrayList<DNS_Answer> getAnswer() {
		return answers;
	}
	
	/****************************************************************
	 * @return list of authority responses in this packet.
	 ***************************************************************/
	public ArrayList<DNS_Answer> getAuthority() {
		return authorities;
	}
	
	/****************************************************************
	 * @return list of additional responses in this packet.
	 ***************************************************************/
	public ArrayList<DNS_Answer> getAdditional() {
		return additionals;
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
	
	/****************************************************************
	 * @return bytes which make up this DNS packet.
	 ***************************************************************/
	public byte[] getBytes() {
		return data;
	}
}
