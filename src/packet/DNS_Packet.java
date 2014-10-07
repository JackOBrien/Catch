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
 * @version Oct 7, 2014
 *******************************************************************/
public class DNS_Packet {

	/** This packet's header */
	private DNS_Header header;
	
	/** List of all of this packet's questions */
	private ArrayList<DNS_Question> questions;
	
	/** List of all this packet's responses. */
	private ArrayList<DNS_Answer> responses;
		
	/** The index of the last index used by the last answer that
	 * was created by this packet's constructor. */
	private int lastNativeAnsw;
	
	/** Byte array containing the byte representation of this packet. */
	private byte[] data;
	
	/** The length of this packet. */
	private int dataLength;
	
	/****************************************************************
	 * Default constructor for DNS_Packet.
	 * 
	 * @param data bytes which make up the packet.
	 ***************************************************************/
	public DNS_Packet(byte[] d) {
		data = d;
		dataLength = 512;
		header = new DNS_Header(d);
		createQuestions();
		createResponses();
	}
	
	/****************************************************************
	 * Constructor for DNS_Packet that takes a byte array and the length
	 * of the bytes used in the array.
	 * 
	 * @param d bytes which make up the packet.
	 * @param length number of bytes used in the given byte array.
	 ***************************************************************/
	public DNS_Packet(byte[] d, int length) {
		data = d;
		dataLength = length;
		header = new DNS_Header(d);
		createQuestions();
		createResponses();		
	}
	
	/****************************************************************
	 * Generates DNS_Answer objects from the byte array.
	 ***************************************************************/
	private void createResponses() {
		responses = new ArrayList<DNS_Answer>();
		int numResponses = header.getANCOUNT() + header.getNSCOUNT() + 
				header.getARCOUNT();
		
		lastNativeAnsw = 0;
		
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
		
		if (header.getANCOUNT() > 0) {
			lastNativeAnsw = 
					responses.get(header.getANCOUNT() - 1).getEndIndex();
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
	 * @return the String representation of the first CNAME type found
	 * in this packet's responses. If none, a blank string is returned.
	 ***************************************************************/
	public String getCNAME() {
		
		for (DNS_Answer a : responses) {
			if (a.getType() == DNS_Answer.CNAME_TYPE) {
				return a.getRDATA();
			}
		}
		
		return "";
	}
	
	/****************************************************************
	 * Sets the name field of the first question of this packet.
	 * 
	 * @param name name to be set for this packet's question.
	 ***************************************************************/
	public void setQuestionName(String name) {
		int size = data.length;
		DNS_Question q = questions.get(0);
		q.setName(name);
		data = q.getData();
		size = data.length - size;
		dataLength += size;
	}
	
	/****************************************************************
	 * Sets this packet's ID from an array of bytes
	 * 
	 * @param bytes byte array where the first two bytes contain the
	 * ID to be set.
	 ***************************************************************/
	public void setID(byte[] bytes) {		
		
		if (bytes.length != 2) {
			bytes = new byte[] {bytes[0], bytes[1]};
		}
		
		data[0] = bytes[0];
		data [1] = bytes[1];
	}
	
	/****************************************************************
	 * @return DNS_Header object representing the header of this packet.
	 ***************************************************************/
	public DNS_Header getHeader() {
		return header;
	}
	
	/****************************************************************
	 * @return list of responses in this packet.
	 ***************************************************************/
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
			names += q.getName();
		}
		
		return names;
	}
	
	/****************************************************************
	 * @return list of IPs found in the responses of this packet.
	 ***************************************************************/
	public ArrayList<InetAddress> getResponseIPs() {
		ArrayList<InetAddress> ipArr = new ArrayList<InetAddress>();
		
		for (DNS_Answer answ : responses) {
			if (answ.getType() == DNS_Answer.A_TYPE) {
				try {
					ipArr.add(InetAddress.getByName(answ.getRDATA()));
				} catch (UnknownHostException e) {
					continue;
				}
			}
		}
		
		return ipArr;
	}
	
	/****************************************************************
	 * @return list of answers found in this packet.
	 ***************************************************************/
	public ArrayList<DNS_Answer> getAnswers() {
		int numAnswer = header.getANCOUNT();
		ArrayList<DNS_Answer> answers = new ArrayList<DNS_Answer>();
		
		for (int i = 0; i < numAnswer; i++) {
			answers.add(responses.get(i));
		}
		
		return answers;
	}
	
	/****************************************************************
	 * Adds the given DNS_Answer to this packet. The answer is added
	 * after the last answer type in the packet.
	 * 
	 * @param answ answer object to be inserted to this packet.
	 ***************************************************************/
	public void addAnswer(DNS_Answer answ) {	
		ArrayList<Byte> byteList = new ArrayList<Byte>();
		
		/* Converts byte array to an ArrayList of type Byte */
		for (byte b : data) {
			byteList.add(new Byte(b));
		}
		
		int start = questions.get(0).getEndIndex();
		
		if (header.getANCOUNT() > 0)
			start = responses.get(header.getANCOUNT() - 1).getEndIndex();
		int length = answ.getLength();
		
		byte[] answArr = new byte[length];
		byte[] totalAnsw = answ.getBytes();
		
		for (int i = 0; i < answArr.length; i++) {
			answArr[i] = totalAnsw[i + answ.getStartIndex()];
		}
		
		for (byte b : answArr) {
			byteList.add(start, new Byte(b));
			start++;
		}
		
		data = new byte[byteList.size()];
		
		for (int i = 0; i < byteList.size(); i++) {
			data[i] = byteList.get(i).byteValue();
		}
		
		answ.setEndIndex(start + length);
		
		responses.add(header.getANCOUNT(), answ);
				
		for (DNS_Answer a : responses) {
			data = a.accountForOffest(length, lastNativeAnsw, data);
		}
				
		/* Change the number of answers. */
		String bin = String.format("%16s", Integer.toBinaryString(
				(header.getANCOUNT() + 1) & 0xFF)).replace(' ', '0');
		
		data[6] = (byte) Integer.parseInt(bin.substring(0, 8), 2);
		data[7] = (byte) Integer.parseInt(bin.substring(8, 16), 2);
		header.setANCOUNT(header.getANCOUNT() + 1);
		
		dataLength += answ.getLength();
	}
	
	/****************************************************************
	 * Returns the answers found in this packet of a given type.
	 * Only supported for A and NS types.
	 * 
	 * @param type type of answers to return
	 * @return all answers of the specified type.
	 ***************************************************************/
	public ArrayList<DNS_Answer> getAnswers(int type) {
		
		if (type != DNS_Answer.A_TYPE && type != DNS_Answer.NS_TYPE)
			return null;
		
		ArrayList<DNS_Answer> answers = new ArrayList<DNS_Answer>();
		
		for (DNS_Answer answ : responses) {
			if (answ.getType() == type) {
				answers.add(answ);
			}
		}
		
		return answers;
	}
	
	/****************************************************************
	 * @return string array of the final answers found in this packet.
	 ***************************************************************/
	public String[] getFinalAnswers() {
		int numAnswers = header.getANCOUNT();
		if (numAnswers == 0) return null;
		
		String[] answers = new String[numAnswers];
				
		for (int i = 0; i < numAnswers; i++) {
			answers[i] = responses.get(i).getRDATA();
		}
		
		return answers;
	}
	
	/****************************************************************
	 * @return bytes which make up this DNS packet.
	 ***************************************************************/
	public byte[] getBytes() {
		return data;
	}
	
	/****************************************************************
	 * @return the number of bytes used in this packets byte array.
	 ***************************************************************/
	public int getLength() {
		return dataLength;
	}
	
	/****************************************************************
	 * Sets the length of this packet to the specified number.
	 * 
	 * @param length length to be set.
	 ***************************************************************/
	public void setLength(int length) {
		dataLength = length;
	}
}
