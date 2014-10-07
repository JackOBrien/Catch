package packet;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;

import com.sun.org.apache.xpath.internal.operations.And;

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
	
	private int offset;
	
	private int lastNativeAnsw;
	
	private byte[] data;
	
	private int dataLength;
	
	/****************************************************************
	 * Constructor for DNS_Packet.
	 * 
	 * @param data bytes which make up the packet.
	 ***************************************************************/
	public DNS_Packet(byte[] d) {
		data = d;
		dataLength = 512;
		header = new DNS_Header(d);
		createQuestions();
		createResponses();
		offset = 0;
	}
	
	public DNS_Packet(byte[] d, int length) {
		data = d;
		dataLength = length;
		header = new DNS_Header(d);
		createQuestions();
		createResponses();		
		offset = 0;
	}
	
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
	
	public String getCNAME() {
		
		for (DNS_Answer a : responses) {
			if (a.getType() == DNS_Answer.CNAME_TYPE) {
				return a.getRDATA();
			}
		}
		
		return "";
	}
	
	public void setQuestionName(String name) {
		int size = data.length;
		DNS_Question q = questions.get(0);
		q.setName(name);
		data = q.getData();
		size = data.length - size;
		dataLength += size;
	}
	
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
	
	public ArrayList<DNS_Answer> getAnswers() {
		int numAnswer = header.getANCOUNT();
		ArrayList<DNS_Answer> answers = new ArrayList<DNS_Answer>();
		
		for (int i = 0; i < numAnswer; i++) {
			answers.add(responses.get(i));
		}
		
		return answers;
	}
	
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
		
		System.out.println("4" + Arrays.toString(data));
		
		for (DNS_Answer a : responses) {
			data = a.accountForOffest(length, lastNativeAnsw, data);
		}
		
		System.out.println("F" + Arrays.toString(data));
		
		/* Change the number of answers. */
		String bin = String.format("%16s", Integer.toBinaryString(
				(header.getANCOUNT() + 1) & 0xFF)).replace(' ', '0');
		
		data[6] = (byte) Integer.parseInt(bin.substring(0, 8), 2);
		data[7] = (byte) Integer.parseInt(bin.substring(8, 16), 2);
		header.setANCOUNT(header.getANCOUNT() + 1);
		
		dataLength += answ.getLength();
	}
	
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
	
	public int getLength() {
		return dataLength;
	}
	
	public void setLength(int length) {
		dataLength = length;
	}
}
