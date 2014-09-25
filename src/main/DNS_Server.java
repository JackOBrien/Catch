package main;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;


/**********************************************************
 * DNS_Server.java
 *
 * @author Jack
 * @version Sep 25, 2014
 *********************************************************/
public class DNS_Server {
	public static void main(String args[]) throws Exception{
    	
		DatagramSocket serverSocket = new DatagramSocket(9876);
    	
    	while(true){
		    byte[] recvData = new byte[1024];
		    byte[] sendData = new byte[1024];
		
		    DatagramPacket recvPacket = 
			new DatagramPacket(recvData,recvData.length);
		    
		    serverSocket.receive(recvPacket);
		    String message = new String(recvPacket.getData());
		    InetAddress IPAddress = recvPacket.getAddress();
		    int port = recvPacket.getPort();
		    
		    String newMessage  = "From Server" + message+"\n";
		    sendData = newMessage.getBytes();
		    
		    DatagramPacket sendPacket = new DatagramPacket(sendData,sendData.length,IPAddress,port);
		    serverSocket.send(sendPacket);
    	}
    }
}
