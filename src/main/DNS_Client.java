package main;

import java.io.*;
import java.net.*;

public class DNS_Client {
	public static void main(String args[]) throws Exception{
		DatagramSocket clientSocket = new DatagramSocket();
		
		clientSocket.setSoTimeout(5000);
		
		BufferedReader inFromUser = new BufferedReader(new InputStreamReader(System.in));
		System.out.println("Enter a message: ");
		String message = inFromUser.readLine();
		byte[] sendData = new byte[1024];
		sendData = message.getBytes();
		
		InetAddress IPAddress = InetAddress.getByName("127.0.0.1");
		
		DatagramPacket sendPacket = new DatagramPacket(sendData,sendData.length,IPAddress,2402);
		clientSocket.send(sendPacket);
		byte[] receiveData = new byte[1024];
		DatagramPacket receivePacket = new DatagramPacket(receiveData,receiveData.length);
		
		try{
		    clientSocket.receive(receivePacket);
		} catch(SocketTimeoutException e){
		    System.out.println("Sorry, didn't get anything");
		    return;
		}
		
		String servermessage = new String(receivePacket.getData());
		System.out.println("Got from server: "+servermessage);
	}
}
