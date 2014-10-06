package main;

import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

public class Catch_GUI {

	private JFrame frame;
	
	private JTextArea textArea;
	
	private DNS_Resolver resolver;
	
	public Catch_GUI() {
		String message = "Port Number?";
		int port = -1;
		do {
			String response = JOptionPane.showInputDialog(message);
			
			try {
				port = Integer.parseInt(response);
			} catch (NumberFormatException e) {}
			message = "Please enter a valid port number";
		} while (port < 1000);
		
		redirectSystemStreams();
		
		frame = new JFrame("Catch: Recursive DNS Caching Resolver");
		frame.setLayout(new BorderLayout());
		
		textArea = new JTextArea(30, 70);
		textArea.setFont(new Font("monospaced", Font.PLAIN, 12));
		textArea.setEditable(false);
		JScrollPane sp = new JScrollPane(textArea);
		
		JButton button = new JButton("Print Cache");
		button.addActionListener(bl);
		
		frame.add(sp);
		frame.add(button, BorderLayout.PAGE_END);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.pack();
		frame.setVisible(true);
		
		resolver = null;
		try {
			resolver = new DNS_Resolver(port);
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
		
		resolver.begin();
	}
	
	private void updateTextArea(final String text) {
		SwingUtilities.invokeLater(new Runnable() {
			public void run() {
				textArea.append(text);
			}
		});
	}

	private void redirectSystemStreams() {
		OutputStream out = new OutputStream() {
			@Override
			public void write(int b) throws IOException {
				updateTextArea(String.valueOf((char) b));
			}

			@Override
			public void write(byte[] b, int off, int len) throws IOException {
				updateTextArea(new String(b, off, len));
			}

			@Override
			public void write(byte[] b) throws IOException {
				write(b, 0, b.length);
			}
		};

		System.setOut(new PrintStream(out, true));
		System.setErr(new PrintStream(out, true));
	}
	
	ActionListener bl = new ActionListener() {
		
		@Override
		public void actionPerformed(ActionEvent e) {
			System.out.println(resolver.printCache());
		}
	};

	public static void main(String[] args) {
		new Catch_GUI();
	}
	
}
