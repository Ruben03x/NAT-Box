package project3;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.Socket;
import java.util.Random;
import java.util.Scanner;

/**
 * This class is used to send and receive packets from the server.
 */
public class Client {

    public static final int ECHO_REPLY = 0;
    public static final int ECHO_REQUEST = 8;
    public static final int DHCP_REPLY = 1;
    public static final int DHCP_REQUEST = 2;
    public static final int ARP_REPLY = 3;
    public static final int ARP_REQUEST = 4;

    private String natIP;
    private Socket socket;
    private ObjectInputStream objectInputStream;
    private ObjectOutputStream objectOutputStream;
    private char internalExternal;
    public String MAC;
    public String clientIP;
    public String ip;
    public String NATMAC = null;

    /**
     * Client constructor: generates a MAC and IP address for the client, assigns NAT IP, assigns socket and input and output streams, as well as if the client is internal or external.
     * @param socket The client 
     * @param internalExternal
     * @param natIP
     */
    public Client(Socket socket, char internalExternal, String natIP) {
        generateMACAddress();
        generateIP();
        ip = clientIP;
        this.socket = socket;
        try {
            objectInputStream = new ObjectInputStream(socket.getInputStream());
            objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
        } catch (IOException e) {
            System.out.println("ERROR!: Unable to create input and output streams");
            closeResources();
            System.exit(0);
        }
        this.internalExternal = internalExternal;
        this.natIP = natIP;
    }

    /**
     * This method will be called by the main thread, and will handle the user
     * input.
     * 
     * @throws IOException if the socket is closed.
     */
    public void start() {
        while (socket.isConnected()) {
            try {
                Scanner CLIInput = new Scanner(System.in);
                String text = CLIInput.nextLine();
                CLICommand(text);
            } catch (Exception e) {
                // System.out.println("ERROR: Reading object");
                closeResources();
                // e.printStackTrace();
                System.exit(0);
            }
        }
    }

    /**
     * Processes a command received from the Command Line Interface.
     * Supports commands including closing the client, sending the packet to a destination, displaying client details, and showing help information. 
     * 
     * @param input The input command from the CLI.
     */
    private void CLICommand(String input) {
        Paquet paquet = null;
        String[] parts = null;
        if (input.startsWith("close")) { //handles closing client

            closeResources();
            System.exit(0);
        } else if (input.startsWith("send")) { //handles sending
            parts = input.split(" ", 4);
            String destinationIP = parts[1];
            int destinationPort = Integer.parseInt(parts[2]);
            String message = parts[3];
            System.out.println("\nSending paquet with following details:" +
                    "\n  IP      : " + MAC +
                    "\n  Port    : " + clientIP +
                    "\n  Message : " + message);
            if (internalExternal == 'i') {
                paquet = new Paquet(MAC, null, ip, destinationIP, socket.getLocalPort(), 0, ARP_REQUEST,
                        message);
            } else {
                paquet = new Paquet(MAC, null, ip, destinationIP, socket.getLocalPort(), destinationPort, ARP_REQUEST,
                        message);
            }
            try {
                objectOutputStream.writeObject(paquet);
                objectOutputStream.flush();
            } catch (Exception e) {
                System.out.println("ERROR!: Sending paquet");
            }
        } else if (input.startsWith("details")) { //prints client details
            System.out.println("\nClient details:");
            System.out.println("  MAC      : " + MAC);
            System.out.println("  IP       : " + clientIP);
            String type;
            if (internalExternal == 'i')
                type = "Internal";
            else
                type = "External";
            System.out.println("  Type     : " + type);
            System.out.println("  LOCAL IP : " + ip);
            System.out.print("  PORT     : " + getLocalPort() + "\n\n>> ");
        } else if (input.startsWith("help")) { //prints help
            System.out.println("\nLegal Commands:");
            System.out.println("close   : Close the client");
            System.out.println("details : Show client details");
            System.out.print("send <destination IP> <destination Port> <message>: sends a message to a client\n\n>> ");
        } else {
            System.out.print("\nIllegal command!\nEnter 'help' to view all legal commands\n\n>> ");
        }

    }

    /**
     * Returns the local port of the socket.
     * 
     * @return the local port of the socket.
     */
    private String getLocalPort() {
        return String.valueOf(socket.getLocalPort());
    }

    /**
     * Sends a DHCP request to the server.
     */
    public void dhcpRequest() {
        try {
            // send request
            String message = "";
            if (internalExternal == 'i')
                message = "internal";
            else
                message = "external";
            Paquet paquet = new Paquet(MAC, null, clientIP, null, socket.getLocalPort(), 0, DHCP_REQUEST,
                    message);
            objectOutputStream.writeObject(paquet);
            objectOutputStream.flush();
        } catch (Exception e) {
            System.out.println("ERROR!: With DHCP Request");
            closeResources();
            System.exit(0);
        }
    }

    /**
     * Returns whether this is an internal state or not.
     * 
     * @return whether this is an internal state or not.
     */
    public boolean isInternal() {
        return internalExternal == 'i';
    }

    /**
     * Listens for a new client to connect to the server.
     * 
     * @param socket             The socket to listen on.
     * @param objectInputStream  The input stream to read from.
     * @param objectOutputStream The output stream to write to.
     * @param server             The server to send messages to.
     */
    public void packetsFromNat() {
        ClientListener listener = new ClientListener(socket, objectInputStream,
                objectOutputStream, this);
        Thread newThread = new Thread(listener);
        newThread.start();
    }

    /**
     * Generates a random MAC address.
     */
    private void generateMACAddress() {
        String[] hexadecimal = { "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F" };
        MAC = "";
        for (int i = 0; i < 6; i++) {
            Random random = new Random();

            MAC = MAC + ":" + hexadecimal[random.nextInt(16)] + hexadecimal[random.nextInt(16)];
        }
        MAC = MAC.substring(1);
    }

    /**
     * Generates an IP address based on if the client is external or internal.
     */
    private void generateIP() {
        Random random = new Random();
        if (internalExternal == 'i') {
            String address = "192.168"; //default internal IP starter
            for (int i = 0; i < 2; i++) {
                address = address + "." + random.nextInt(256);
            }
            clientIP = address;
        } else {
            String address = random.nextInt(256) + "";
            if (address == "192" || address == "10") //alters IP if similar to internal
                address = "191";
            for (int i = 0; i < 3; i++) {
                address = address + "." + random.nextInt(256);
            }
            clientIP = address;
        }

    }

    /**
     * Closes the socket and streams.
     */
    public void closeResources() {
        try {
            if (objectInputStream != null)
                objectInputStream.close();
            if (objectOutputStream != null)
                objectOutputStream.close();
            if (socket != null)
                socket.close();
        } catch (IOException e) {
            System.err.println("ERROR!: While closing resources");
        }
        System.exit(0);
    }

    /**
     * Main method: Gains information on whether the client is internal or external, then sets up a socket using the provided NAT port and IP address
     * Then creates a client, creates a DHCP request, listens for paquets from the NAT box and starts the client.
     * 
     * @param args command line arguments
     * @throws IOException if provided NAT unavailable
     */
    public static void main(String[] args) throws IOException {
        String NATIPAddress;
        int NATPort;
        char internalExternal;
        Socket socket;
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.print("Internal or External client: ");
            String input = scanner.nextLine();
            input = input.toUpperCase();
            if (input.startsWith("E")) {
                internalExternal = 'e';
                break;
            } else if (input.startsWith("I")) {
                internalExternal = 'i';
                break;
            } else {
                System.out.println("ERROR!: Invalid input (Enter internal or external). Try again");
            }
        }

        while (true) {
            System.out.print("Enter NAT-Box IP Address: ");
            NATIPAddress = scanner.nextLine();

            System.out.print("Enter NAT-Box Port: ");
            String NATPortString = scanner.nextLine();
            NATPort = Integer.parseInt(NATPortString);

            try {
                socket = new Socket(NATIPAddress, NATPort);
                break;
            } catch (Exception e) {
                System.out.println("ERROR!: NAT unavailable on given address and port. Try again\n");
            }
        }

        System.out.println("\nNAT-BOX DETAILS:" +
                "\n  IP Address : " + NATIPAddress +
                "\n  Port       : " + NATPort);

        Client client = new Client(socket, internalExternal, NATIPAddress);
        client.dhcpRequest();
        client.packetsFromNat();
        client.start();
        client.closeResources();

    }
}

/**
 * "Listens" to the server to handle incoming paquets. Allows this to be done in parallel by implementing the Runnable interface.
 */
class ClientListener implements Runnable {

    public static final int ECHO_REPLY = 0;
    public static final int ECHO_REQUEST = 8;
    public static final int DHCP_REPLY = 1;
    public static final int DHCP_REQUEST = 2;
    public static final int ARP_REPLY = 3;
    public static final int ARP_REQUEST = 4;
    public static final int ERROR = -1;
    public static final int ERRORNP = -2;

    private Socket socket;
    private ObjectInputStream objectInputStream;
    private ObjectOutputStream objectOutputStream;
    private Client client;

    /**
     * ClientListener object constructor.
     * @param socket The socket for the client listener.
     * @param objectInputStream The object input stream.
     * @param objectOutputStream The object output stream.
     * @param client The client for this current client listener.
     */
    public ClientListener(Socket socket, ObjectInputStream objectInputStream,
            ObjectOutputStream objectOutputStream, Client client) {
        this.socket = socket;
        this.objectInputStream = objectInputStream;
        this.objectOutputStream = objectOutputStream;
        this.client = client;
    }

    /**
     * This method will be called when a new paquet is received; can be run in multiple threads.
     * 
     * @param paquet the paquet received.
     */
    @Override
    public void run() {
        while (socket.isConnected()) {
            Timeout timeout = new Timeout();
            Thread thread = new Thread(timeout);
            thread.start();
            try {
                Paquet paquet = (Paquet) objectInputStream.readObject();
                handlePaquet(paquet);
            } catch (Exception e) {
                closeResources();
                break;
            }
            thread.interrupt();
        }

    }

    /**
     * Handles paquets based on the paquet's type. All methods either print the paquet or an error message.
     * 
     * Handles different types of paquets: ECHO_REPLY, ECHO_REQUEST, DHCP_REPLY, DHCP_REQUEST, ARP_REPLY, ARP_REQUEST and ERROR.
     * ARP_REPLY sends paquet details. ECHO_REQUEST sends an echo reply using a new paquet.
     * 
     * @param paquet The paquet in question.
     */
    private void handlePaquet(Paquet paquet) {
        int type = paquet.type;
        switch (type) {
            case ECHO_REPLY:
                printPaquet(paquet, "Echo reply");
                break;
            case ECHO_REQUEST:
                // System.out.println("[" + p.getSourceIP() + "]: " + p.getText());
                System.out.println();
                printPaquet(paquet, "Paquet Details Received:");

                // send echo reply
                Paquet echoReplyPaquet = new Paquet(paquet.destinationMAC, paquet.sourceMAC,
                        paquet.destinationIP,
                        paquet.sourceIP, paquet.destinationPort, paquet.sourcePort, ECHO_REPLY,
                        paquet.message);
                try {
                    objectOutputStream.writeObject(echoReplyPaquet);
                    objectOutputStream.flush();
                } catch (IOException e1) {

                }

                break;
            case DHCP_REPLY:
                client.NATMAC = paquet.sourceMAC;
                client.ip = paquet.destinationIP;

                System.out.println("  MAC        : " + client.NATMAC + "\n");

                System.out.println("CLIENT DETAILS:" +
                        "\n  MAC      : " + client.MAC +
                        "\n  IP       : " + client.clientIP +
                        "\n  Port     : " + socket.getLocalPort());
                if (client.isInternal())
                    System.out.println("  Local IP : " + client.ip);
                System.out.print("\n>> ");
                break;
            case DHCP_REQUEST:
                // nothing
                break;
            case ARP_REPLY:
                paquet.type = ECHO_REQUEST;
                try {
                    objectOutputStream.writeObject(paquet);
                    objectOutputStream.flush();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                printPaquet(paquet, "Paquet Details Sent");
                System.out.print("\n>>");
                break;

            case ARP_REQUEST:
                break;

            case ERROR:
                System.out.println("ERROR!: Dropped packet. No client at " + paquet.destinationIP);
                System.out.print("\n>>");
                break;

            case ERRORNP:
                System.out.println("ERROR!: " + paquet.message);
                System.out.print("\n>>");
                closeResources();
                break;

            default:
                System.out.println("ERROR!: Not a valid packet type");
                System.out.print("\n>>");
                System.exit(0);
        }
    }

    /**
     * Prints a Paquet object to the console.
     * 
     * @param p      The Paquet object to print.
     * @param detail A string to print before the Paquet object.
     */
    private void printPaquet(Paquet paquet, String detail) {
        System.out.print("\n" + detail +
                "\n  Paquet Type: " + paquet.returnTypeText() +
                "\n  Source MAC : " + paquet.sourceMAC +
                "\n  Source IP  : " + paquet.sourceIP +
                "\n  Source Port: " + paquet.sourcePort +
                "\n  Dest MAC   : " + paquet.destinationMAC +
                "\n  Dest IP    : " + paquet.destinationIP +
                "\n  Dest Port  : " + paquet.destinationPort +
                "\n  Text       : " + paquet.message + "\n\n>>");
    }

    /**
     * Closes all open streams and sockets.
     */
    private void closeResources() {
        try {
            if (objectInputStream != null)
                objectInputStream.close();
            if (objectOutputStream != null) {
                objectOutputStream.close();
            }
            if (socket != null)
                socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.exit(0);
    }
}

/**
 * Threaded timer that times out the server when unused for 15 minutes.
 */
class Timeout implements Runnable {
    static final int TIMEOUT = 15 * (1000 * 60);// 15mins

    public Timeout() {

    }

    /**
     * The timeout thread that will be used to kill the server when expired
     */
    @Override
    public void run() {

        try {
            Thread.sleep(TIMEOUT);
            System.out.println("----------------------------------------------------------------");
            System.err.println("EXPIRED TIMEOUT OF " + TIMEOUT + "ms.");
            System.out.println("----------------------------------------------------------------\n");
            System.exit(0);
        } catch (InterruptedException e) {
        }

    }

}

/**
 * Represents a network paquet on the client side. Very similar to the same class in the NAT.java file.
 * 
 * Encapsulates essential parts of network paquets, such as source and destination MAC addresses, IP addresses and ports and provides constructors and methods to create and modify paquets. 
 */
class Paquet implements Serializable {

    // Ethernet frame important elements
    public String destinationMAC;
    public String sourceMAC;

    // IP packet/segment important elements
    public String sourceIP;
    public String destinationIP;
    public int sourcePort;
    public int destinationPort;

    // note: 1 = dchp request, 2 = dchp reply
    public int type; // https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol

    // payload
    public String message;

    /**
     * Constructor for this class, initializing ports and the MAC and IP addresses.
     * 
     * @param sourceMAC The Mac address of the source.
     * @param destinationMAC Mac address of the destination.
     * @param sourceIP The IP address of the source.
     * @param destinationIP The IP address of the destination.
     * @param sourcePort The port of the source.
     * @param destinationPort The port of the destination.
     * @param type The type of the paquet; used in paquet handling.
     * @param message The actual message contained in the paquet.
     */
    public Paquet(String sourceMAC, String destinationMAC, String sourceIP, String destinationIP, int sourcePort,
            int destinationPort, int type, String message) {
        this.sourceMAC = sourceMAC;
        this.destinationMAC = destinationMAC;
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.type = type;
        this.message = message;
    }

    /**
     * Another paquet constructor, where just the message is initialized.
     * 
     * @param message The actual message contained in the paquet.
     */
    public Paquet(String message) {
        this.message = message;
    }

    /**
     * Returns the name of the type of this packet.
     * 
     * @return The name of the type of this packet.
     */
    public String returnTypeText() {
        switch (type) {
            case 0:
                return "ECHO_REPLY";
            case 1:
                return "DHCP_REPLY";
            case 2:
                return "DHCP_REQUEST";
            case 3:
                return "ARP_REPLY";
            case 4:
                return "ARP_REQUEST";
            case 5:
                return "TCP";
            case 6:
                return "UDP";
            case 7:
                return "ICMP";
            case 8:
                return "ECHO_REQUEST";
            default:
                return "ERROR";
        }
    }

}