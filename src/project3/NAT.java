package project3;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.ThreadLocalRandom;
import java.util.stream.Collectors;

/**
 * Represents a NAT box that facilitates communication between internal and external networks.
 */
public class NAT implements Runnable {
    private static final int DEFAULT_POOL_SIZE = 100;
    private static final String DEFAULT_NAT_IP_BASE = "192.168.0.";

    private ServerSocket serverSocket;
    private String ip;
    private String mac;
    private int openPort = 0;
    private ArrayList<Table> table = new ArrayList<Table>();
    private ArrayList<String> pool = new ArrayList<String>();
    private ArrayList<ClientConnection> connections = new ArrayList<>();
    private long refreshInterval; // NAT table refresh interval in milliseconds.

    /**
     * Inner class Table within NAT; represents a mapping entry in the NAT table.
     */
    public static class Table {
        private String clientIP;
        private int clientPort;
        private String natIP;
        private int natPort;
        private ClientConnection clientConnection; // Add reference to the ClientConnection

        // Existing fields remain unchanged.
        private long lastAccessTime; // Timestamp of last access.

        /**
         * Constructs a NAT table entry with the specified parameters and updates the last access time into the NAT table.
         * 
         * @param clientIP The client's IP address, represented as a String.
         * @param clientPort The client's port, represented as an integer.
         * @param natIP The NAT IP address, represented as a String.
         * @param natPort The NAT port, represented as an integer.
         * @param clientConnection The associated ClientConnection object.
         */
        public Table(String clientIP, int clientPort, String natIP, int natPort, ClientConnection clientConnection) {
            this.clientIP = clientIP;
            this.clientPort = clientPort;
            this.natIP = natIP;
            this.natPort = natPort;
            this.clientConnection = clientConnection;
            updateAccessTime(); // Initialize last access time
        }

        /**
         * Getter that returns the client IP.
         * @return The client's IP address as a String.
         */
        public String getClientIP() {
            return clientIP;
        }

        /**
         * Getter that returns the client's port.
         * @return The client's port as an integer.
         */
        public int getClientPort() {
            return clientPort;
        }

        /**
         * Gets the NAT IP address.
         * @return The NAT IP address as a String.
         */
        public String getNatIP() {
            return natIP;
        }

        /**
         * Gets the NAT port.
         * @return The NAT port as an integer.
         */
        public int getNatPort() {
            return natPort;
        }

        /**
         * Updates the last access time into the table entry using system time.
         */
        public void updateAccessTime() {
            this.lastAccessTime = System.currentTimeMillis();
        }

        /**
         * Checks if the entry is expired.
         * @param currentTime Current system time.
         * @param expiryTime The NAT table refresh interval.
         * @return True if expired, false otherwise.
         */
        public boolean isExpired(long currentTime, long expiryTime) {
            return (currentTime - this.lastAccessTime) > expiryTime;
        }

        /**
         * Closes associated client connection.
         */
        public void closeConnection() {
            if (clientConnection != null) {
                clientConnection.closeResources(); // Close the client connection
            }
        }
    }

    /**
     * Constructs a NAT instance with the associated parameters. 
     * 
     * Generates a random MAC address for the NAT table, and starts the NAT table refresher thread.
     * 
     * @param serverSocket The server socket for accepting connections.
     * @param ip The nat IP.
     * @param refreshIntervalInMinutes The NAT refresh interval in minutes.
     */
    public NAT(ServerSocket serverSocket, String ip, long refreshIntervalInMinutes) {
        this.serverSocket = serverSocket;
        this.ip = ip;
        this.mac = randomMAC();

        for (int i = 1; i <= DEFAULT_POOL_SIZE; i++) {
            pool.add(DEFAULT_NAT_IP_BASE + i);
        }

        this.refreshInterval = refreshIntervalInMinutes * 60000; // Convert minutes to milliseconds.
        startTableRefresher(); // Start the NAT table refresher thread.
    }

    /**
     * Starts the NAT table refresher thread.
     */
    private void startTableRefresher() {
        Thread refresherThread = new Thread(() -> {
            while (!serverSocket.isClosed()) {
                try {
                    Thread.sleep(refreshInterval);
                    System.out.println("NAT Table Refreshing.");
                    refreshNATTable();
                } catch (InterruptedException e) {
                    // Handle the interruption properly.
                    System.out.println("NAT Table Refresher interrupted.");
                }
            }
        });
        refresherThread.start();
    }

    /**
     * Refreshes the NAT table by adding The expired entries to an array list, closing the connection for each expired entry and removing each from the NAT table.
     */
    private synchronized void refreshNATTable() {
        long currentTime = System.currentTimeMillis();
        // Collect entries that need to be removed due to expiry
        List<Table> expiredEntries = new ArrayList<>();
        for (Table entry : table) {
            if (entry.isExpired(currentTime, refreshInterval)) {
                expiredEntries.add(entry);
            }
        }

        // Process each expired entry: print timeout info, close connection, and remove
        // from the NAT table
        for (Table expiredEntry : expiredEntries) {
            // Close the connection and remove the entry from the NAT table
            expiredEntry.closeConnection(); // Close the connection if not already
            table.remove(expiredEntry); // Remove the entry from the NAT table
        }
    }

    /**
     * Updates the last access time into the NAT table using either the client's IP or NAT port.
     * @param ip The client IP address.
     * @param port THe NAT port.
     */
    public synchronized void updateLastAccessTime(String ip, int port) {
        // Look for the table entry using either the client IP or NAT port
        for (Table entry : table) {
            if (entry.getClientIP().equals(ip) || entry.getNatPort() == port) {
                entry.updateAccessTime();
                //System.out.println("Updated last access time for entry: " + ip + ":" + port);
                break;
            }
        }
    }

    /**
     * Starts the NAT box and listens for client communication.
     */
    public void start() {
        System.out.println("NAT IP: " + ip);
        System.out.println("NAT MAC: " + mac);
        System.out.println();
        try {
            while (!serverSocket.isClosed()) {
                Socket socket = serverSocket.accept();

                ClientConnection connection = new ClientConnection(socket, this);
                connections.add(connection);

                Thread thread = new Thread(connection);
                thread.start();
            }
        } catch (IOException e) {
            closeServerSocket();
        }
    }

    /**
     * Sends a paquet over TCP by iterating over connections and sending to the client when the connection's client address and the paquet's destination IP match up.
     * @param p The paquet to send.
     */
    public void tcpSend(Paquet p) {
        for (ClientConnection connection_ : connections) {
            if (connection_.clientAddress.equals(p.destinationIP)) {
                connection_.tcpSendToThisClient(p);
            }
        }
    }

    /**
     * Pops an IP address from the array list pool of IP addresses.
     * @return The popped IP address.
     */
    public String popIPfromPool() {
        if (!pool.isEmpty()) {
            String ip = pool.get(0);
            pool.remove(0);
            return ip;
        } else {
            System.err.println("ERROR: No more IPs in pool.\n");
            return null;
        }
    }

    /**
     * Adds an IP address to the array list pool of IP addresses; if it is not already there. Then, removes the NAT table from the list if the client IP matches the IP address added to the pool.
     * @param ip The IP address to add.
     */
    public void addIPtoPool(String ip) {
        if (!pool.contains(ip)) {
            pool.add(ip);
        }
        for (Table row : table) {
            if (row.getClientIP().equals(ip)) {
                table.remove(row);
                break;
            }
        }
    }

    /**
     * Adds a row to the NAT table. 
     * 
     * Creates a new entry in the NAT table using the parameters provided. Also updates the access time for the new entry upon creation.
     * 
     * @param clientAddress
     * @param clientPort
     * @param natAddress
     * @param natPort
     * @param clientConnection
     */
    public void addRow(String clientAddress, int clientPort, String natAddress, int natPort,
            ClientConnection clientConnection) {
        Table row = new Table(clientAddress, clientPort, natAddress, natPort, clientConnection);
        row.updateAccessTime(); // Update access time upon creation.
        table.add(row);
    }

    /**
     * Gets the NAT IP.
     * @return The IP address.
     */
    public String getIP() {
        return ip;
    }

    /**
     * Gets the NAT MAC address.
     * @return The MAC address in question.
     */
    public String getMAC() {
        return mac;
    }

    /**
     * Gets the open port after incrementing it.
     * @return The open port value post incrementation.
     */
    public int getopenPort() {
        return ++openPort;
    }

    /**
     * Gets the client IP from the NAT port and returns it. Also updates the access time.
     * 
     * @param port The NAT port.
     * @return NULL if the NAT port is not found. Otherwise returns the client IP.
     */
    public String getClientIPFromNATPort(int port) {
        for (Table row : table) {
            if (row.getNatPort() == port) {
                row.updateAccessTime(); // Update access time upon access.
                return row.getClientIP();
            }
        }
        return null;
    }

    /**
     * Gets the Client MAC address from its IP address.
     * 
     * @param ip The client IP address.
     * @return The client MAC address if found, else return NULL.
     */
    public String getClientMACFromIP(String ip) {
        for (ClientConnection connection_ : connections) {
            if (connection_.clientAddress.equals(ip)) {
                return connection_.clientMAC;
            }
        }
        return null;
    }

    /**
     * Gets the client port from its IP address.
     * 
     * @param ip Client IP
     * @return The client's port if found, 0 if not.
     */
    public int getClientPortFromIP(String ip) {
        for (ClientConnection connection_ : connections) {
            if (connection_.clientAddress.equals(ip)) {
                return connection_.clientPort;
            }
        }
        return 0;
    }

    /**
     * Removes a client connection from the list of clients maintained by the NAT instance.
     * 
     * If found, the connection is removed from the list of maintained connections and the details of the connected client are printed to the console.
     * 
     * @param connection The client connection to be removed.
     */
    public void removeClient(ClientConnection connection) {
        if (connections.contains(connection)) {
            connections.remove(connection);
            // Print a neatly formatted disconnection log
            System.out.println(String.join("", Collections.nCopies(60, "-")));
            System.out.println("Client Disconnected:");
            System.out.println(String.join("", Collections.nCopies(60, "-")));
            System.out.printf("| %-20s | %-36s %n", "Attribute", "Value");
            System.out.println(String.join("", Collections.nCopies(60, "-")));
            System.out.printf("| %-20s | %-36s %n", "MAC", connection.clientMAC);
            System.out.printf("| %-20s | %-36s %n", "IP", connection.clientAddress);
            System.out.printf("| %-20s | %-36s %n", "Port", connection.clientPort);
            System.out.println(String.join("", Collections.nCopies(60, "-")));
            System.out.println();
        } else {
        }
    }

    /**
     * Checks if the maintained list of client connections contains the connection we are looking for.
     * 
     * @param connection The connection we are looking for.
     * @return True if found, else return false.
     */
    public boolean connectionsContains(ClientConnection connection) {
        if (connections.contains(connection))
            return true;
        else
            return false;
    }

    /**
     * Enumeration representing the network location; can be either internal, external or unknown.
     */
    private enum NetworkLocation {
        INTERNAL, EXTERNAL, UNKNOWN
    }

    /**
     * Determine the IP location using the NetworkLocation enumeration.
     * @param ip The IP address of the connection.
     * @return The network location: internal, external or unknown.
     */
    private NetworkLocation determineIPLocation(String ip) {
        for (ClientConnection connection : connections) {
            if (connection.clientAddress.equals(ip)) {
                return connection.isInternal() ? NetworkLocation.INTERNAL : NetworkLocation.EXTERNAL;
            }
        }
        return NetworkLocation.UNKNOWN; // Return UNKNOWN if no matching IP found
    }

    /**
     * Check if the IP address is internal.
     * @param ip The IP address to check.
     * @return True if the address is internal, false if not.
     */
    public boolean isIPInternal(String ip) {
        return determineIPLocation(ip) == NetworkLocation.INTERNAL;
    }

    /**
     * Check if the IP address is external.
     * @param ip The IP address to check.
     * @return True if the address is external, false if not.
     */
    public boolean isIPExternal(String ip) {
        return determineIPLocation(ip) == NetworkLocation.EXTERNAL;
    }

    /**
     * Creates a random MAC address as a String, and ensures the second hex digit is even (unicast).
     * @return The MAC address as a String.
     */
    private String randomMAC() {
        // Create a random MAC address ensuring the second hex digit is even (unicast)
        ThreadLocalRandom random = ThreadLocalRandom.current();

        // second character is one of 2, 6, A, E to keep it unicast and globally unique
        String macAddress = String.format("%02X:02:%02X:%02X:%02X:%02X",
                random.nextInt(0, 256) & 0xFE, // zeroing the multicast bit and ensuring global uniqueness
                random.nextInt(0, 256),
                random.nextInt(0, 256),
                random.nextInt(0, 256),
                random.nextInt(0, 256),
                random.nextInt(0, 256));

        return macAddress;
    }

    /**
     * Checks if the NAT port is in the NAT table.
     * @param destinationPort The port to check.
     * @return True if port present, false otherwise.
     */
    public boolean checkNatPort(int destinationPort) {
        for (Table row : table) {
            if (row.getNatPort() == destinationPort) {
                return true;
            }
        }
        return false;
    }

    /**
     * Prints the NAT table. Conveys that the table is empty if so, otherwise prints the header and all current mappings.
     */
    public void printTable() {
        // Check if the NAT table is populated
        if (table == null || table.isEmpty()) {
            System.out.println("The NAT mapping table is currently empty.");
            return;
        }

        // Print the header
        System.out.println("\nNAT Mappings Overview:");
        System.out.println(String.join("", Collections.nCopies(74, "-"))); // Dynamic generation of separator line
        System.out.printf("| %-15s | %-11s | %-17s | %-12s %n", "Client IP", "Client Port", "NAT IP", "NAT Port");
        System.out.println(String.join("", Collections.nCopies(74, "-")));

        // Print each mapping in the table
        for (Table mapping : table) {
            System.out.printf("| %-15s | %-11d | %-17s | %-12d %n",
                    mapping.getClientIP(),
                    mapping.getClientPort(),
                    mapping.getNatIP(),
                    mapping.getNatPort());
        }

        // End of table
        System.out.println(String.join("", Collections.nCopies(74, "-")) + "\n");
    }

    /**
     * Closes the server socket.
     */
    public void closeServerSocket() {
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Overwites the run() method in the Runnable class, to enable a parallel NAT thread to run.
     * 
     * Continuously listens for user input: displays nat table if /display is called and shuts it down if /shutdown is called.
     */
    public void run() {
        // Command listener logic here
        Scanner scanner = new Scanner(System.in);
        System.out.println("NAT Command Console Ready (Type '/shutdown' to close or '/display' to view table): ");
        while (true) {
            String command = scanner.nextLine();
            if (command.equals("/display")) {
                printTable();
            } else if (command.equals("/shutdown")) {
                closeServerSocket();
                scanner.close();
                System.exit(0);
            } else {
                System.out.println("Unknown command");
                System.out.println("Available commands: /display, /shutdown");
            }
        }
    }

    /**
     * Main method: gets the IP address, port number and NAT table refresh interval, then creates the NAT box, and creates and starts the thread to accept client connections and starts the command listener threads.
     */
    public static void main(String[] args) throws IOException {
        System.out.print("Public IP address: ");
        Scanner scan = new Scanner(System.in);
        String pIP = scan.nextLine();

        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter port number: ");
        int port = scanner.nextInt();

        ServerSocket serverSocket = new ServerSocket(port);

        System.out.print("Enter NAT table refresh interval (minutes): ");
        long refreshInterval = scanner.nextLong();
        System.out.println();

        NAT box = new NAT(serverSocket, pIP, refreshInterval);

        // Create and start the NAT instance and command listener on separate threads
        Thread serverThread = new Thread(() -> {
            box.start(); // Method to accept client connections
        });
        serverThread.start();

        Thread listenerThread = new Thread(box); // Using NAT instance itself for listening to commands
        listenerThread.start();
    }
}

/**
 * Represents a client connection in the NAT system.
 * 
 * Handles communication with a client connected to the NAT server. Has methods for sending and receiving paquets, handling different paquet types, making NAT table entries and closing resources associated with the client connection.
 */
class ClientConnection implements Runnable {

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
    private NAT nat;
    public String clientAddress = null;
    public String clientMAC;
    public int clientPort;
    private int natPort = 0;
    private int internalExternal;

    /**
     * Client connection constructor; sets up input and output streams, the NAT instance, client port and socket.
     * @param socket The client socket 
     * @param nat The NAT box.
     */
    public ClientConnection(Socket socket, NAT nat) {
        try {
            this.socket = socket;
            objectOutputStream = new ObjectOutputStream(socket.getOutputStream());
            objectInputStream = new ObjectInputStream(socket.getInputStream());
            this.nat = nat;
            this.clientPort = socket.getPort();
        } catch (IOException e) {
            closeResources();
        }
    }

    @Override
    /**
     * Overrides the Runnable class's run method to allow for concurrent client connections.
     */
    public void run() {
        while (socket.isConnected()) {
            try {
                Paquet paquet = (Paquet) objectInputStream.readObject();
                handlePaquet(paquet);
            } catch (IOException e) {
                closeResources();
                break;
            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Actually sends a paquet to the client over TCP.
     * @param paquet The paquet to send.
     */
    public void tcpSendToThisClient(Paquet paquet) {
        try {
            objectOutputStream.writeObject(paquet);
            objectOutputStream.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Returns if the client connection is internal.
     * @return True if the client connection is internal, false otherwise.
     */
    public boolean isInternal() {
        return internalExternal == 'i';
    }

    /**
     * Handles paquets based on the paquet's type.
     * 
     * Handles different types of paquets: ECHO_REPLY, ECHO_REQUEST, DHCP_REPLY, DHCP_REQUEST, ARP_REPLY, ARP_REQUEST and ERROR.
     * DHCP_REQUEST assigns client MAC, IP address and port. ECHO- _REPLY and _REQUEST both call the paquetForwarding method.
     * 
     * @param paquet The paquet in question.
     */
    private void handlePaquet(Paquet paquet) {
        int type = paquet.type;
        switch (type) {
            case ECHO_REPLY:
                paquetForwarding(paquet);
                break;

            case ECHO_REQUEST:
                paquetForwarding(paquet);
                break;
            case DHCP_REPLY:
                // nothing
                break;

            case DHCP_REQUEST:
                dhcpRequest(paquet);
                if (internalExternal == 'i') {
                    System.out.println("New client connected:\n  Type : Internal");
                } else {
                    System.out.println("New client connected:\n  Type : External");
                }

                System.out.println("  MAC  : " + clientMAC);
                System.out.println("  IP   : " + clientAddress);
                System.out.println("  Port : " + clientPort);
                if (natPort != 0) {
                    System.out.println("  NAT-box Port: " + natPort);
                }
                System.out.println();
                break;

            case ARP_REPLY:
                // nothing
                break;

            case ARP_REQUEST:
                arp(paquet);
                break;

            case ERROR:
                // nothing
                break;
            default:
                System.out.println("ERROR!: Invalid Paquet Type ");
                System.exit(0);
        }
    }

    /**
     * Forwards the given paquet based on its destination and NAT configuration.
     * 
     * If the client is internal and destination IP is internal the packet is sent directly to the client over TCP.
     * If destination IP is external, the paquets source information is modified to the NAT's IP and port and sends it out to the external network.
     * If the client is external, and the destination IP is the NAT's IP with a valid NAT port, the paquet is forwarded to the internal client associated with that NAT port.
     * If destination client is not found, an error paquet is sent back.
     * 
     * @param paquet The paquet to forward.
     */
    private void paquetForwarding(Paquet paquet) {
        if (internalExternal == 'i' && nat.isIPInternal(paquet.destinationIP)) {
            // internal -> internal
            nat.tcpSend(paquet);
        } else if (internalExternal == 'i' && nat.isIPExternal(paquet.destinationIP)) {
            // internal -> external
            paquet.sourceIP = nat.getIP();
            paquet.sourceMAC = nat.getMAC();
            paquet.sourcePort = natPort;
            nat.tcpSend(paquet);
            // Update last access time for NAT entry
            nat.updateLastAccessTime(paquet.sourceIP, paquet.sourcePort);
        } else if (internalExternal != 'i' && paquet.destinationIP.equals(nat.getIP())
                && nat.checkNatPort(paquet.destinationPort)) {
            // external -> internal
            String ip = nat.getClientIPFromNATPort(paquet.destinationPort);
            paquet.destinationIP = ip;
            paquet.destinationMAC = nat.getClientMACFromIP(ip);
            paquet.destinationPort = nat.getClientPortFromIP(ip);
            nat.tcpSend(paquet);
            // Update last access time for NAT entry
            nat.updateLastAccessTime(ip, paquet.destinationPort);
        } else {
            // Destination client not connected to NAT
            System.out.println("ERROR: DESTINATION CLIENT NOT FOUND\n");
            try {
                paquet.type = ERROR;
                objectOutputStream.writeObject(paquet);
                objectOutputStream.flush();
            } catch (Exception e) {

            }
        }
    }

    /**
     * Processes DHCP requests from clients.
     * 
     * Extracts client IP, MAC and port and determines if client is external or internal from the paquet message.
     * 
     * If internal, it assigns an IP from the NAT's IP pool, updates the NAT table, and sends a DHCP reply paquet back to the client with the client with the assigned IP address.
     * If there are no IP addresses available in the pool, it sends an error paquet.
     * If the client is external, no further action is taken.
     * 
     * @param paquet The paquet in question.
     */
    private void dhcpRequest(Paquet paquet) {
        clientMAC = paquet.sourceMAC;
        clientAddress = paquet.sourceIP;
        clientPort = paquet.sourcePort;
        if (paquet.message.equals("internal"))
            internalExternal = 'i';
        else
            internalExternal = 'e';
        if (internalExternal == 'i') {
            clientAddress = nat.popIPfromPool();
            if (clientAddress == null) {
                Paquet newPaquet = new Paquet(null, null, null, null, 0, 0, ERRORNP, "No more IPs available");
                try {
                    objectOutputStream.writeObject(newPaquet);
                    objectOutputStream.flush();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                return;
            }
            natPort = nat.getopenPort();
            addToTable();
        }
        Paquet newPaquet = new Paquet(nat.getMAC(), null, null, clientAddress, natPort, 0, DHCP_REPLY, null);
        try {
            objectOutputStream.writeObject(newPaquet);
            objectOutputStream.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Handles ARP requests and replies.
     * 
     * Extracts source MAC address, source IP address, destination IP address and message from the provided paquet.
     * Then, determines destination MAC based on if the destination IP is the NAT's IP address or the client's IP address.
     * If destination IP matches the NAT's IP, the destination MAC is set to the NAT's MAC address, otherwise it retrieves the client's MAC address using the destination IP.
     * Then constructs a new ARP reply packet with the appropriate MAC addresses and sends it back to the source client.
     * 
     * @param paquet The ARP request paquet received from the client.
     */
    private void arp(Paquet paquet) {
        String sourceMac = paquet.sourceMAC;
        String sourceIP = paquet.sourceIP;
        String destIP = paquet.destinationIP;
        int sourcePort = paquet.sourcePort;
        String text = paquet.message;
        String destMac;
        if (destIP.equals(nat.getIP())) {
            destMac = nat.getMAC();
        } else {
            destMac = nat.getClientMACFromIP(destIP);
        }
        int destPort = paquet.destinationPort;
        if (destPort == 0) { // internal
            destPort = nat.getClientPortFromIP(destIP);
        }

        Paquet newPaquet = new Paquet(sourceMac, destMac, sourceIP, destIP, sourcePort, destPort, ARP_REPLY, text);
        try {
            objectOutputStream.writeObject(newPaquet);
            objectOutputStream.flush();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Adds client to NAT table.
     */
    private void addToTable() {
        nat.addRow(clientAddress, socket.getPort(), nat.getIP(), natPort, this);
    }

    /**
     * Closes client connection resources.
     */
    public void closeResources() {
        nat.removeClient(this);
        if (internalExternal == 'i') {
            nat.addIPtoPool(clientAddress);
        }
        try {
            if (objectInputStream != null)
                objectInputStream.close();
            if (objectOutputStream != null)
                objectOutputStream.close();
            if (socket != null)
                socket.close();
        } catch (IOException e) {
        }
    }

}

/**
 * Represents a network paquet on the NAT side.
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
