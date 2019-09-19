package project2task5;

import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class RSAServerTCP {
    Map<String, User> userMap;
    Socket clientSocket;
    int serverPort;
    ServerSocket listenSocket;
    
    // Constructor
    public RSAServerTCP() {
        System.out.println("Constructor called");
        userMap = new HashMap<>();
    }
    
    // Initializer
    public void init() throws IOException {
        serverPort = 7777;
        listenSocket = new ServerSocket(serverPort);
        clientSocket = null;
    }
    
    // copied from BabyHash provided in class
    // modified to a byte array with the length of 20
    private String convertToHex(byte[] data) {
        StringBuffer buf = new StringBuffer();
        byte[] tmp = new byte[20];
        // copy the data array to the tmp array
        System.arraycopy(data, data.length - 21, tmp, 0, 20);
        
        for (int i = 0; i < tmp.length; i++) {
            int halfbyte = (tmp[i] >>> 4) & 0x0F;
            int two_halfs = 0;
            do {
                if ((0 <= halfbyte) && (halfbyte <= 9))
                    buf.append((char) ('0' + halfbyte));
                else
                    buf.append((char) ('a' + (halfbyte - 10)));
                halfbyte = tmp[i] & 0x0F;
            } while(two_halfs++ < 1);
        }
        
        return buf.toString();
    }
    
    // copied from BabyHash class
    // compute SHA-256 hash for a string
    public String computeSHA_256_as_Hex_String(String text) {
        
        try {
            // Create a SHA256 digest
            MessageDigest digest;
            digest = MessageDigest.getInstance("SHA-256");
            // allocate room for the result of the hash
            byte[] hashBytes;
            // perform the hash
            digest.update(text.getBytes("UTF-8"), 0, text.length());
            // collect result
            hashBytes = digest.digest();
            return convertToHex(hashBytes);
        }
        catch (NoSuchAlgorithmException nsa) {
            System.out.println("No such algorithm exception thrown " + nsa);
        }
        catch (UnsupportedEncodingException uee ) {
            System.out.println("Unsupported encoding exception thrown " + uee);
        }
        return null;
    }
    
    public boolean verifySignature(String messageToCheck, String sign, String eString, String nString)
            throws Exception  {
        // convert e, n to BigInteger
        BigInteger e = new BigInteger(eString);
        BigInteger n = new BigInteger(nString);
        
        // Take the encrypted string and make it a big integer
        BigInteger encryptedHash = new BigInteger(sign);
        // Decrypt it
        BigInteger decryptedHash = encryptedHash.modPow(e, n);
        
        // Get the bytes from messageToCheck
        byte[] bytesOfMessageToCheck = messageToCheck.getBytes("UTF-8");
        
        // compute the digest of the message with SHA-256
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        
        byte[] messageToCheckDigest = md.digest(bytesOfMessageToCheck);
        
        // messageToCheckDigest is a full SHA-256 digest
        // take two bytes from SHA-256 and add a zero byte
        byte[] extraByte = new byte[messageToCheckDigest.length + 1];
        extraByte[0] = 0;
        for (int i = 0; i < messageToCheckDigest.length; i++) {
            extraByte[i + 1] = messageToCheckDigest[i];
        }
        
        // Make it a big int
        BigInteger bigIntegerToCheck = new BigInteger(extraByte);
        
        // inform the client on how the two compare
        if(bigIntegerToCheck.compareTo(decryptedHash) == 0) {
            return true;
        } else {
            return false;
        }
    }
    
    // method to verify id and signature
    // note that the message to be seperated
    private boolean verify(String[] input) throws Exception {
        // 2 flags for verifying the client
        boolean idVerified = false;
        boolean signVerified = false;
        // Extract the public key of the client and verify the ID
        String id = input[0];
        String e = input[1];
        String n = input[2];
        String pubKey = e + n;
        String hashID = computeSHA_256_as_Hex_String(pubKey);
        // verify the id
        if (id.equals(hashID)) {
            idVerified = true;
        }
        
        // Extract the signature and message to be verified
        String sign = input[input.length - 1];
        
        // re-build the comma sepearated message
        StringBuilder messageToCheck = new StringBuilder();
        messageToCheck.append(input[0]).append(",").
                append(input[1]).append(",").
                append(input[2]).append(",").
                append(input[3]);
        if (!input[3].equals("view")) {
            messageToCheck.append(",").append(input[4]);
        }
        // verify the signature
        signVerified = verifySignature(messageToCheck.toString(), sign, e, n);
       
        return idVerified && signVerified;
    }
    
    // Server side operation add method communicating to the client
    private void add(String[] input, PrintWriter out) throws IOException {
        if (userMap.isEmpty()) { // if the map is empty
            // create a new user object
            User user = new User(input[0]);
            // add the value to this user's sum
            user.add(Double.parseDouble(input[input.length - 2]));
            // put the user into the userMap
            userMap.put(input[0], user);
        } else {
            if (userMap.containsKey(input[0])) { // if userMap contains the user
                // add the value to its sum
                userMap.get(input[0]).add(Double.parseDouble(input[input.length - 2]));
            } else {
                // create a new user object
                User user = new User(input[0]);
                // add the value to this user's sum
                user.add(Double.parseDouble(input[input.length - 2]));
                // put the user into the userMap
                userMap.put(input[0], user);
            }
        }
        out.println("OK");
        out.flush();
    }
    
    // Server side operation subtract method communicating to the client
    private void subtract(String[] input, PrintWriter out) throws IOException {
        if (userMap.isEmpty()) { // if the map is empty
            // create a new user object
            User user = new User(input[0]);
            // add the value to this user's sum
            user.subtract(Double.parseDouble(input[input.length - 2]));
            // put the user into the userMap
            userMap.put(input[0], user);
        } else {
            if (userMap.containsKey(input[0])) { // if userMap contains the user
                // add the value to its sum
                userMap.get(input[0]).subtract(Double.parseDouble(input[input.length - 2]));
            } else {
                // create a new user object
                User user = new User(input[0]);
                // add the value to this user's sum
                user.subtract(Double.parseDouble(input[input.length - 2]));
                // put the user into the userMap
                userMap.put(input[0], user);
            }
        }
        out.println("OK");
        out.flush();
    }
    
    // Server side operation view method communicating to the client
    private void view(String[] input, PrintWriter out) throws IOException {
        String replyString = "";
        
        if (userMap.isEmpty()) { // if the map is empty
            replyString = "No results available";
        } else {
            if (userMap.containsKey(input[0])) { // if userMap contains the user
                // add the value to its sum
                replyString = String.format("%.2f", userMap.get(input[0]).view());
            } else {
                replyString = "No results available";
            }
        }       
        out.println("The sum for user " + input[0] + " is " + replyString);
        out.flush();
    }
    
    
    
    public static void main(String args[]) {
        System.out.println("Server running");
        RSAServerTCP server = new RSAServerTCP();
        
        try {
            // Initialize
            server.init();
            /*
            * Block waiting for a new connection request from a client.
            * When the request is received, "accept" it, and the rest
            * the tcp protocol handshake will then take place, making
            * the socket ready for reading and writing.
            */
            server.clientSocket = server.listenSocket.accept();
            // If we get here, then we are now connected to a client.
            
            // Set up "in" to read from the client socket
            Scanner in;
            in = new Scanner(server.clientSocket.getInputStream());
            
            // Set up "out" to write to the client socket
            PrintWriter out;
            out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(server.clientSocket.getOutputStream())));
            
            /*
            * Forever,
            *   read a line from the socket
            *   print it to the console
            *   echo it (i.e. write it) back to the client
            */
            int count = 1;
            while (true) {
                System.out.println("Operation " + count);
                if (in.hasNext()) { // if the Scanner has next token
                    String data = in.nextLine();
                    
                    // parse the comma seperated message
                    String[] input = data.split(",");
                    
                    // verify the request
                    boolean verified = server.verify(input);
                    
                    if (verified) {
                        System.out.println("Verified client");
                        System.out.println("Sending reply");
                        // decide which operation to take
                        if (input[3].equals("add")) {
                            server.add(input, out);
                        } else if (input[3].equals("subtract")) {
                            server.subtract(input, out);
                        } else if (input[3].equals("view")) {
                            server.view(input, out);
                        }
                    } else {
                        out.println("Error in request");
                        out.flush();
                    }
                } else { // if the Scanner is empty
                    // stop the connection
                    server.listenSocket.close();
                    System.out.println("Server stops");
                    break;
                }
                count++;
            }
            
            // Handle exceptions
        } catch (IOException e) {
            System.out.println("IO Exception:" + e.getMessage());
            
            // If quitting (typically by you sending quit signal) clean up sockets
        } catch (Exception e) {
            System.out.println("Exception caught: " + e.getMessage());
        }finally {
            try {
                if (server.clientSocket != null) {
                    server.clientSocket.close();
                }
            } catch (IOException e) {
                // ignore exception on close
            }
        }
    }
}
