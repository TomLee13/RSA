package project2task5;

import java.net.*;
import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class RSAClientTCP {
    Socket clientSocket;
    int serverPort;
    // Client's public and private keys
    // Each public and private key consists of an exponent and a modulus
    BigInteger n; // n is the modulus for both the private and public keys
    BigInteger e; // e is the exponent of the public key
    BigInteger d; // d is the exponent of the private key
    
    // Constructor
    public RSAClientTCP() {
        System.out.println("Constructor called");
        // generate keys for this client
        keyGeneration();
    }
    
    // Initialization method
    public void init() throws IOException {
        serverPort = 7777;
        clientSocket = new Socket("localhost", serverPort);
    }
    
    // generate client's public and private keys
    private void keyGeneration() {
        Random rnd = new Random();
        // Step 1: Generate two large random primes.
        BigInteger p = new BigInteger(400,100,rnd);
        BigInteger q = new BigInteger(400,100,rnd);
        // Step 2: Compute n by the equation n = p * q.
        n = p.multiply(q);
        // Step 3: Compute phi(n) = (p-1) * (q-1)
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        // Step 4: Select a small odd integer e that is relatively prime to phi(n).
        e = new BigInteger ("65537");
        // Step 5: Compute d as the multiplicative inverse of e modulo phi(n).
        d = e.modInverse(phi);
        
        System.out.println(" e = " + e);  // Step 6: (e,n) is the RSA public key
        System.out.println(" d = " + d);  // Step 7: (d,n) is the RSA private key
        System.out.println(" n = " + n);  // Modulus for both keys
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
    
    // the method that allows the client to sign the message to be sent
    public String sign(String message) throws Exception {
        
        // compute the digest with SHA-256
        byte[] bytesOfMessage = message.getBytes("UTF-8");
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] bigDigest = md.digest(bytesOfMessage);
        
        // we add a 0 byte as the most significant byte to keep
        // the value to be signed non-negative.
        byte[] messageDigest = new byte[bigDigest.length + 1];
        messageDigest[0] = 0;   // most significant set to 0
        for (int i = 0; i < bigDigest.length; i++) {
            messageDigest[i + 1] = bigDigest[i];
        }
        
        // From the digest, create a BigInteger
        BigInteger m = new BigInteger(messageDigest); 
        
        // encrypt the digest with the private key
        BigInteger c = m.modPow(d, n);  
        
        // return this as a big integer string
        return c.toString();
    }
    
    // a method communicating with the server implementing the proxy pattern.
    // add
    public void add(BufferedReader in, PrintWriter out, String message)
            throws IOException {
        // print the message to the server
        out.println(message);
        out.flush();
        // read a line of data from the stream
        String data = in.readLine();
        System.out.println("Reply: " + data);
    }
    
    // a method communicating with the server implementing the proxy pattern.
    // substract
    public void subtract(BufferedReader in, PrintWriter out, String message)
            throws IOException {
        // print the message to the server
        out.println(message);
        out.flush();
        // read a line of data from the stream
        String data = in.readLine();
        System.out.println("Reply: " + data);
    }
    
    // a method communicating with the server implementing the proxy pattern.
    // view
    public void view(BufferedReader in, PrintWriter out, String message)
            throws IOException {
        // print the message to the server
        out.println(message);
        out.flush();
        // read a line of data from the stream
        String data = in.readLine();
        System.out.println("Reply: " + data);
    }
    
    public static void main(String args[]) {
        System.out.println("Client running");
        RSAClientTCP client = new RSAClientTCP();
        
        try {
            // Initialize the client object
            client.init();
            
            // Create reader and writer for the client
            BufferedReader in = new BufferedReader(new InputStreamReader(client.clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(client.clientSocket.getOutputStream())));
            // Create reader for user input
            BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
            
            int count = 1;
            while (true) {
                System.out.println("Operation " + count);
                // compute hash of the public key
                String pubKey = client.e.toString() + client.n.toString();
                String id = client.computeSHA_256_as_Hex_String(pubKey);
                System.out.println(" ID is: " + id);
                
                String operation = "";
                String value = "";
                // take user input for the 2 values above: operation and value
                System.out.println("Enter the operation you want to perform:");
                operation = input.readLine();
                if (!operation.equals("view")) {
                    System.out.println("Enter a value:");
                    value = input.readLine();
                }
                
                // use a StringBuilder to build a message to be sent
                // the message so far includes: userID, pubKey(e), pubKey(n), opearion, (value)
                StringBuilder sb = new StringBuilder();
                sb.append(id).append(",").
                        append(client.e.toString()).append(",").
                        append(client.n.toString()).append(",").
                        append(operation);
                if (!value.equals("")) {
                    sb.append(",").append(value);
                }
                
                // sign the message above
                String sign = client.sign(sb.toString());
                System.out.println("Client has signed the message.");
                
                // append the signature to the message to be sent
                sb.append(",").append(sign);
                
                // the message to be sent includes: userID, pubKey(e), pubKey(n), opearion, (value), signature
                // the key information in this message is comma seperated
                
                // depending on the value of operation, call different communicating functions
                if (operation.equals("add")) {
                    client.add(in, out, sb.toString());
                } else if (operation.equals("subtract")) {
                    client.subtract(in, out, sb.toString());
                } else if (operation.equals("view")) {
                    client.view(in, out, sb.toString());
                } else {
                    System.out.println("Please enter a valid command.");
                }                
                count++;
            }
        } catch (IOException e) {
            System.out.println("IO Exception:" + e.getMessage());
        } catch (Exception e) {
            System.out.println("Exception caught: " + e.getMessage());
        }finally {
            try {
                if (client.clientSocket != null) {
                    client.clientSocket.close();
                }
            } catch (IOException e) {
                // ignore exception on close
            }
        }
    }
}
