# RSA
RSA encryption and verification using TCP  

The functionalities of this program are:  
1. Each time the client runs, it will create new RSA public and private keys. After it creates these keys, it interacts
with the server.  
2. The client’s id will be formed by taking the least significant 20 bytes of the hash of the
client’s public key. Note: an RSA public key is the pair e and n.  
3. The client will be interactive and menu driven. It will transmit add or subtract or view requests to the server, 
along with the id computed in (2).  
4. The client will also transmit its public key with each request.  
5. Finally, the client will sign each request. So, by using its private key (d and n), the client will encrypt the hash of 
the message it sends to the server. The signature will be added to each request.  
6. The server will make two checks before servicing any client request. First, does the public key (included with each request) 
hash to the id (also provided with each request)? Second, is the request properly signed? 
If both of these are true, the request is carried out on behalf of the client. 
The server will add, subtract or view. Otherwise, the server returns the message “Error in request”.  
