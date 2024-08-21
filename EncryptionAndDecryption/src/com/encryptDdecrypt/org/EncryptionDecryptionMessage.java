package com.encryptDdecrypt.org;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;
import com.encrypt.org.*;
import com.decrypt.org.*;
import com.ibm.readfile.ReadFile;

public class EncryptionDecryptionMessage 
{
	public static void main(String[] args)
	{
		Scanner sc = new Scanner(System.in);
		String message = sc.next();
		
		try {
			//KeyPair pair = GenarateKeyPairs.generateKeyPairs();
			
			//setting publicKey and privateKey file path
			String publicKeyPath = "C:\\Users\\syste\\OneDrive\\Documents\\keys\\publickey.crt";
			String privateKeyPath = "C:\\Users\\syste\\OneDrive\\Documents\\keys\\privatekey.crt";
			
			
			//reading public and private key from file
			String pubKey = ReadFile.getKeyFromFile(publicKeyPath);
			String priKey = ReadFile.getKeyFromFile(privateKeyPath);
			
			
			//encoding publicKey and privateKey into byte[] 
			byte[] publicKeyBytes = Base64.getDecoder().decode(pubKey.getBytes());
			byte[] privateKeyBytes = Base64.getDecoder().decode(priKey.getBytes());
			
			
			//extracting publicKey from publicKeyBytes to publicKey type
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
			PublicKey publickey = keyFactory.generatePublic(publicKeySpec);
			
			
			//extracting privateKey from privateKeyBytes to privateKey type
			KeyFactory keyFactory1 = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
			PrivateKey privateKey = keyFactory1.generatePrivate(privateKeySpec);
			
			
			//PublicKey publicKey = pair.getPublic();
			//PrivateKey privateKey = pair.getPrivate();
			
			
			//encrypting message using public key
			String encryptedMessage = EncrptyMessage.encrypt(publickey, message);
			
			System.out.println("Encrypted Message : "+encryptedMessage);
			
			//decrypting message using private key
			String decryptedMessage = DecryptMessage.decryptMessage(privateKey, encryptedMessage);
			
			System.out.println("Decrypted Message : "+decryptedMessage);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}
}
