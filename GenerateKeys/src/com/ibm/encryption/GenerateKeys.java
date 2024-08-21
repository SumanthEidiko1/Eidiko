package com.ibm.encryption;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class GenerateKeys 
{
	public static void main(String[] args) {
		generate();
	}
	public static void generate() 
	{
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			/*PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();
			System.out.println("Public key : "+Base64.getEncoder().encodeToString(publicKey.getEncoded()));
			System.out.println("Private key : "+Base64.getEncoder().encodeToString(privateKey.getEncoded()));*/
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
