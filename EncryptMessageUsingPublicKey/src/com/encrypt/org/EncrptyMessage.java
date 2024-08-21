package com.encrypt.org;

import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;


public class EncrptyMessage 
{
	public static String encrypt(PublicKey publicKey, String Message)
	{
		String encryptedText = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] encryptedBytes = cipher.doFinal(Message.getBytes());
			encryptedText = Base64.getEncoder().encodeToString(encryptedBytes);
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
		return encryptedText;
	}
}
