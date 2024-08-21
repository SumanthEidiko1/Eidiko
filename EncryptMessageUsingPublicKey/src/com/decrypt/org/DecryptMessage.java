package com.decrypt.org;

import java.security.PrivateKey;
import java.util.Base64;

import javax.crypto.Cipher;

public class DecryptMessage 
{
	public static String decryptMessage(PrivateKey privateKey,String encryptedMessage)
	{
		String originalMessage = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
			originalMessage = new String(decryptedBytes);
		} catch (Exception e) {
			// TODO Auto- generated catch block
			e.printStackTrace();
		}
		return originalMessage;
	}
}