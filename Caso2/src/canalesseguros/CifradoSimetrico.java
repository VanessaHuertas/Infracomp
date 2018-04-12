package canalesseguros;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class CifradoSimetrico {

	private SecretKey desKey;
	public final static String ALGORITMO = "AES";
	
	public byte[] cifrar() {
		byte[] cipheredText;
		
		try {
			
			KeyGenerator keygen = KeyGenerator.getInstance(ALGORITMO);
			desKey = keygen.generateKey();
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
			
			String pwd = stdIn.readLine();
			byte[] clearText = pwd.getBytes();
			String s1 = new String(clearText);
			System.out.println("Clavo original: " + s1);
			
			cipher.init(Cipher.ENCRYPT_MODE, desKey);
			long startTime = System.nanoTime();
			cipheredText = cipher.doFinal(clearText);
			long endTime = System.nanoTime();
			String s2 = new String(cipheredText);
			System.out.println("Clave cifrada: " + s2);
			System.out.println("Tiempo: " + (endTime-startTime));
			
			return cipheredText;
			
		}catch( Exception e ) {
			System.out.println("Excepci�n: " + e.getMessage());
			return null;
		}
	}
	
	public void descifrar( byte[] cipheredText ) {
		try {
			
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			cipher.init(Cipher.DECRYPT_MODE, desKey);
			byte[] clearText = cipher.doFinal(cipheredText);
			String s3 = new String(clearText);
			System.out.println("Clave descifrada: " + s3);
			
		}catch(Exception e) {
			System.out.println("Excepci�n: " + e.getMessage());
		}
	}
	
	public SecretKey getKey() {
		return desKey;
	}
}
