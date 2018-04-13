package canalesSeguros;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.Cipher;

public class CifradoAsimetrico {

	private KeyPair keyPair;
	private final static String ALGORITMO = "RSA";
	
	public byte[] cifrar(){
		try {
			
			KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITMO);
			generator.initialize(1024);
			keyPair = generator.generateKeyPair();
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
			String pwd = stdIn.readLine();
			byte[] clearText = pwd.getBytes();
			String s1 = new String(clearText);
			System.out.println("Clave original: " + s1);
			
			System.out.println("");
			cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
			long startTime = System.nanoTime();
			byte[] cipheredText = cipher.doFinal(clearText);
			long endTime = System.nanoTime();
			System.out.println("Clave cifrada: " + cipheredText);
			System.out.println("Tiempo asim�trico: " + (endTime-startTime));
			
			return cipheredText;
			
		}catch(Exception e) {
			
			System.out.println("Excepci�n: " + e.getMessage());
			return null;
		}
	}	
	
	public void descifrar( byte[] cipheredText ) {
		try {
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
			byte[] clearText = cipher.doFinal(cipheredText);
			String s3 = new String(clearText);
			System.out.println("Calve descifrada: " + s3);
			
		}catch (Exception e) {
			System.out.println("Excepci�n: " + e.getMessage());
		}
	}
}