package seguridad;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class Cifrado {
	
	private final static String PADDING="AES/ECB/PKCS5Padding";

	public static byte[] cifrar(PublicKey servidorP, byte[] texto, String algoritmo) {
		try {

			Cipher cipher = Cipher.getInstance(algoritmo);
			System.out.println(servidorP);
			cipher.init(Cipher.ENCRYPT_MODE, servidorP);

			byte [] cipheredText = cipher.doFinal(texto);

			return cipheredText;
		}
		catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}

	public static byte[] cifrarLS(SecretKey ls, byte[] texto) {


		byte [] cipheredText;
		try {
			Cipher cipher = Cipher.getInstance(PADDING);

			cipher.init(Cipher.ENCRYPT_MODE, ls);

			cipheredText = cipher.doFinal(texto);

			return cipheredText;
		}
		catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}

	}
	public static byte[] descifrarLS(SecretKey ls, byte[] texto) {
		try {
			Cipher cipher = Cipher.getInstance(PADDING);

			byte[] cipheredText = texto;
			cipher.init(Cipher.DECRYPT_MODE, ls);
			byte [] clearText = cipher.doFinal(cipheredText);
			return clearText;

		}
		catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}

	public static byte[] descifrar(byte[] cipheredText, PrivateKey privada, String algoritmo) {
		try {
			Cipher cipher = Cipher.getInstance(algoritmo);
			cipher.init(Cipher.DECRYPT_MODE, privada);
			byte [] clearText = cipher.doFinal(cipheredText);
			System.out.println("Texto descifrado: "+ clearText.toString());
			return clearText;

		}
		catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
			return null;
		}
	}

	//Lo pusimos como long, pero puede que sea String
	public static byte[] getKeyedDigest(byte[] array, Key key) {
		try {
	        Mac mac = Mac.getInstance("HMACMD5");
	        mac.init(key);
	        byte[] bytes = mac.doFinal(array);
	        return bytes;
		} catch (Exception e) {
			return null;
		}
	}
	
	public static boolean verificar(byte[] codigo, byte[] calculado){
		boolean rta = false;
		if(codigo.length != calculado.length){
			return false;
		}
		for (int i = 0; i < calculado.length; i++) {
			if(codigo[i]==calculado[i]){
				rta=true;
			}
		}
		return rta; 
	}
}