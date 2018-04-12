package canalesSeguros;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class NuevaImplementacion {

	public static void main(String[] args) {

		CifradoSimetrico algoritmo = new CifradoSimetrico();
		byte[] pCifrado = algoritmo.cifrar();
		SecretKey pKey = algoritmo.getKey();

		try {
			FileOutputStream farch = new FileOutputStream("datoCifrado");
			ObjectOutputStream oos = new ObjectOutputStream(farch);
			oos.writeObject(pCifrado);
			oos.close();

			FileOutputStream farch2 = new FileOutputStream("llave");
			ObjectOutputStream oos2 = new ObjectOutputStream(farch2);
			oos2.writeObject(pKey);
			oos2.close();

			FileInputStream input = new FileInputStream("datoCifrado");
			ObjectInputStream ois = new ObjectInputStream(input);
			byte[] cipheredText = (byte[])ois.readObject();
			ois.close();
			
			FileInputStream input2 = new FileInputStream("llave");
			ObjectInputStream ois2 = new ObjectInputStream(input2);
			SecretKey llave = (SecretKey)ois2.readObject();
			ois2.close();
			
			Cipher cipher = Cipher.getInstance(CifradoSimetrico.ALGORITMO);
			cipher.init(Cipher.DECRYPT_MODE, llave);
			byte[] clearText = cipher.doFinal(cipheredText);
			String s3 = new String(clearText);
			System.out.println("Clave descifrada: " + s3);

		}catch(Exception e) {
			System.out.println("Excepci�n: " + e.getMessage());	
		}		
	}
}
