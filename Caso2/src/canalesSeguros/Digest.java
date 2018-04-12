package canalesSeguros;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.MessageDigest;

public class Digest {

	private byte[] getKeyDigest(byte[] buffer)
	{
		try {
			
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			md5.update(buffer);
			return md5.digest();
		}catch(Exception e) {
			return null;
		}
	}

	public byte[] calcular() {
		try {
			BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
			String dato = stdIn.readLine();
			byte[] text = dato.getBytes();
			String s1 = new String(text);
			System.out.println("Dato original: " + s1);

			byte[] digest = getKeyDigest(text);
			String s2 = new String(digest);
			System.out.println("Digest: " + s2);
			return digest;
		}catch(Exception e) {
			System.out.println( "Excepción: " + e.getMessage());
			return null;
		}
	}

	public boolean verificar(byte[] pCodigo)
	{	
		//Revisar
		boolean si = false;
		byte[] pCodigoCalculado = calcular();

		if (pCodigo.length == calcular().length)
		{
			int cont = 0;
			byte[] datos = new byte[pCodigo.length];

			for (int i = 0; i < datos.length; i++) {
				if( pCodigo[i] == pCodigoCalculado[i] ) {
					cont++;
				}
			}
			if( cont == pCodigo.length ) {
				si = true;
			}
		}

		return si;
	}

	public static void main ( String[] args ) {
		Digest calculo = new Digest();
		byte[] textoCal = calculo.calcular();
		boolean si = calculo.verificar(textoCal);
		String textS = "";
		if(si)textS = "Igual";
		else textS = "Diferente";
		System.out.println("Texto verificado: " + textoCal + "Igual?: " + textS);
	}
}
