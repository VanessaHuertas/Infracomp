package canalesseguros;

public class CifradoAsimetricoPrincipal {
		
	public static void main(String[] args) {
		CifradoAsimetrico cifradoAsimetrico = new CifradoAsimetrico();	
		byte[] cifrado = cifradoAsimetrico.cifrar();
		System.out.println("");
		cifradoAsimetrico.descifrar(cifrado);		
	}	
}
