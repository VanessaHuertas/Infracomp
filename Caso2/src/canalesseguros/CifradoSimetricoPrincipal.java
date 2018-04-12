package canalesseguros;

public class CifradoSimetricoPrincipal {

	public static void main(String[] args) {
		CifradoSimetrico algoritmo = new CifradoSimetrico();
		byte[] cifrado = algoritmo.cifrar();
		
		algoritmo.descifrar(cifrado);
		
		CifradoSimetrico algoritmo2 = new CifradoSimetrico();
		byte[] cifrado2 = algoritmo2.cifrar();
		
		algoritmo2.descifrar(cifrado2);
	}
}
