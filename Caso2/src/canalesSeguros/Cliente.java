package canalesSeguros;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Date;

import seguridad.Certificado;
import seguridad.Cifrado;
import server.Seguridad;
import server.Transformacion;
import server.Worker;

public class Cliente{

	private static final String IP = "localhost"; 
	private static Certificado cert;

	public static void main( String[] args )throws Exception {

		cert = new Certificado();
		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;
		try {
			socket = new Socket(IP, 8080);
			escritor = new PrintWriter(socket.getOutputStream(), true);
			lector = new BufferedReader(new InputStreamReader(
					socket.getInputStream()));
		} catch (Exception e) {
			System.err.println("Exception: " + e.getMessage());
			System.exit(1);
		}
		BufferedReader stdIn = new BufferedReader(
				new InputStreamReader(System.in));
		try
		{
			comenzar(lector,escritor);			
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}

		escritor.close();
		lector.close();
		stdIn.close();
		// cierre el socket y la entrada estándar
		socket.close();

	}

	public static void comenzar(BufferedReader pIn,PrintWriter pOut) throws Exception 
	{
		byte[] reto = new byte[1];

		String inputLine, outputLine;
		int estado = 0;
		pOut.println("HOLA");

		boolean finalizo = false;
		while (!finalizo && (inputLine = pIn.readLine()) != null) 
		{
			switch (estado) {
			case 0:
				if (inputLine.equalsIgnoreCase("OK")) 
				{
					outputLine = "ALGORITMOS:AES:RSA:HMACMD5";
					estado++;
				} 
				else 
				{
					outputLine = "ERROR-EsperabaOk";
					estado = 0;
				}
				pOut.println(outputLine);
				break;
			case 1:
				if(inputLine.equalsIgnoreCase("OK"))
				{
					outputLine = cert.create(new Date(), new Date(), "RSA", 512, "SHA1withRSA");
					estado++;
				}
				else
				{
					outputLine = "ERROR-EsperabaOk";
					estado = 0;
				}
				pOut.println(outputLine);
				String pem = leerCertificado(pIn);		
				if (pem.startsWith("-----BEGIN CERTIFICATE-----") && cert.readCertificate(pem)) 
				{
					byte[] act1Bytes = outputLine.getBytes();

					byte[] act1Cifrado = Seguridad.aE(act1Bytes, cert.getServerPublicKey(), Seguridad.RSA);
					String act1CifradoStr = Transformacion.toHexString(act1Cifrado);
				} 
				else 
				{
					outputLine = "ERROR-EsperabaCertificado";
					estado = 0;
				}
				pOut.println(outputLine);
				break;
			case 2:
				inputLine = pIn.readLine();
				byte[] numCifrado = Transformacion.toByteArray(inputLine);
				byte[] num = Cifrado.descifrar(numCifrado, cert.getOwnPrivateKey(), "RSA");

				boolean verificar = Seguridad.verifyIntegrity(numCifrado, cert.getOwnPrivateKey(), Seguridad.HMACMD5, num);

				if(verificar) {
					pOut.println(Worker.ESTADO + Worker.SEPARADOR + Worker.OK);
					outputLine= Worker.OK;
					estado++;
				}else {
					pOut.println(Worker.ERROR + Worker.SEPARADOR + "No se cumple con integridad de respuesta");
					estado = 0;
					outputLine = Worker.ERROR;
				}
				pOut.println(outputLine);
				break;
			case 3:
				byte[] numCifrado2 = Transformacion.toByteArray(inputLine);
				byte[] num2 = Cifrado.descifrar(numCifrado2, cert.getOwnPrivateKey(), "RSA");

				byte[] cifrado = Cifrado.cifrar(cert.getServerPublicKey(), num2, "RSA");
				outputLine = Transformacion.toHexString(cifrado);
				estado++;
				pOut.println(outputLine);
				break;
			case 5:
				String[] input = inputLine.split(":");
				byte[] hexInput1 = Transformacion.toByteArray(input[0]);
				byte[] hexInput2 = Transformacion.toByteArray(input[1]);
				byte[] resLS = Cifrado.descifrarLS(cert.getLlaveSimetrica(), hexInput1);

				byte[] resHashLS = Cifrado.descifrarLS(cert.getLlaveSimetrica(), hexInput2);

				byte[] hashCalculado = Cifrado.getKeyedDigest(resLS, cert.getLlaveSimetrica());

				boolean verificarA = Seguridad.verifyIntegrity(resHashLS, cert.getOwnPrivateKey(), Seguridad.HMACMD5, hashCalculado);

				if(verificarA) {
					pOut.println(Worker.ESTADO + Worker.SEPARADOR + Worker.OK);
					System.out.println("El protocolo termina de manera correcta.");
					finalizo = true;
				}else {
					outputLine  = Worker.ERROR;
				}
				break;
			default:
				outputLine = "ERROR";
				estado = 0;
				pOut.println(outputLine);
				break;
			}
		}

	}

	private static String leerCertificado(BufferedReader pIn) throws IOException
	{
		String pem = "";
		String input = pIn.readLine();
		if(input.equalsIgnoreCase("-----BEGIN CERTIFICATE-----"))
		{
			boolean finish = false;
			pem += input + System.lineSeparator();
			while(!finish)
			{
				input = pIn.readLine();
				pem += input + System.lineSeparator();
				if(input.equalsIgnoreCase("-----END CERTIFICATE-----"))
				{
					finish = true;
				}
			}
		}
		return pem;
	}
}
