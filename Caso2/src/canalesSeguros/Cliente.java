package canalesSeguros;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import seguridad.Certificado;
import seguridad.Cifrado;
import server.Seguridad;
import server.Transformacion;
import server.Worker;

public class Cliente{

	private static final String IP = "localhost"; 
	private static Certificado cert;

	public static void main( String[] args ){

		cert = new Certificado();
		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;
		try {
			socket = new Socket(IP, 8084);
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
			comenzar(lector, escritor, socket, socket.getOutputStream());
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
		finally {
			try {
				escritor.close();
				lector.close();
				stdIn.close();
				// cierre el socket y la entrada estándar
				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	public static void comenzar(BufferedReader pIn, PrintWriter pOut, Socket socket, OutputStream oS) throws Exception 
	{
		String inputLine, outputLine;
		int estado = 0;
		
		pOut.println("HOLA");

		boolean finalizo = false;
		inputLine = pIn.readLine();
		while (!finalizo && inputLine != null) 
		{
			switch (estado) {
			case 0:
				if (inputLine.equalsIgnoreCase("INICIO")) 
				{
					outputLine = "ALGORITMOS:AES:RSA:HMACMD5";
					estado++;
				} 
				else 
				{
					outputLine = "ERROR-EsperabaInicio";
					estado = 0;
				}
				pOut.println(outputLine);
				break;
			case 1:
				inputLine = pIn.readLine();
				if(inputLine.equalsIgnoreCase("ESTADO:OK"))
				{
					outputLine = "CERTCLNT";
					estado++;
				}
				else
				{
					outputLine = "ERROR-EsperabaOk";
					estado = 0;
				}
				pOut.println(outputLine);
				
				byte[] bytes = cert.createBytes(new Date(), new Date(), "RSA", 512, "SHA1withRSA");
				oS.write(bytes);
				break;
				
			case 2:
				inputLine = pIn.readLine();
				if(inputLine.equalsIgnoreCase("ESTADO:OK"))
				{
					estado++;
				}
				else
				{
					outputLine = "ERROR-EsperabaOk";
					pOut.println(outputLine);
					estado = 0;
				}
				break;
			case 3:
				inputLine = pIn.readLine();
				if(inputLine.equalsIgnoreCase("CERTSRV"))
				{
					estado++;
				}
				else
				{
					outputLine = "ERROR-EsperabaAnuncioCERT";
					pOut.println(outputLine);
					estado = 0;
				}
				break;
			case 4:
				InputStream inStream = socket.getInputStream();
				X509Certificate serverCertificate = null;
				byte[] buffer = new byte[1024];
				inStream.read(buffer);
				inStream = new ByteArrayInputStream(buffer);
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				serverCertificate = (X509Certificate)cf.generateCertificate(inStream);
				cert.setServer(serverCertificate);
				if(serverCertificate != null) {
					outputLine = "Estado:OK";
				}
				else 
				{
					outputLine = "ERROR-EsperabaCertificadoValido";
					estado = 0;
				}
				pOut.println(outputLine);
				estado++;
				break;
			case 5:
				inputLine = pIn.readLine();
				byte[] act1B = inputLine.getBytes();
				String act1S = new String(act1B);
				System.out.println(act1S);
				
				byte[] act1Cifrado = Seguridad.aE(act1B, cert.getOwnPublicKey(), "RSA");
				byte[] act1 = Cifrado.descifrar(act1Cifrado, cert.getOwnPrivateKey(), "RSA");
				
				byte[] cifrado1 = Cifrado.cifrar(cert.getServerPublicKey(), act1, "RSA");
				outputLine = Transformacion.toHexString(cifrado1);

				boolean verificar = Seguridad.verifyIntegrity(act1Cifrado, cert.getOwnPrivateKey(), Seguridad.HMACMD5, act1);

				if(verificar) {
					pOut.println("Estado:OK");
					outputLine= "OK";
					estado++;
				}else {
					pOut.println("ERROR:No se cumple con integridad de respuesta");
					estado = 0;
					outputLine = "ERROR";
				}
				pOut.println(outputLine);
				break;
			case 6:
				inputLine = pIn.readLine();
				byte[] act2B = inputLine.getBytes();
				String act2S = new String(act2B);
				
				byte[] actCifrado2 = Transformacion.toByteArray(act2S);
				byte[] act2 = Cifrado.descifrar(actCifrado2, cert.getOwnPrivateKey(), "RSA");

				byte[] cifrado = Cifrado.cifrar(cert.getServerPublicKey(), act2, "RSA");
				outputLine = Transformacion.toHexString(cifrado);
				estado++;
				pOut.println(outputLine);
				break;
			case 7:
				inputLine = pIn.readLine();
				String[] input = inputLine.split(":");
				byte[] hexInput1 = Transformacion.toByteArray(input[0]);
				byte[] hexInput2 = Transformacion.toByteArray(input[1]);
				byte[] resLS = Cifrado.descifrarLS(cert.getLlaveSimetrica(), hexInput1);

				byte[] resHashLS = Cifrado.descifrarLS(cert.getLlaveSimetrica(), hexInput2);

				byte[] hashCalculado = Cifrado.getKeyedDigest(resLS, cert.getLlaveSimetrica());

				boolean verificarA = Seguridad.verifyIntegrity(resHashLS, cert.getOwnPrivateKey(), Seguridad.HMACMD5, hashCalculado);

				if(verificarA) {
					pOut.println("ESTADO:OK");
					System.out.println("El protocolo termina de manera correcta.");
					finalizo = true;
				}else {
					outputLine  = "ERROR";
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
}
