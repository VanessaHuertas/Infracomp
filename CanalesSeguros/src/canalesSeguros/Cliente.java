package canalesSeguros;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.util.encoders.Hex;

import mediciones.EscritorIndicadores;
import seguridad.Certificado;
import seguridad.Cifrado;
import server.Seguridad;
import server.Transformacion;

public class Cliente{

	private static final String IP = "localhost"; 
	private static Certificado cert;
	private EscritorIndicadores indicador;

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

				if ( inputLine.startsWith("INICIO") ) {
//					outputLine = "ACT1";
//					pOut.println(outputLine);
					
//					byte[] act1B = inputLine.getBytes();

//					byte[] act1Cifrado = Seguridad.aE(act1B, cert.getOwnPublicKey(), "RSA");
					
					String llaveSimetrica = inputLine.split(":")[1];
					byte[] bytesCifrados = DatatypeConverter.parseHexBinary(llaveSimetrica);
					byte[] bytesLS = Cifrado.descifrar(bytesCifrados, cert.getOwnPrivateKey(), "RSA");
					SecretKey secretKey = new SecretKeySpec(bytesLS, 0, bytesLS.length, "RSA");
					cert.setLlaveSimetrica(secretKey);
					estado++;
				}else {
					outputLine = "ERROR-EsperabaCifradoValido";	
					pOut.println(outputLine);
					estado = 0;
				}
				break;
			case 6:
				inputLine = pIn.readLine();	

				if ( inputLine.startsWith("ACT1") ) {
					outputLine = "ACT2";
					pOut.println(outputLine);
					
					String[] in = inputLine.split(":");
					
					byte[] act2B = Transformacion.toByteArray(in[1]);
					byte[] act2Descifrado = Cifrado.descifrarLS(cert.getLlaveSimetrica(), act2B);
					byte[] act2Hash = Cifrado.getKeyedDigest(act2Descifrado, cert.getLlaveSimetrica());
					String cifrado2String = new String(act2Hash);
					
					String transformacion = new String(Hex.decode(cifrado2String));
					
					outputLine = "ACT2:" + transformacion;
					pOut.println(outputLine);
					estado++;
				}else {
					outputLine = "ERROR-EsperabaActividadValida";	
					pOut.println(outputLine);
					estado = 0;
				}
				break;
			case 7:
				inputLine = pIn.readLine();
				String[] input = inputLine.split(":");
				byte[] hexInput2 = Transformacion.toByteArray(input[1]);
				byte[] resHashLS = Cifrado.descifrarLS(cert.getLlaveSimetrica(), hexInput2);
				byte[] hashCalculado = Cifrado.getKeyedDigest(resHashLS, cert.getLlaveSimetrica());
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
	
	public void ejecutar() {
//		cert = new Certificado();
//		medidor = new EscritorIndicadores();
//		Socket socket = null;
//		PrintWriter escritor = null;
//		BufferedReader lector = null;
//		try {
//			socket = new Socket();
//			socket.connect(new InetSocketAddress(IP, 9200),50000000);
//			escritor = new PrintWriter(socket.getOutputStream(), true);
//			lector = new BufferedReader(new InputStreamReader(
//					socket.getInputStream()));
//		} catch (Exception e) {
//			System.err.println("Exception: " + e.getMessage());
//			System.exit(1);
//		}
//		BufferedReader stdIn = new BufferedReader(
//				new InputStreamReader(System.in));
//		try
//		{
//			comenzar(lector, escritor, socket, socket.getOutputStream());
//		}
//		catch (Exception e)
//		{
//			e.printStackTrace();
//		}
//		finally {
//			try {
//				escritor.close();
//				lector.close();
//				stdIn.close();
//				// cierre el socket y la entrada estándar
//				socket.close();
//			} catch (IOException e) {
//				e.printStackTrace();
//			}
//		}
	}
}
