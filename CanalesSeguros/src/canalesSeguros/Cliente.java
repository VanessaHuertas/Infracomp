package canalesSeguros;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import mediciones.EscritorIndicadores;
import seguridad.Certificado;
import seguridad.Cifrado;

public class Cliente{

	private static final String IP = "localhost"; 
	private static Certificado cert;
	private EscritorIndicadores indicador;

	public void comenzar(BufferedReader pIn, PrintWriter pOut, Socket socket, OutputStream oS) throws Exception 
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
				indicador.startAutServidor();
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
				indicador.finishAutServidor();
				if ( inputLine.startsWith("INICIO") ) {

					String llaveSimetrica = inputLine.split(":")[1];
					byte[] bytesCifrados = DatatypeConverter.parseHexBinary(llaveSimetrica);
					byte[] bytesLS = Cifrado.descifrar(bytesCifrados, cert.getOwnPrivateKey(), "RSA");
					SecretKey secretKey = new SecretKeySpec(bytesLS, "AES");
					cert.setLlaveSimetrica(secretKey);
					estado++;
				}else {
					outputLine = "ERROR-EsperabaCifradoValido";	
					pOut.println(outputLine);
					estado = 0;
				}
				
				break;
			case 6:
				String coors1 = "41 24.2028, 2 10.4418";
				byte[] bytesEncCoors1 = Cifrado.cifrarLS(cert.getLlaveSimetrica(), coors1.getBytes());
				String hexCoors1 = DatatypeConverter.printHexBinary(bytesEncCoors1);
				outputLine = "ACT1:" + new String(hexCoors1);
				indicador.startAutCliente();
				pOut.println(outputLine);
				estado++;
				indicador.startRespuesta();
				break;
			case 7:
				String coors2 = "41 24.2028, 2 10.4418";
				byte[] bytesEncCoors2 = Cifrado.getKeyedDigest(coors2.getBytes(), cert.getLlaveSimetrica());
				byte[] act2Asm = Cifrado.cifrar(cert.getServerPublicKey(), bytesEncCoors2, "RSA");
				String hexCoors2 = DatatypeConverter.printHexBinary(act2Asm);
				outputLine = "ACT2:" + new String(hexCoors2);
				pOut.println(outputLine);
				estado++;
				System.out.println("El protocolo termina de manera correcta.");
				finalizo = true;
				indicador.finishAutCliente();				
				indicador.finishRespuesta();
				break;
			default:
				outputLine = "ERROR";
				estado = 0;
				pOut.println(outputLine);
				break;
			}
		}

		if(finalizo != true)
		{
			indicador.registrarFallo();
		}
		indicador.imprimirResultado();
	}

	public void ejecutar() {
		cert = new Certificado();
		indicador = new EscritorIndicadores();
		Socket socket = null;
		PrintWriter escritor = null;
		BufferedReader lector = null;
		try {
			socket = new Socket();
			socket.connect(new InetSocketAddress(IP, 8084),50000000);
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
		finally 
		{
			try {
				escritor.close();
				lector.close();
				stdIn.close();
				// cierre el socket y la entrada est�ndar
				socket.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
}
