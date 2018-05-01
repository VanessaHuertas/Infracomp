package mediciones;

import java.io.IOException;
import java.io.PrintWriter;

import gLoad.Generator;

public class EscritorIndicadores 
{
	private long autServidor;
	private long autCliente;
	private long respuesta;
	private boolean fallo;
	
	public EscritorIndicadores()
	{
		fallo = false;
		autServidor = 0;
		autCliente = 0;
		respuesta = 0;
	}
	
	public void startAutServidor()
	{
		autServidor = System.nanoTime();
	}
	
	public void finishAutServidor()
	{
		autServidor = System.nanoTime() - autServidor;
	}
	
	public void startAutCliente()
	{
		autCliente = System.nanoTime();
	}
	
	public void finishAutCliente()
	{
		autCliente = System.nanoTime() - autCliente;
	}
	
	public void startRespuesta()
	{
		respuesta = System.nanoTime();
	}
	
	public void finishRespuesta()
	{
		respuesta = System.nanoTime() - respuesta;
	}
	
	public void registrarFallo()
	{
		fallo = true;
	}
	
	public void imprimirResultado()
	{
		try{
		    PrintWriter writer = new PrintWriter("datos/resultado_0"+Generator.ai.getAndIncrement()+".txt", "UTF-8");
		    writer.println(autServidor+":"+autCliente+":"+respuesta);
		    String error = fallo? "Fallido":"Correcto";
		    writer.println(error);
		    writer.close();
		} catch (IOException e) {
		   // do something
		}
	}
}
