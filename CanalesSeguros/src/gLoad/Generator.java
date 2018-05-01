package gLoad;



import java.util.concurrent.atomic.AtomicInteger;

import uniandes.gload.core.LoadGenerator;
import uniandes.gload.core.Task;

public class Generator {
	
	private LoadGenerator generator;
	public static AtomicInteger ai;
	
	public Generator(){
		ai = new AtomicInteger();
		Task tarea = crearTarea();
		int numeroTareas = 400;
		int brechaEntreTareas = 20; //milisegundos
		generator = new LoadGenerator("Prueba de carga Cliente-Servidor", numeroTareas, (uniandes.gload.core.Task) tarea, brechaEntreTareas);
		generator.generate();
	}
	
	private Task crearTarea(){
		return new ClientServerTask();
	}
	
	public static void main (String[]args){
		@SuppressWarnings("unused")
		Generator g = new Generator();
	}

}
