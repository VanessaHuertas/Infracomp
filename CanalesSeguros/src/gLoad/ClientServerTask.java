package gLoad;

import canalesSeguros.Cliente;
import uniandes.gload.core.Task;

public class ClientServerTask extends Task {


	public void fail() {
		System.out.println(Task.MENSAJE_FAIL);
	}


	public void success() {
		System.out.println(Task.OK_MESSAGE);
	}

	@Override
	public void execute() {
		Cliente client = new Cliente();
		client.ejecutar();
	}
}
