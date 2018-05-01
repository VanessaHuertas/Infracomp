package util;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class Converter 
{

	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	
	public static byte[] hexStringToByteArray(String s) {
		long len = s.length();
		byte[] data = new byte[(int)len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
					+ Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}

	public static int byteArrayToInteger(byte[] array)
	{
		int value = 0;
		for (int i = 0; i < array.length; i++)
		{
			value += ((int) array[i] & 0xffL) << (8 * i);
		}
		return value;
	}
	
	public static byte[] integerToBytes(int x) 
	{
	    ByteBuffer buffer = ByteBuffer.allocate(Integer.SIZE);
	    buffer.putInt(x);
	    return buffer.array();
	}
	
	public static String stringToHex(String arg) 
	{
	    return String.format("%040x", new BigInteger(1, arg.getBytes(/*YOUR_CHARSET?*/)));
	}
	
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}
}
