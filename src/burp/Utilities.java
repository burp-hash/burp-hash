package burp;

public class Utilities
{
	public static String byteArrayToHex(byte[] bytes) 
	{
		   StringBuilder sb = new StringBuilder(bytes.length * 2);
		   for(byte b: bytes)
		      sb.append(String.format("%02x", b & 0xff));
		   return sb.toString();
	}
}