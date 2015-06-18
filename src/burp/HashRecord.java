package burp;

import java.util.ArrayList;
import java.util.List;
import java.util.Base64;

public class HashRecord
{
	boolean found = false;
	List<int[]> markers = new ArrayList<int[]>();
	String record = "";
	HashAlgorithmName algorithm;
	EncodingType encodingType;

	public String getNormalizedRecord() //TODO: normalize h:e:x, 0xFF
	{
		if (encodingType.equals(EncodingType.Base64))
		{
			return Utilities.byteArrayToHex(Base64.getDecoder().decode(record)).toLowerCase();
		}
		return record.toLowerCase(); 
	}
	
	public String toString()
	{
		if (!encodingType.equals(EncodingType.Hex))
		{
			return algorithm + " Hash " + record + " (" + getNormalizedRecord() + ")";
		}
		return algorithm + " Hash " + record;
	}
}