package burp;

import java.util.ArrayList;
import java.util.List;
import java.util.Base64;

/**
 * Stores found strings that appear to be hashes.
 */
class HashRecord
{
	List<int[]> markers = new ArrayList<>();
	String record = "";
	HashAlgorithmName algorithm;
	EncodingType encodingType;
	SearchType searchType;

	String getNormalizedRecord() //TODO: normalize h:e:x, 0xFF
	{
		if (encodingType.equals(EncodingType.Base64))
		{
			return Utilities.byteArrayToHex(Base64.getDecoder().decode(record)).toLowerCase();
		}
		return record.toLowerCase(); 
	}
	
	@Override
	public String toString()
	{
		if (!encodingType.equals(EncodingType.Hex))
		{
			return algorithm + " Hash " + record + " (" + getNormalizedRecord() + ")";
		}
		return algorithm + " Hash " + record;
	}
	
	void sortMarkers()
	{
		List<int[]> sorted = new ArrayList<>();
		int[] previous = { -1, -1 };
		for (int[] marker : markers)
		{
			boolean unique = true;
			for(int[] m : sorted)
			{
				if (m[0] == marker[0] && m[1] == marker[1])
				{
					unique = false;
					break;
				}
			}
			if(unique)
			{
				sorted.add(marker);
			}
		}
		markers = sorted;
	}
}