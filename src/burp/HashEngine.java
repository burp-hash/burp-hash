package burp;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Generates hashes in one place.
 */

public class HashEngine
{
	public static String Hash(String value, HashAlgorithmName algorithm) throws NoSuchAlgorithmException
	{
		if (value == null) throw new IllegalArgumentException ("Parameter 'value' cannot be null.");
		if (algorithm == null) throw new IllegalArgumentException ("Parameter 'algorithm' cannot be null");
		MessageDigest md = MessageDigest.getInstance(algorithm.getValue());
		byte[] digest = md.digest(value.getBytes(StandardCharsets.UTF_8));
		return Utilities.byteArrayToHex(digest);
	}
}