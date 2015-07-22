package burp;

/**
 * Stores the hash of a {@link Parameter} along with the name of the hashing algorithm.
 */
public class ParameterHash
{
	public HashAlgorithmName algorithm;
	public String hashedValue = "";
}