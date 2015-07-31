package burp;

/**
 * Stores the hash of a {@link Parameter} along with its {@HashAlgorithmName}.
 */
class ParameterWithHash
{
	Parameter parameter;
	HashAlgorithmName algorithm;
	String hashedValue = "";
}