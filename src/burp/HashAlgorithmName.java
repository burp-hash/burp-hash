package burp;

/**
 * HashAlgorithmName.SHA_256.getValue() == SHA-256<br/>
 * HashAlgorithmName.SHA_256.toString() == SHA_256<p>
 * 
 * HashAlgorithmName han = HashAlgorithmName.SHA_1;<br/>
 * MessageDigest md = MessageDigest.getInstance(han.getValue()); 
 */
public enum HashAlgorithmName {
	MD5("MD5"), SHA_1("SHA-1"), SHA_224("SHA-224"), SHA_256("SHA-256"), SHA_384("SHA-384"), SHA_512("SHA-512");

	public static HashAlgorithmName getName(String text) {
		return valueOf(text.replaceAll("-", "_").toUpperCase());
	}

	public final String text;

	private HashAlgorithmName(String text) {
		this.text = text;
	}

	public String getValue() {
		return text;
	}
};
