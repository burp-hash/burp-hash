package burp;

import java.security.*;

//Use these to generate hashes for observed parameters.
//not sure that strings are the best? What do we consider normalized?
public class HashingEngine {
	public String returnHash (HashAlgorithmName n, String inValue) {
		
		//Can't thinkg of a better way to transform these to the format that
		//Messagedigest wants
		String hAlgo = n.toString();
		if (hAlgo == "SHA512") hAlgo = "SHA-512";
		if (hAlgo == "SHA1") hAlgo = "SHA-1";
		if (hAlgo == "SHA224") hAlgo = "SHA-224";
		if (hAlgo == "SHA256") hAlgo = "SHA-256";		
		if (hAlgo == "SHA384") hAlgo = "SHA-384";
		try {
				MessageDigest md = MessageDigest.getInstance(hAlgo);
		        md.update(inValue.getBytes());
		        byte byteData[] = md.digest();
		        //convert the byte to hex format method 1
		        StringBuffer sb = new StringBuffer();
		        for (int i = 0; i < byteData.length; i++) {
		            sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
		           }
				return sb.toString();
			} catch (NoSuchAlgorithmException e) {
				System.err.println("I'm sorry, but "+hAlgo+" is not a valid message digest algorithm");
			}
		return null;
	}
}