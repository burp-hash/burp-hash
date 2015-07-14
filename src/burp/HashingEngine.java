package burp;

import java.security.*;

//Use these to generate hashes for observed parameters.
//not sure that strings are the best? What do we consider normalized?
public class HashingEngine {
	public String returnHash (HashAlgorithmName n, String inValue) {
		String hAlgo = n.getValue();
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