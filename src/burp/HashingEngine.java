package burp;

import java.security.*;
import java.util.Base64;

//nevermind, I think this is already built in BurpExtender
//Use these to generate hashes for observed parameters.
//normalized Utilities.byteArrayToHex(Base64.getDecoder().decode(record)).toLowerCase();

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