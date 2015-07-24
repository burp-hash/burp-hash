package burp;

/**
 * Generates text used in creating Burp Scanner issues.
 */
public class HashDiscoveredIssueText 
{
	public String Name, Details, Severity, Confidence, RemediationDetails, Background, RemediationBackground;

	public HashDiscoveredIssueText(HashRecord hash)
	{
		Name = hash.algorithm + " Hash Discovered";
		String source = SearchType.RESPONSE.toString();
		if (hash.searchType.equals(SearchType.REQUEST))
		{
			source = "request";
		}
		Details = "The " + source + " contains what appears to be a <b>" + hash.algorithm + "</b> hashed value:\n<ul><li>" + hash.getNormalizedRecord() + "</li></ul>";
		if (!hash.encodingType.equals(EncodingType.Hex))
		{
			Details += "<br>The hash was discovered encoded as:\n<ul><li>" + hash.record + "</li></ul>";
		}
		Confidence = "Tentative";
		RemediationBackground = "This was found by the " + BurpExtender.extensionName + 
				" extension: <a href=\"" + BurpExtender.extensionUrl + "\">" + BurpExtender.extensionUrl + "</a>";
		if (hash.algorithm.equals(HashAlgorithmName.MD5) || hash.algorithm.equals(HashAlgorithmName.SHA_1))
		{
			Severity = "Medium";
			if (hash.algorithm.equals(HashAlgorithmName.MD5))
			{
				Severity = "Medium";
			}
			RemediationDetails = "Consider upgrading to a stronger cryptographic hash algorithm, such as SHA-256.";
			Background = "This cryptographic algorithm is considered to be weak and should be phased out.\n\n" +
					"The presence of a cryptographic hash may be of interest to a penetration tester.  " +
					"This may assist the tester in locating vectors to bypass access controls.";
		}
		else
		{
			Severity = "Information";
			RemediationDetails = "No remediation may be necessary. This is purely informational.";
			Background = "The presence of a cryptographic hash may be of interest to a penetration tester.  " +
					"This may assist the tester in locating vectors to bypass access controls.";
		}
		
	}	
}