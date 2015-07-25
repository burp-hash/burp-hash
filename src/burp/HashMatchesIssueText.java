package burp;

/**
 * Generates text used in creating Burp Scanner issues.
 */
public class HashMatchesIssueText 
{
	public String Name, Details, Severity, Confidence, RemediationDetails, Background, RemediationBackground;

	public HashMatchesIssueText(HashRecord hash, String plainTextValue)
	{
		Severity = "High";
		Name = hash.algorithm + " Hash Match";
		String source = SearchType.RESPONSE.toString();
		if (hash.searchType.equals(SearchType.REQUEST))
		{
			source = "request";
		}
		Details = "The " + source + " contains a <b>" + hash.algorithm + "</b> hashed value that matches an observed parameter\n" 
				+ plainTextValue + " becomes " + hash.getNormalizedRecord() + " when hashed.";
		Confidence = "Firm";
		RemediationDetails = "SALT YO' HASHES, FOOL!";
		RemediationBackground = "This was found by the " + BurpExtender.extensionName + 
				" extension: <a href=\"" + BurpExtender.extensionUrl + "\">" + BurpExtender.extensionUrl + "</a>";	
	}	
}