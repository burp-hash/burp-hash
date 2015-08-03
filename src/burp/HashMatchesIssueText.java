package burp;

/**
 * Generates text used in creating Burp Scanner issues.
 */
class HashMatchesIssueText
{
	String Name, Details, Severity, Confidence, RemediationDetails, Background, RemediationBackground;

	HashMatchesIssueText(HashRecord hash, String plainTextValue)
	{
		Severity = "High";
		Name = hash.algorithm.name.text + " Hash Match";
		String source = SearchType.RESPONSE.toString();
		if (hash.searchType.equals(SearchType.REQUEST))
		{
			source = SearchType.REQUEST.toString();
		}
		Details = "The " + source + " contains a <b>" + hash.algorithm.name.text + "</b> hashed value that matches an observed parameter.<br><br>\n" 
				+ "Observed hash: <b>" + hash.getNormalizedRecord() + "</b><br>"
				+ "Source parameter: <b>" + plainTextValue + "</b><br>";
		Confidence = "Firm";
		RemediationDetails = "Only use salted or keyed hashes for high security operations.";
		RemediationBackground = "This was found by the " + BurpExtender.extensionName + 
				" extension: <a href=\"" + BurpExtender.extensionUrl + "\">" + BurpExtender.extensionUrl + "</a>";	
	}	
}