package burp;

import java.net.URL;

/**
 * Implementation of the IScanIssue interface.
 */
class Issue implements IScanIssue {
	private IHttpService httpService;
	private URL url;
	private IHttpRequestResponse[] httpMessages;
	private String issueName;
	private String issueDetail;
	private String severity;
	private String confidence;
	private String remediationDetail;
	private String issueBackground;
	private String remediationBackground;

	// TODO: finish constructor and remove all null returns
	public Issue(IHttpService httpService, URL url,
			IHttpRequestResponse[] httpMessages, String issueName,
			String issueDetail, String severity, String confidence,
			String remediationDetail, String issueBackground,
			String remediationBackground) {
		this.httpService = httpService;
		this.url = url;
		this.httpMessages = httpMessages;
		this.issueName = issueName;
		this.issueDetail = issueDetail;
		this.severity = severity;
		this.confidence = confidence;
		this.remediationDetail = remediationDetail;
		this.issueBackground = issueBackground;
		this.remediationBackground = remediationBackground;
	}

	@Override
	public URL getUrl() {
		return this.url;
	}

	@Override
	public String getIssueName() {
		return this.issueName;
	}

	@Override
	public int getIssueType() {
		return 134217728; // type is always "extension generated"
	}

	@Override
	public String getSeverity() {
		return this.severity;
	}

	@Override
	public String getConfidence() {
		return this.confidence;
	}

	@Override
	public String getIssueBackground() {
		return this.issueBackground;
	}

	@Override
	public String getRemediationBackground() {
		return this.remediationBackground;
	}

	@Override
	public String getIssueDetail() {
		return this.issueDetail;
	}

	@Override
	public String getRemediationDetail() {
		return this.remediationDetail;
	}

	@Override
	public IHttpRequestResponse[] getHttpMessages() {
		return this.httpMessages;
	}

	@Override
	public IHttpService getHttpService() {
		return this.httpService;
	}
	
	public String toString()
	{
		return "Name: " + this.issueName + " URL: " + this.url + " Severity: " + this.severity + " Confidence: " 
				+ this.confidence + " Detail: " + this.issueDetail + " Remediation: " + this.remediationDetail 
				+ " Background: " + this.issueBackground + " Remediation Background: " + this.remediationBackground;
	}

}
