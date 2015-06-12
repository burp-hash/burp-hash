package burp;

import java.net.URL;
import java.security.MessageDigest;
import java.util.Date;
import java.util.List;

public class BurpExtender implements IBurpExtender, IScannerCheck {

	public static final String EXTENSION_NAME = "burp-hash";
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();

		callbacks.setExtensionName(EXTENSION_NAME);
		callbacks.registerScannerCheck(this);
	}

	@Override
	public List<IScanIssue> doActiveScan(
			IHttpRequestResponse baseRequestResponse,
			IScannerInsertionPoint insertionPoint) {
		return null; // no active scans
	}

	@Override
	public List<IScanIssue> doPassiveScan(
			IHttpRequestResponse baseRequestResponse) {
		// TODO: implement method - this is where the real action begins
		return null;
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue,
			IScanIssue newIssue) {
		if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()) {
			return -1; // discard new issue
		} else {
			return 0; // use both issues
		}
	}

	private Object[] generateHashes() {
		// TODO: only generate hashes that are enabled in config
		return null;
	}
}

/**
 * This implementation of ICookie and IParameter is used to homogenize the two
 * object types during processing.
 *
 * @author sjohnson
 *
 */
class Item implements ICookie, IParameter {
	// TODO: add a constructor and remove null and -1 returns
	public static final int COOKIE = 1;
	public static final int PARAMETER = 0;

	public Object getItem() {
		return null;
	}

	public int getItemType() {
		return -1;
	}

	// Methods common to both interfaces
	@Override
	public String getName() {
		return null;
	}

	@Override
	public String getValue() {
		return null;
	}

	// ICookie methods
	@Override
	public String getDomain() {
		return null;
	}

	@Override
	public Date getExpiration() {
		return null;
	}

	// IParameter methods
	@Override
	public byte getType() {
		return -1;
	}

	@Override
	public int getNameStart() {
		return -1;
	}

	@Override
	public int getNameEnd() {
		return -1;
	}

	@Override
	public int getValueStart() {
		return -1;
	}

	@Override
	public int getValueEnd() {
		return -1;
	}
}

/**
 * Impementation of the IScanIssue interface.
 *
 * @author sjohnson
 *
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

}
