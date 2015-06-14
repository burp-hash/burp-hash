package burp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.Serializable;
import java.net.URL;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, IScannerCheck {

	private static final String extensionName = "burp-hash";
	private static Map<String, String> hashdb = new ConcurrentHashMap<>();
	private static Map<Integer, List<String>> algos = new ConcurrentHashMap<>();
	private static Map<Integer, Pattern> regex = new ConcurrentHashMap<>();
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private PrintWriter stdErr;
	private PrintWriter stdOut;
	private Config config;

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks c) {
		callbacks = c;
		helpers = callbacks.getHelpers();
		stdErr = new PrintWriter(callbacks.getStderr(), true);
		stdOut = new PrintWriter(callbacks.getStdout(), true);

		// set extension name in burp
		callbacks.setExtensionName(extensionName);

		// load configuration
		try {
			config = Config.load(callbacks);
		} catch (Exception e) {
			stdErr.println("Error loading config: " + e.getMessage());
			e.printStackTrace(stdErr);
		}

		// build algorithm table
		if (algos == null) {
			algos.putIfAbsent(32, Arrays.asList("MD5"));
			algos.putIfAbsent(40, Arrays.asList("SHA"));
			algos.putIfAbsent(56, Arrays.asList("SHA-224"));
			algos.putIfAbsent(64, Arrays.asList("SHA-256"));
			algos.putIfAbsent(96, Arrays.asList("SHA-384"));
			algos.putIfAbsent(128, Arrays.asList("SHA-512"));
		}
		// build regex list
		if (regex == null) {
			Iterator<Integer> i = algos.keySet().iterator();
			while (i.hasNext()) {
				int n = i.next();
				regex.putIfAbsent(n,
						Pattern.compile(String.format("[0-9a-fA-F]{%s}", n)));
			}
		}

		callbacks.registerScannerCheck(this);
	}

	// doActiveScan is required but not used
	@Override
	public List<IScanIssue> doActiveScan(
			IHttpRequestResponse baseRequestResponse,
			IScannerInsertionPoint insertionPoint) {
		return null;
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

}

/**
 * Manages settings for the extension.
 */
class Config implements Serializable {
	private static final long serialVersionUID = 1L;
	private transient IBurpExtenderCallbacks callbacks;
	private transient PrintWriter stdErr;
	private transient PrintWriter stdOut;
	public boolean isMd5Enabled = true;
	public boolean isSha1Enabled = true;
	public boolean isSha224Enabled = false;
	public boolean isSha256Enabled = true;
	public boolean isSha384Enabled = false;
	public boolean isSha512Enabled = false;

	private Config(IBurpExtenderCallbacks c) {
		callbacks = c;
		stdErr = new PrintWriter(c.getStderr(), true);
		stdOut = new PrintWriter(c.getStdout(), true);
		stdOut.println("No saved settings found — using defaults.");
	}

	public static Config load(IBurpExtenderCallbacks c) throws Exception {
		String encodedConfig = c.loadExtensionSetting("burp-hash");
		if (encodedConfig == null) {
			return new Config(c);
		}
		byte[] decodedConfig = Base64.getDecoder().decode(encodedConfig);
		ByteArrayInputStream b = new ByteArrayInputStream(decodedConfig);
		ObjectInputStream in = new ObjectInputStream(b);
		Config cfg = (Config) in.readObject();
		cfg.callbacks = c;
		cfg.stdErr = new PrintWriter(c.getStderr(), true);
		cfg.stdOut = new PrintWriter(c.getStdout(), true);
		cfg.stdOut.println("Successfully loaded settings.");
		return cfg;
	}

	public void save() throws Exception {
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		ObjectOutputStream out = new ObjectOutputStream(b);
		out.writeObject(this);
		String encoded = Base64.getEncoder().encodeToString(b.toByteArray());
		callbacks.saveExtensionSetting("burp-hash", encoded);
		stdOut.println("Successfully saved settings.");
	}
}
