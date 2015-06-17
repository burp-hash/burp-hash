package burp;

import java.io.PrintWriter;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
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

		// build algorithm table keyed on hexdigest length
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

		// register with Burp as a scanner
		callbacks.registerScannerCheck(this);
	}

	// doActiveScan is required but not used
	@Override
	public List<IScanIssue> doActiveScan(
			IHttpRequestResponse baseRequestResponse,
			IScannerInsertionPoint insertionPoint) {
		return null;
	}
	
	public boolean isHash(String s)
	{
		//stdOut.println("isHash(" + s + ");");
		if (s.equals("tim"))
		{
			stdOut.println("HASH");
			return true;
		}
		else
		{
			//stdOut.println("FALSE");
			return false;
		}
	}
	
	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		// TODO: implement method - this is where the real action begins
		// report the issue
        List<IScanIssue> issues = new ArrayList<>();
		List<Item> items = new ArrayList<>();
		IRequestInfo req = this.helpers.analyzeRequest(baseRequestResponse);
		List<IParameter> params = req.getParameters();
		for (IParameter param : params) {
			//stdOut.println("param: " + param.getValue());
			if (isHash(param.getValue()))
			{
				Issue issue = new Issue(
	                    baseRequestResponse.getHttpService(),
	                    helpers.analyzeRequest(baseRequestResponse).getUrl(), 	
	                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, null) }, 
	                    HashIssueText.Name,
	                    HashIssueText.getDetails(param.getValue()),
	                    HashIssueText.Severity,
	                    HashIssueText.Confidence,
	                    HashIssueText.RemediationDetails,
	                    HashIssueText.Background,
	                    HashIssueText.RemediationBackground);
				issues.add(issue);
				items.add(new Item(param));
			}
		}
		IResponseInfo resp = this.helpers.analyzeResponse(baseRequestResponse
				.getResponse());
		List<ICookie> cookies = resp.getCookies();
		for (ICookie cookie : cookies) {
			items.add(new Item(cookie));
		}
		// this.stdOut.println("Items stored: " + items.size());
		stdOut.println("Issues collected: " + issues.size());
		for (IScanIssue issue : issues) {
			stdOut.println("Issue URL: " + issue.getIssueName() + " " + issue.getUrl());
		}
		return issues;
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		return 0; //TODO: for now, no consolidation
		/*if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()) {
			return -1; // discard new issue
		} else {
			return 0; // use both issues
		}*/
	}

	private Object[] generateHashes() {
		// TODO: only generate hashes that are enabled in config
		return null;
	}
}

class HashIssueText {
	public static final String Name = "Hash Discovered";
	public static final String getDetails (String param)
	{
		return "The server response contains what appears to be a hashed value: " + param + ".";
	}
	public static final String Severity = "Information";
	public static final String Confidence = "Tentative";
	public static final String RemediationDetails = "TBD";
	public static final String Background = "TBD";
	public static final String RemediationBackground = "TBD";
}
