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
import java.util.regex.Matcher;

public class BurpExtender implements IBurpExtender, IScannerCheck 
{
	private static final String extensionName = "burp-hash";
	private static Map<String, String> hashdb = new ConcurrentHashMap<>();
	private static List<HashAlgorithm> hashAlgorithms = new ArrayList<HashAlgorithm>();
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private PrintWriter stdErr;
	private PrintWriter stdOut;
	private Config config;
	private enum SearchType { REQUEST, RESPONSE };

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks c) 
	{
		callbacks = c;
		helpers = callbacks.getHelpers();
		stdErr = new PrintWriter(callbacks.getStderr(), true);
		stdOut = new PrintWriter(callbacks.getStdout(), true);
		callbacks.setExtensionName(extensionName);
		callbacks.registerScannerCheck(this); // register with Burp as a scanner

		try 
		{
			config = Config.load(callbacks); // load configuration
		} 
		catch (Exception e) 
		{
			stdErr.println("Error loading config: " + e.getMessage());
			e.printStackTrace(stdErr);
		}

		//Build in reverse order (largest first) for searching:
		if(config.isSha512Enabled) hashAlgorithms.add(new HashAlgorithm(128, "SHA-512"));
		if(config.isSha384Enabled) hashAlgorithms.add(new HashAlgorithm(96, "SHA-384"));
		if(config.isSha256Enabled) hashAlgorithms.add(new HashAlgorithm(64, "SHA-256"));
		if(config.isSha224Enabled) hashAlgorithms.add(new HashAlgorithm(56, "SHA-224"));
		if(config.isSha1Enabled) hashAlgorithms.add(new HashAlgorithm(40, "SHA-1"));
		if(config.isMd5Enabled) hashAlgorithms.add(new HashAlgorithm(32, "MD5"));
	}

	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
	{
		return null; // doActiveScan is required but not used
	}
		
	private List<Issue> FindHashes(String s, IHttpRequestResponse baseRequestResponse, SearchType searchType)
	{
		List<Issue> issues = new ArrayList<>();
		List<String> hashes = new ArrayList<String>();
		for(HashAlgorithm hashAlgorithm : hashAlgorithms)
		{
			Matcher matcher = hashAlgorithm.pattern.matcher(s);
			while (matcher.find())
			{
				boolean found = false;
				for (String hash : hashes)
				{
					stdOut.println("Old: " + hash + " new: " + matcher.group());
					if (hash.toLowerCase().contains(matcher.group().toLowerCase()))
					{
						stdOut.println("Collision!");
						found = true;
						break;
					}
				}
				if (found) continue;
				hashes.add(matcher.group());
				stdOut.println("Found " + hashAlgorithm.name + " hash: " + matcher.group() + " URL: " + helpers.analyzeRequest(baseRequestResponse).getUrl());
				List<int[]> markers = new ArrayList<int[]>();
				markers.add(new int[] { matcher.start(), matcher.end() });				
				IHttpRequestResponse[] reqres;
				if (searchType.equals(searchType.REQUEST))
				{ //apply markers to the request
					reqres = new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, markers, null) };
				}
				else
				{ //apply markers to the response
					reqres = new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, markers) };
				}
				Issue issue = new Issue(
		                baseRequestResponse.getHttpService(),
		                helpers.analyzeRequest(baseRequestResponse).getUrl(), 	
		                reqres, 
		                HashIssueText.getName(hashAlgorithm.name),
		                HashIssueText.getDetails(hashAlgorithm.name, matcher.group()),
		                HashIssueText.Severity,
		                HashIssueText.Confidence,
		                HashIssueText.RemediationDetails,
		                HashIssueText.Background,
		                HashIssueText.RemediationBackground);
				issues.add(issue);
			}
		}
		//TODO: Persist hashes
		return issues;
	}
	
	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) 
	{
		// TODO: implement method - this is where the real action begins
		List<IScanIssue> issues = new ArrayList<>();
		String request = "", response = "";
		try 
		{
			request = new String(baseRequestResponse.getRequest(), "UTF-8");
			response = new String(baseRequestResponse.getResponse(), "UTF-8");
		}
		catch (Exception ex) {}
		issues.addAll(FindHashes(request, baseRequestResponse, SearchType.REQUEST));
		issues.addAll(FindHashes(response, baseRequestResponse, SearchType.RESPONSE));
		
		if (!config.reportHashesOnly)
		{
			//TODO: This is where we should wire in the logic to check if any params match captured hashes
			List<Item> items = new ArrayList<>();
			IRequestInfo req = this.helpers.analyzeRequest(baseRequestResponse);
			List<IParameter> params = req.getParameters();
			IResponseInfo resp = this.helpers.analyzeResponse(baseRequestResponse.getResponse());
			List<ICookie> cookies = resp.getCookies();
			for (ICookie cookie : cookies) 
			{
				items.add(new Item(cookie));
			}
			// this.stdOut.println("Items stored: " + items.size());
		}
		stdOut.println("Issues collected: " + issues.size());
		for (IScanIssue issue : issues) 
		{
			stdOut.println("Issue URL: " + issue.getIssueName() + " " + issue.getUrl());
		}
		return issues;
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) 
	{
		return 0; //TODO: for now, no consolidation
		/*if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()) {
			return -1; // discard new issue
		} else {
			return 0; // use both issues
		}*/
	}

	private Object[] generateHashes() 
	{
		// TODO: only generate hashes that are enabled in config
		return null;
	}
}

class HashIssueText 
{
	public static final String getName (String algorithm)
	{
		return algorithm + " Hash Discovered";
	}
	public static final String getDetails (String algorithm, String param)
	{
		return "The server response contains what appears to be a " + algorithm + " hashed value: " + param + ".";
	}
	public static final String Severity = "Information";
	public static final String Confidence = "Tentative";
	public static final String RemediationDetails = "TBD";
	public static final String Background = "TBD";
	public static final String RemediationBackground = "TBD";
}

class HashAlgorithm
{
	public int charWidth;
	public String name;
	public Pattern pattern;
	private static final String hexRegex = "([a-f0-9]{%s})";
	
	public HashAlgorithm(int charWidth, String name)
	{
		this.charWidth = charWidth;
		this.name = name;
		this.pattern = Pattern.compile(String.format(hexRegex, charWidth));
	}
}