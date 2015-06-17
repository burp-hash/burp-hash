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
	public static final String extensionName = "burp-hash";
	private static Map<String, String> hashdb = new ConcurrentHashMap<>();
	private static List<HashAlgorithm> hashAlgorithms = new ArrayList<HashAlgorithm>();
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private PrintWriter stdErr;
	private PrintWriter stdOut;
	private Config config;
	public enum SearchType { REQUEST, RESPONSE };

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks c) 
	{
		callbacks = c;
		helpers = callbacks.getHelpers();
		stdErr = new PrintWriter(callbacks.getStderr(), true);
		stdOut = new PrintWriter(callbacks.getStdout(), true);
		callbacks.setExtensionName(extensionName);
		callbacks.registerScannerCheck(this); // register with Burp as a scanner
		LoadConfig();
	}
	
	private void LoadConfig()
	{
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
	
	private HashRecord FindRegex(String s, Pattern pattern, String algorithm)
	{
		HashRecord _rec = new HashRecord();
		Matcher matcher = pattern.matcher(s);
		while (matcher.find())
		{
			//stdOut.println("Found: " + matcher.group());
			_rec.found = true;
			_rec.markers.add(new int[] { matcher.start(), matcher.end() });
			_rec.record = matcher.group();
			_rec.algorithm = algorithm;
		}
		return _rec;
	}
		
	private List<Issue> FindHashes(String s, IHttpRequestResponse baseRequestResponse, SearchType searchType)
	{
		List<HashRecord> hashes = new ArrayList<HashRecord>();
		for(HashAlgorithm hashAlgorithm : hashAlgorithms)
		{
			HashRecord result = FindRegex(s, hashAlgorithm.pattern, hashAlgorithm.name);
			if (result.found)
			{
				boolean found = false;
				for (HashRecord hash : hashes)
				{
					if (hash.getNormalizedRecord().contains(result.getNormalizedRecord()))
					{ //to prevent shorter hashes (e.g. MD5) from being identified inside longer hashes (e.g. SHA-256)
						found = true;
						break;
					}
				}
				if (found) continue;
				hashes.add(result);
				stdOut.println("Found " + hashAlgorithm.name + " hash: " + result.record + " URL: " + helpers.analyzeRequest(baseRequestResponse).getUrl());
			}
		}
		//TODO: Persist hashes
		return CreateIssues(hashes, baseRequestResponse, searchType);
	}
	
	private List<Issue> CreateIssues(List<HashRecord> hashes, IHttpRequestResponse baseRequestResponse, SearchType searchType)
	{
		List<Issue> issues = new ArrayList<>();
		for(HashRecord hash : hashes)
		{
			IHttpRequestResponse[] message;
			if (searchType.equals(searchType.REQUEST))
			{ //apply markers to the request
				message = new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, hash.markers, null) };
			}
			else
			{ //apply markers to the response
				message = new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, hash.markers) };
			}
			HashIssueText issueText = new HashIssueText(hash.algorithm, hash.record, searchType);
			Issue issue = new Issue(
	                baseRequestResponse.getHttpService(),
	                helpers.analyzeRequest(baseRequestResponse).getUrl(), 	
	                message, 
	                issueText.Name,
	                issueText.Details,
	                issueText.Severity,
	                issueText.Confidence,
	                issueText.RemediationDetails,
	                issueText.Background,
	                issueText.RemediationBackground);
			issues.add(issue);
		}
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
		if (issues.size() > 0)
		{
			stdOut.println("Added " + issues.size() + " issues.");
		}
		for (IScanIssue issue : issues) 
		{
			stdOut.println("Issue URL: " + issue.getIssueName() + " " + issue.getUrl());
		}
		return issues;
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) 
	{
		if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()) {
			return -1; // discard new issue
		} else {
			return 0; // use both issues
		}
	}

	private Object[] generateHashes() 
	{
		// TODO: only generate hashes that are enabled in config
		return null;
	}
}

class HashIssueText 
{
	public HashIssueText(String algorithm, String param, BurpExtender.SearchType searchType)
	{
		Name = algorithm + " Hash Discovered";
		String source = "server response";
		if (searchType.equals(BurpExtender.SearchType.REQUEST))
		{
			source = "request";
		}
		Details = "The " + source + " contains what appears to be a " + algorithm + " hashed value: " + param + ".";
		Confidence = "Tentative";
		RemediationBackground = "This was found by the " + BurpExtender.extensionName + " extension."; //TODO: add github URL to project in this message
		if (algorithm.equals("MD5") || algorithm.equals("SHA-1"))
		{
			Severity = "Medium";
			if (algorithm.equals("MD5"))
			{
				Severity = "High";
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
	public static String Name, Details, Severity, Confidence, RemediationDetails, Background, RemediationBackground;
}

class HashAlgorithm
{
	public int charWidth;
	public String name;
	public Pattern pattern;
	private static final String hexRegex = "([a-f0-9]{%s})"; 
	//TODO: Regex will flag on longer hex values - fix this.
	//TODO: Add support for Base64 encoding
	//TODO: Add support for f0:a3:cd style encoding
	//TODO: Add support for 0xFF style encoding
	//TODO: validate upper and lower case
	
	public HashAlgorithm(int charWidth, String name)
	{
		this.charWidth = charWidth;
		this.name = name;
		this.pattern = Pattern.compile(String.format(hexRegex, charWidth));
	}
}

class HashRecord
{
	boolean found = false;
	List<int[]> markers = new ArrayList<int[]>();
	String record = "";
	String algorithm = "";
	public String getNormalizedRecord()
	{
		return record.toLowerCase(); //TODO: normalize base64, upper/lower, h:e:x, 0xFF
	}
}