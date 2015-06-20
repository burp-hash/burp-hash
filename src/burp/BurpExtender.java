package burp;

import java.io.PrintWriter;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Base64;
import java.net.URLDecoder;
import java.util.EnumSet;

public class BurpExtender implements IBurpExtender, IScannerCheck 
{
	public static final String extensionName = "burp-hash";
	public static final String extensionUrl = "https://burp-hash.github.io/";
	private static Map<String, String> hashdb = new ConcurrentHashMap<>();
	private static List<HashAlgorithm> hashAlgorithms = new ArrayList<HashAlgorithm>();
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private PrintWriter stdErr;
	private PrintWriter stdOut;
	private Config config;
	public Pattern b64 = Pattern.compile("[a-zA-Z0-9+/%]+={0,2}"); //added % for URL encoded B64
	//TODO: Use this to determine which hash algos to use on params for hash guessing:
	public static EnumSet<HashAlgorithmName> hashTracker = EnumSet.noneOf(HashAlgorithmName.class); 

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
		if(config.isSha512Enabled) hashAlgorithms.add(new HashAlgorithm(128, HashAlgorithmName.SHA512));
		if(config.isSha384Enabled) hashAlgorithms.add(new HashAlgorithm(96, HashAlgorithmName.SHA384));
		if(config.isSha256Enabled) hashAlgorithms.add(new HashAlgorithm(64, HashAlgorithmName.SHA256));
		if(config.isSha224Enabled) hashAlgorithms.add(new HashAlgorithm(56, HashAlgorithmName.SHA224));
		if(config.isSha1Enabled) hashAlgorithms.add(new HashAlgorithm(40, HashAlgorithmName.SHA1));
		if(config.isMd5Enabled) hashAlgorithms.add(new HashAlgorithm(32, HashAlgorithmName.MD5));
	}

	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
	{
		return null; // doActiveScan is required but not used
	}
	
	private List<HashRecord> FindRegex(String s, Pattern pattern, HashAlgorithmName algorithm)
	{
		//TODO: Regex will flag on longer hex values - fix this.
		//TODO: Add support for f0:a3:cd style encoding
		//TODO: Add support for 0xFF style encoding
		List<HashRecord> hashes = new ArrayList<HashRecord>();
		Matcher matcher = pattern.matcher(s);
		while (matcher.find())
		{
			HashRecord hash = new HashRecord();
			hash.found = true;
			hash.markers.add(new int[] { matcher.start(), matcher.end() });
			hash.record = matcher.group();
			hash.algorithm = algorithm;
			hash.encodingType = EncodingType.Hex;
			hashes.add(hash);
			hashTracker.add(algorithm);
		}
		Matcher b64matcher = b64.matcher(s);
		while (b64matcher.find())
		{
			String urldecoded = b64matcher.group();
			try
			{
				urldecoded = URLDecoder.decode(b64matcher.group(), "UTF-8");
			}
			catch (java.io.UnsupportedEncodingException uee) { }

			try
			{
				//sadly, the base64 regex by itself is ineffective (false positives)
				//so we need to try to decode and catch exceptions instead
				String b64decoded = Utilities.byteArrayToHex(Base64.getDecoder().decode(urldecoded));
				matcher = pattern.matcher(b64decoded);
				if (matcher.matches())
				{
					stdOut.println("Base64 Match: " + urldecoded + " <<" + b64decoded + ">>");
					HashRecord hash = new HashRecord();
					hash.found = true;
					hash.markers.add(new int[] { b64matcher.start(), b64matcher.end() }); 
					hash.record = urldecoded;
					hash.algorithm = algorithm;
					hash.encodingType = EncodingType.Base64;
					hashes.add(hash);
					hashTracker.add(algorithm);
				}
			}
			catch (IllegalArgumentException iae)
			{ }
		}

		return hashes;
	}
		
	private List<Issue> FindHashes(String s, IHttpRequestResponse baseRequestResponse, SearchType searchType)
	{
		List<HashRecord> hashes = new ArrayList<HashRecord>();
		for(HashAlgorithm hashAlgorithm : hashAlgorithms)
		{
			List<HashRecord> results = FindRegex(s, hashAlgorithm.pattern, hashAlgorithm.name);
			for(HashRecord result : results)
			{
				if (result.found)
				{
					boolean found = false;
					for (HashRecord hash : hashes)
					{
						if (hash.getNormalizedRecord().contains(result.getNormalizedRecord()) &&
								!hash.getNormalizedRecord().equals(result.getNormalizedRecord()))
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
		}
		SaveHashes(hashes);
		return CreateHashDiscoveredIssues(hashes, baseRequestResponse, searchType);
	}
	
	private void SaveHashes(List<HashRecord> hashes)
	{
		//TODO: Persist hashes
	}
	
	private List<Issue> CreateHashDiscoveredIssues(List<HashRecord> hashes, IHttpRequestResponse baseRequestResponse, SearchType searchType)
	{
		List<Issue> issues = new ArrayList<>();
		for(HashRecord hash : hashes)
		{
			IHttpRequestResponse[] message;
			if (searchType.equals(SearchType.REQUEST))
			{ //apply markers to the request
				message = new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, hash.markers, null) };
			}
			else
			{ //apply markers to the response
				message = new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, hash.markers) };
			}
			HashDiscoveredIssueText issueText = new HashDiscoveredIssueText(hash, searchType);
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
			for (IParameter param : params)
			{
				items.add(new Item(param));
			}
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
