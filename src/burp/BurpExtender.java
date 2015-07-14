package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, IScannerCheck 
{
	public static final String extensionName = "burp-hash";
	public static final String extensionUrl = "https://burp-hash.github.io/";
	private static List<HashAlgorithm> hashAlgorithms = new ArrayList<>();
	private static Map<String, String> hashdb = new ConcurrentHashMap<>();
	//TODO: Use this to determine which hash algos to use on params for hash guessing:
	public static EnumSet<HashAlgorithmName> hashTracker = EnumSet.noneOf(HashAlgorithmName.class);
	public Pattern b64 = Pattern.compile("[a-zA-Z0-9+/%]+={0,2}"); //added % for URL encoded B64
	private IBurpExtenderCallbacks callbacks;
	private Config config;
	private Database db;
	private GuiTab guiTab;
	private List<HashRecord> hashes = new ArrayList<>();
	private IExtensionHelpers helpers;
	private List<IScanIssue> issues = new ArrayList<>();
	private List<Parameter> parameters = new ArrayList<>();
	private PrintWriter stdErr;
	private PrintWriter stdOut;

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks c) 
	{
		callbacks = c;
		helpers = callbacks.getHelpers();
		stdErr = new PrintWriter(callbacks.getStderr(), true);
		stdOut = new PrintWriter(callbacks.getStdout(), true);

		callbacks.setExtensionName(extensionName);
		callbacks.registerScannerCheck(this); // register with Burp as a scanner

		loadConfig();
		loadDatabase();
		loadGui();
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
	{
		//TODO: determine if we want to remove dupes or not
//		return 0;
		if (existingIssue.getIssueDetail().equals(newIssue.getIssueDetail())) {
			return -1; // discard new issue
		} else {
			return 0; // use both issues
		}
	}

	private void createHashDiscoveredIssues(IHttpRequestResponse baseRequestResponse)
	{
		for(HashRecord hash : hashes)
		{
			IHttpRequestResponse[] message;
			if (hash.searchType.equals(SearchType.REQUEST))
			{ //apply markers to the request
				message = new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, hash.markers, null) };
			}
			else
			{ //apply markers to the response
				message = new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, hash.markers) };
			}
			HashDiscoveredIssueText issueText = new HashDiscoveredIssueText(hash);
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
	}

	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
	{
		return null; // doActiveScan is required but not used
	}

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
	{
		URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
		if (!callbacks.isInScope(url))
		{
			//only hash in-scope URL's params for performance reasons
			return issues;
		}
		String request = "", response = "";
		try 
		{
			request = new String(baseRequestResponse.getRequest(), StandardCharsets.UTF_8);
			response = new String(baseRequestResponse.getResponse(), StandardCharsets.UTF_8);
		}
		catch (Exception ex) {}
		findHashes(request, baseRequestResponse, SearchType.REQUEST);
		findHashes(response, baseRequestResponse, SearchType.RESPONSE);
		createHashDiscoveredIssues(baseRequestResponse);

		if (!config.reportHashesOnly)
		{
			//TODO: find a way to go back and update identified params with new hash algorithms 
			//if new hash algorithms are added to the hashTracker
			issues.addAll(findHashedParameters(baseRequestResponse));
		}
		issues = sortIssues(issues);
		if (issues.size() > 0)
		{
			stdOut.println("Added " + issues.size() + " issues.");
		}
		for (IScanIssue issue : issues)
		{
			//stdOut.println("Begin Issue:\n" + issue.toString() + "\nEnd Issue");
		}
		return issues;
	}

	private List<Issue> findHashedParameters(IHttpRequestResponse baseRequestResponse)
	{
		List<Issue> issues = new ArrayList<>();
		List<Item> items = getParameterItems(baseRequestResponse);
		generateParameterHashes(items);
		issues.addAll(findMatchingHashes());
		return issues;
	}

	private void findHashes(String s, IHttpRequestResponse baseRequestResponse, SearchType searchType)
	{
		for(HashAlgorithm hashAlgorithm : hashAlgorithms)
		{
			List<HashRecord> results = findRegex(s, hashAlgorithm.pattern, hashAlgorithm.name);
			for(HashRecord result : results)
			{
				boolean found = false;
				result.searchType = searchType;
				for (HashRecord hash : hashes)
				{
					if (hash.getNormalizedRecord().contains(result.getNormalizedRecord())
							|| hash.getNormalizedRecord().equals(result.getNormalizedRecord())) //second half of OR statement is likely redundant
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
		saveHashes();
	}

	private List<Issue> findMatchingHashes()
	{
		List<Issue> issues = new ArrayList<>();
		//TODO: improve logic to compare hashed params with discovered hashes
		for(HashRecord hash : hashes)
		{
			for(Parameter param : parameters)
			{
				for (ParameterHash paramHash : param.parameterHashes)
				{
					if (hash.algorithm == paramHash.algorithm && hash.getNormalizedRecord() == paramHash.hashedValue)
					{
						stdOut.println("I sunk your battleship " + paramHash.hashedValue + " " + param.name);
						//TODO: Create an Issue object and add to issues collection
					}
				}
			}
		}
		return issues;
	}

	private List<HashRecord> findRegex(String s, Pattern pattern, HashAlgorithmName algorithm)
	{
		//TODO: Regex will flag on longer hex values - fix this.  Update 6/24: haven't seen this repeated in awhile. Needs more testing to confirm.
		//TODO: Add support for f0:a3:cd style encoding (!MVP)
		//TODO: Add support for 0xFF style encoding (!MVP)
		List<HashRecord> hashes = new ArrayList<HashRecord>();
		Matcher matcher = pattern.matcher(s);
		boolean isUrlEncoded = false;
		String urlDecodedMessage = s;
		try
		{
			urlDecodedMessage = URLDecoder.decode(s, StandardCharsets.UTF_8.toString());
			if (!urlDecodedMessage.equals(s))
			{
				//stdOut.println("URL Encoding Detected");
				isUrlEncoded = true;
			}
		}
		catch (java.io.UnsupportedEncodingException uee) { }

		while (matcher.find())
		{
			HashRecord hash = new HashRecord();
			hash.found = true;
			hash.markers.add(new int[] { matcher.start(), matcher.end() });
			hash.record = matcher.group();
			hash.algorithm = algorithm;
			hash.encodingType = EncodingType.Hex;
			hash.sortMarkers();
			hashes.add(hash);
			hashTracker.add(algorithm);
		}
		Matcher b64matcher = b64.matcher(urlDecodedMessage); 
		while (b64matcher.find())
		{
			String b64EncodedHash = b64matcher.group();
			String urlDecodedHash = b64EncodedHash;
			//TODO: Consider adding support for double-url encoded values (Not MVP)
			try
			{
				//Hacky way to ensure the regex doesn't forget the trailing "==" signs:
				//may have to adjust for URLencoding with the padding...
				int padding = 0;
				while (urlDecodedHash.length() % 4 != 0)
				{
					padding++;
					urlDecodedHash += "=";
					if (isUrlEncoded)
					{
						//TODO: I think I made this bit irrelevant with the new way I'm handling URL encoding:
//						b64EncodedHash += "%3d"; //pad the orig so we can find the proper issue markers
					}
					if (padding == 3)
					{
						//TODO: research b64 encoding padding - don't think 3 "=" are allowed
						//stdErr.println("Oops? Padding == 3: " + urlDecodedHash); 						
					}
				}
				if (urlDecodedMessage.contains(urlDecodedHash)) //this will fail if double url encoded
				{
					//sadly, the base64 regex by itself is ineffective (false positives)
					//so we need to try to decode and catch exceptions instead
					String hexHash = Utilities.byteArrayToHex(Base64.getDecoder().decode(urlDecodedHash));
					matcher = pattern.matcher(hexHash);
					if (matcher.matches())
					{
						stdOut.println("Base64 Match: " + urlDecodedHash + " <<" + hexHash + ">>");
						HashRecord hash = new HashRecord();
						hash.found = true;	
						if (isUrlEncoded)
						{
							b64EncodedHash = b64EncodedHash.replace("=", "%3D");
							int i = s.indexOf(b64EncodedHash);
							hash.markers.add(new int[] { i, (i + b64EncodedHash.length()) });
							stdOut.println("Markers: " + i + " " + (i + b64EncodedHash.length()));
						}
						else
						{
							hash.markers.add(new int[] { b64matcher.start(), (b64matcher.end() + padding) }); 
						}
						hash.record = urlDecodedHash; //TODO: Consider persisting UrlEncoded version if it was found that way
						hash.algorithm = algorithm;
						hash.encodingType = EncodingType.Base64;
						hash.sortMarkers();
						hashes.add(hash);
						hashTracker.add(algorithm);
					}
				}
			}
			catch (IllegalArgumentException iae)
			{
				stdErr.println(iae);
			}
		}

		return hashes;
	}
	
	private void generateParameterHashes(List<Item> items)
	{
		for(Item item : items)
		{
			if (isItemAHash(item))
			{
				continue; // don't rehash the hashes
			}
			Parameter param = new Parameter();
			param.name = item.getName();
			param.value = item.getValue();
			for (HashAlgorithmName algorithm : hashTracker)
			{
				try
				{
					ParameterHash hash = new ParameterHash();
					hash.algorithm = algorithm;
					MessageDigest md = MessageDigest.getInstance(algorithm.getValue());
					byte[] digest = md.digest(param.value.getBytes(StandardCharsets.UTF_8));
					hash.hashedValue = Utilities.byteArrayToHex(digest);
					param.parameterHashes.add(hash);
					stdOut.println("Found Parameter: " + param.name + ":" + param.value + " " + algorithm + " hash: " + hash.hashedValue);
				}
				catch (NoSuchAlgorithmException nsae)
				{ }
			}
			parameters.add(param);
		}
	}
	
	IBurpExtenderCallbacks getCallbacks() {
		return callbacks;
	}
	
	Config getConfig() {
		return config;
	}
	
	private List<Item> getCookieItems(List<ICookie> cookies)
	{
		List<Item> items = new ArrayList<>();
		for (ICookie cookie : cookies) 
		{
			items.add(new Item(cookie));
		}
		return items;
	}
	
	Database getDatabase() {
		return db;
	}

	private List<Item> getParameterItems(IHttpRequestResponse baseRequestResponse)
	{
		List<Item> items = new ArrayList<>();
		//TODO: Verify req and resp objects are not null on the opposite message type
		IRequestInfo req = helpers.analyzeRequest(baseRequestResponse);
		List<IParameter> params = req.getParameters();
		//TODO: Need to find a way to get cookies from requests to include any client side created cookies. This fails to build:
		//items.addAll(req.getCookies());
		//TODO: Find params in JSON
		//TODO: Find params in headers
		for (IParameter param : params)
		{
			items.add(new Item(param));
		}
		IResponseInfo resp = helpers.analyzeResponse(baseRequestResponse.getResponse());
		items.addAll(getCookieItems(resp.getCookies()));
		// this.stdOut.println("Items stored: " + items.size());
		return items;
	}

	PrintWriter getStdErr() {
		return stdErr;
	}

	PrintWriter getStdOut() {
		return stdOut;
	}

	private boolean isItemAHash(Item item)
	{
		//TODO: implement a check to see if the item is already a hash
		return false;
	}

	private void loadConfig()
	{
		try
		{
			config = Config.load(this); // load configuration
		} 
		catch (Exception e) 
		{
			stdErr.println("Error loading config: " + e.getMessage());
			e.printStackTrace(stdErr);
		}

		//Build in reverse order (largest first) for searching:
		if(config.isSha512Enabled) hashAlgorithms.add(new HashAlgorithm(128, HashAlgorithmName.SHA_512));
		if(config.isSha384Enabled) hashAlgorithms.add(new HashAlgorithm(96, HashAlgorithmName.SHA_384));
		if(config.isSha256Enabled) hashAlgorithms.add(new HashAlgorithm(64, HashAlgorithmName.SHA_256));
		if(config.isSha224Enabled) hashAlgorithms.add(new HashAlgorithm(56, HashAlgorithmName.SHA_224));
		if(config.isSha1Enabled) hashAlgorithms.add(new HashAlgorithm(40, HashAlgorithmName.SHA_1));
		if(config.isMd5Enabled) hashAlgorithms.add(new HashAlgorithm(32, HashAlgorithmName.MD5));
	
		//Load persisted hashes/parameters for resuming testing from a previous test:
		loadHashes();
		loadHashedParameters();
	}

	/**
	 * TODO: kill/modify/rename this method
	 *
	 * it's a quick & dirty POC for the SQLite functionality
	 */
	private void loadDatabase() {
		db = new Database(this);
		if (!db.verify()) {
			db.init();
			if (!db.verify()) {
				stdErr.println("Unable to initialize database.");
			} else {
				stdOut.println("Database initialized and verified.");
			}
		} else {
			stdOut.println("Database verified.");
		}
		db.close();
	}

	private void loadGui() {
		guiTab = new GuiTab(this);
		callbacks.addSuiteTab(guiTab);
	}

	private void loadHashedParameters()
	{
		//TODO: Implement retrieving hashed params from disk later (!MVP)
	}

	private void loadHashes()
	{
		//TODO: Implement retrieving hashes from disk later (!MVP)
	}

	private void saveHashedParameters()
	{
		//TODO: Persist hashed params later (!MVP)
	}

	private void saveHashes()
	{
		//TODO: Persist hashes later (!MVP)
	}

	private List<IScanIssue> sortIssues(List<IScanIssue> issues)
	{
		List<IScanIssue> sorted = new ArrayList<>();
		IScanIssue previous = null;
		for (IScanIssue issue : issues)
		{
			if (previous == null)
			{
				previous = issue;
				sorted.add(issue);
				continue;
			}
			boolean unique = true;
			for (IScanIssue i : sorted)
			{
				if (i.getIssueDetail().equals(issue.getIssueDetail()))
				{
					unique = false;
					break;
				}				
			}
			if (unique)
			{
				sorted.add(issue);
			}
		}
		return sorted;
	}
}
