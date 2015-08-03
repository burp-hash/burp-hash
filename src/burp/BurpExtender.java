package burp;

import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.net.URLDecoder;

/**
 * This is the "main" class of the extension. Burp begins by
 * calling {@link BurpExtender#registerExtenderCallbacks(IBurpExtenderCallbacks)}.
 */
public class BurpExtender implements IBurpExtender, IScannerCheck 
{
	static final String extensionName = "burp-hash";
	static final String moduleName = "Scanner";
	static final String extensionUrl = "https://burp-hash.github.io/";
	public Pattern b64Regex = Pattern.compile("(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?");
	public Pattern emailRegex = Pattern.compile("[^=\"&;:\\s]*[a-zA-Z0-9-_\\.]+@[a-zA-Z0-9-\\.]+.[a-zA-Z]+");
	public Pattern ccRegex = Pattern.compile("[0-9]{4}[-]*[0-9]{4}[-]*[0-9]{4}[-]*[0-9]{4}");
	private IBurpExtenderCallbacks callbacks;
	private Config config;
	private Database db;
	private GuiTab guiTab;
	private List<HashRecord> hashes = new ArrayList<>();
	private List<IScanIssue> issues = new ArrayList<>();
	private IExtensionHelpers helpers;
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
		//TODO: determine if we need better dupe comparisons
//		return 0;
		if (existingIssue.getIssueDetail().equals(newIssue.getIssueDetail())) {
			return -1; // discard new issue 
		} else {
			return 0; // use both issues
		}
	}
	
	/**
	 * Active Scanning is not implemented with this plugin.
	 */
	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
	{
		return null; // doActiveScan is required but not used
	}

	/**
	 * Implements the main entry point to Burp's Extension API for Passive Scanning.
	 * Algorithm:
	 *   - Grab the request/response
	 *   - Locate and save all parameters
	 *   - Hash parameters against configured and observed hash functions
	 *   - Locate any hashes and match against pre-computed parameters' hashes
	 *   - If any new hash algorithm types are observed, go back and check previously saved parameters
	 */
	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
	{
		URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
		if (!callbacks.isInScope(url))
		{
			// only scan in-scope URLs for performance reasons
			return null;
		}
		stdOut.println("Scanner: Begin passive scanning: " + url + "\n...");
		if (config.reportHashesOnly && config.debug) stdOut.println(moduleName + ": reporting observed hashes only, hashing parameters is disabled.");
		
		//First locate params and generate hashes (if enabled)
		if (!config.reportHashesOnly)
		{
			//TODO: something in here may be generating duplicate hashes in memory (not in sqlite)
			// the dupe is redundant for matching hashes to params:
			hashNewParameters(findNewParameters(baseRequestResponse));
		}
		
		//Observe hashes in request/response
		hashes = new ArrayList<>();
		issues = new ArrayList<>();
		findHashes(baseRequestResponse, SearchType.REQUEST);
		findHashes(baseRequestResponse, SearchType.RESPONSE);

		//Note any discoveries and create burp issues
		List<IScanIssue> discoveredHashIssues = createHashDiscoveredIssues(baseRequestResponse);
		discoveredHashIssues = sortIssues(discoveredHashIssues);
		if (discoveredHashIssues.size() > 0)
		{
			stdOut.println(moduleName + ": Added " + discoveredHashIssues.size() + " 'Hash Discovered' issues.");
		}
		
		List<IScanIssue> matchedHashIssues = matchParamsToHashes(baseRequestResponse);
		matchedHashIssues = sortIssues(matchedHashIssues);
		if (!matchedHashIssues.isEmpty())
		{
			stdOut.println(moduleName + ": Added " + matchedHashIssues.size() + " 'Hash Matched' issues.");
		}
		issues.addAll(matchedHashIssues);
		issues.addAll(discoveredHashIssues);
		return issues;
	}
	
	protected List<Item> findNewParameters(IHttpRequestResponse baseRequestResponse)
	{
		List<Item> items = new ArrayList<>();
		IRequestInfo req = helpers.analyzeRequest(baseRequestResponse);
		if (req != null)
		{
			items.addAll(saveHeaders(req.getHeaders()));
			for (IParameter param : req.getParameters())
			{
				//TODO: Consider hashing the parameter with any hash algorithms missing from DB
				if (config.debug) stdOut.println(moduleName + ": Found Request Parameter: '" + param.getName() + "':'" + param.getValue() + "'");
				if (db.saveParam(param.getValue()))
				{
					items.add(new Item(param));
				}
				try 
				{
					String urldecoded = URLDecoder.decode(param.getValue(), "UTF-8");
					if (!urldecoded.equals(param.getValue()))
					{
						if (config.debug) stdOut.println(moduleName + ": Found UrlDecoded Request Parameter: '" + param.getName() + "':'" + urldecoded + "'");
						if (db.saveParam(urldecoded))
						{
							Item i = new Item(param);
							i.setValue(urldecoded);
							items.add(i);
						}
					}
				} catch (UnsupportedEncodingException e) 
				{
					e.printStackTrace();
				}
			}
			String wholeRequest = new String(baseRequestResponse.getRequest(), StandardCharsets.UTF_8);
			//items.addAll(saveNewValueParams(findEmailRegex(wholeRequest)));
			//items.addAll(saveNewValueParams(findParamsInJson(wholeRequest)));
			try 
			{
				String urlDecodedWholeRequest = URLDecoder.decode(wholeRequest, StandardCharsets.UTF_8.toString());
				//items.addAll(saveNewValueParams(findEmailRegex(urlDecodedWholeRequest)));
			} 
			catch (UnsupportedEncodingException e) 
			{
				if (config.debug) stdOut.println(moduleName + ": encoding exception: " + e);
			}
		}
		IResponseInfo resp = helpers.analyzeResponse(baseRequestResponse.getResponse());
		if (resp != null) 
		{
			//items.addAll(saveHeaders(resp.getHeaders()));
			for (IParameter cookie : getCookieItems(resp.getCookies()))
			{
				if (config.debug) stdOut.println(moduleName + ": Found Response Cookie: '" + cookie.getName() + "':'" + cookie.getValue() + "'");
				if (db.saveParam(cookie.getName())) //check the cookie name
				{
					items.add(new Item(cookie));
				}
				if (db.saveParam(cookie.getValue())) //as well as its value
				{
					items.add(new Item(cookie));
				}
			}			
			//TODO: Find params in html body response via common regexes (email, user ID, credit card, etc.)
			String wholeResponse = new String(baseRequestResponse.getResponse(), StandardCharsets.UTF_8);
			items.addAll(saveNewValueParams(findEmailRegex(wholeResponse)));
			items.addAll(saveNewValueParams(findParamsInJson(wholeResponse)));
			// if (config.debug) stdOut.println("Items stored: " + items.size());
		}
		return items;
	}
	
	protected List<Item> saveHeaders(List<String> headers)
	{
		//TODO: Find cookies from request
		//TODO: Find params in request headers
		List<Item> items = new ArrayList<>();
		for (String header : headers)
		{
//			if (config.debug) stdOut.println(moduleName + ": header = " + header);
			if (header.startsWith("Date:") || header.startsWith("Content-Length:"))
			{
				//Don't want to fill the db with server response time stamps and content length headers
				continue;
			}
			if (db.saveParam(header))
			{
				items.add(new Item(header)); //save and hash entire header
			}
		}
		return items;
	}
	
	protected List<Item> saveNewValueParams(List<Item> items)
	{
		List<Item> savedItems = new ArrayList<>();
		for (Item item : items)
		{
			if (db.saveParam(item.getValue()))
			{
				savedItems.add(item);
			}
		}		
		return savedItems;
	}
	
	protected List<Item> findEmailRegex(String msg)
	{
		List<Item> items = new ArrayList<>();
		Matcher matcher = emailRegex.matcher(msg);
		while (matcher.find())
		{
			String email = matcher.group();
			if (email.contains("&"))
			{
				email = email.split("&")[0];
			}
			if (config.debug) stdOut.println(moduleName + ": Found Email by Regex: " + email);			
			items.add(new Item(email));
		}
		return items;
	}
	
	protected List<Item> findParamsInJson(String msg)
	{
		List<Item> items = new ArrayList<>();
		if (Pattern.compile(Pattern.quote("json"), Pattern.CASE_INSENSITIVE).matcher(msg).find())
		{
			//TODO: the message says "json" presumably in the content type header, which could include
			// jsonp, jsonrpc, and other json* variants.  So, parse the string for name/value pairs...
			//String value = "";
			//items.add(new Item(val));			
		}
		return items;
	}
	
	protected List<Parameter> hashNewParameters(List<Item> items)
	{
		List<Parameter> parameters = new ArrayList<>();
		for(Item item : items)
		{
			//TODO: validate this works:
			/*if (isItemAHash(item))
			{
				continue; // don't rehash the hashes
				//but probably want to add them to the parameter DB at some point
			}*/
			Parameter param = new Parameter();
			param.name = item.getName();
			param.value = item.getValue();
			for (HashAlgorithm algorithm : config.hashAlgorithms)
			{
				if (!algorithm.enabled)
				{
					if (config.debug) stdOut.println(moduleName + ": " + algorithm.name.text + " disabled.");
					continue;
				}
				try
				{
					ParameterWithHash paramWithHash = new ParameterWithHash();
					paramWithHash.parameter = param;
					paramWithHash.algorithm = algorithm.name;
					paramWithHash.hashedValue = HashEngine.Hash(param.value, algorithm.name);
					if (db.saveParamWithHash(paramWithHash)) 
					{
						if (config.debug) stdOut.println(moduleName + ": " + algorithm.name.text + " saved hash for: " + param.value + " hash=" + paramWithHash.hashedValue);
						continue;
					}
					if (config.debug) stdOut.println(moduleName + ": " + algorithm.name.text + " hash already in db (" + paramWithHash.hashedValue + ")");
				}
				catch (Exception e)
				{ 
					stdOut.println(moduleName + ": " + e); 
				}
			}
			parameters.add(param);
		}
		return parameters;
	}

	protected void findHashes(IHttpRequestResponse baseRequestResponse, SearchType searchType)
	{
		String s;
		if (searchType.equals(SearchType.REQUEST)) 
		{
			s = new String(baseRequestResponse.getRequest(), StandardCharsets.UTF_8);
		} 
		else 
		{
			s = new String(baseRequestResponse.getResponse(), StandardCharsets.UTF_8);
		}
		for(HashAlgorithm hashAlgorithm : config.hashAlgorithms)
		{
			if (config.debug) stdOut.println(moduleName + ": Searching for " + hashAlgorithm.name.text + " hashes.");
			findHashRegex(s, hashAlgorithm.pattern, hashAlgorithm);
			for(HashRecord hash : hashes)
			{
				if (hash.reported)
				{
					continue;
				}
				hash.reported = true;
				hash.searchType = searchType;
				stdOut.println(moduleName + ": Found " + hashAlgorithm.name.text + " hash in " + searchType + ": " + hash.record);
				//TODO: same hash string with different marker values gets lost
				// ^ No longer believe this is true, need to test. [TM]
				db.saveHash(hash);
				if (!hashAlgorithm.enabled)
				{
					config.toggleHashAlgorithm(hashAlgorithm.name, true);
					if (config.debug) stdOut.println(moduleName + ": Dynamic hash detection enabled " + hashAlgorithm.name.text + ".");
					rehashSavedParameters(hashAlgorithm);
				}
				break; //to avoid a false 'match' with a shorter hash algorithm
			}
		}
	}
	
	private void rehashSavedParameters(HashAlgorithm algorithm)
	{
		List<String> paramsWithoutNewHash = db.getParamsWithoutHashType(algorithm);
		if (config.debug) stdOut.println(moduleName + ": Preparing to update " + paramsWithoutNewHash.size() + 
				" parameters with " + algorithm.name.text + " hashes...");
		for (String param : paramsWithoutNewHash)
		{
			try 
			{
				HashRecord hash = new HashRecord();
				hash.algorithm = algorithm;
				hash.record = HashEngine.Hash(param, algorithm.name);
				db.saveHash(hash);
			}
			catch (NoSuchAlgorithmException e) 
			{
				stdErr.println(moduleName + ": " + e);
			}
		}
	}
	
	protected List<IScanIssue> createHashDiscoveredIssues(IHttpRequestResponse baseRequestResponse)
	{
		List<IScanIssue> issues = new ArrayList<>();
		if (baseRequestResponse == null)
		{
			throw new IllegalArgumentException(moduleName + ": base request/response object cannot be null.");
		}
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
		return issues;
	}

	protected List<IScanIssue> matchParamsToHashes(IHttpRequestResponse baseRequestResponse)
	{
		if (config.debug) stdOut.println(moduleName + ": Matching Params to " + hashes.size() + " observed hashes.");
		List<IScanIssue> issues = new ArrayList<>();
		for(HashRecord hash : hashes)
		{
			String paramValue = db.getParamByHash(hash);
			if (paramValue != null)
			{
				stdOut.println(moduleName + ": " + hash.algorithm.name.text + " ***HASH MATCH*** for parameter'" + paramValue + "' = '" + hash.getNormalizedRecord() + "'");
				IHttpRequestResponse[] message;
				if (hash.searchType.equals(SearchType.REQUEST))
				{ //apply markers to the request
					message = new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, hash.markers, null) };
				}
				else
				{ //apply markers to the response
					message = new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, hash.markers) };
				}
				
				HashMatchesIssueText issueText = new HashMatchesIssueText(hash, paramValue);
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
			else
			{
				if (config.debug) stdOut.println(moduleName + ": Did not find plaintext match for " + hash.algorithm.name.text + " hash: '" + hash.getNormalizedRecord() + "'");
			}
		}
		return issues;
	}
	
	protected boolean isDupeHash(HashRecord hash)
	{
		//if the markers show this starts at the same spot on the same request/response object
		//and the longer record includes the shorter record, this is either an exact dupe or 
		//a larger hash (e.g. SHA-512) mistaken for a shorter hash (e.g. SHA-256)
		for (HashRecord h : hashes)
		{
			if (h.markers.get(0).equals(hash.markers.get(0)))
			{
				if (h.record.length() > hash.record.length())
				{
					if (h.record.startsWith(hash.record))
					{
						return true;
					}
				}
				else
				{
					if (hash.record.startsWith(h.record))
					{
						return true;
					}
				}
			}
		}
		return false;
	}

	protected void findHashRegex(String s, Pattern pattern, HashAlgorithm algorithm)
	{
		//TODO: Add support for f0:a3:cd style encoding (!MVP)
		//TODO: Add support for 0xFF style encoding (!MVP)
		//TODO: Consider adding support for double-url encoded values (!MVP)
		Matcher matcher = pattern.matcher(s);
		// search for hashes in raw request/response
		while (matcher.find())
		{
			String result = matcher.group();
			//enforce char length of the match here, rather than regex which has false positives
			if (result.length() != algorithm.charWidth)
			{
				continue;
			}
			if (matcher.end() + 1 < s.length())
			{
				String nextChars = s.substring(matcher.end(), matcher.end() + 1);
				Matcher next = pattern.matcher(nextChars);
				//stdOut.println("Next: '" + nextChars + "' pattern: " + next.pattern().toString());
				if (next.find())
				{
					//stdOut.println("the next char is also [a-fA-F0-9] so this is a false positive");
					continue;
				}
			}
			HashRecord hash = new HashRecord();
			hash.markers.add(new int[] { matcher.start(), matcher.end() });
			hash.record = matcher.group();
			hash.algorithm = algorithm;
			hash.encodingType = EncodingType.Hex;
			hash.sortMarkers();
			if (!isDupeHash(hash))
			{
				hashes.add(hash);
			}
		}

		// search for Base64-encoded data
		Matcher b64matcher = b64Regex.matcher(s);
		while (b64matcher.find())
		{
			String b64EncodedHash = b64matcher.group();
			// save some cycles
			if (b64EncodedHash.isEmpty() || b64EncodedHash.length() < 16)
			{
				continue;
			}
			//stdOut.println("B64: " + b64EncodedHash);
			try
			{
				// find base64-encoded hex strings representing hashes
				byte[] byteHash = Base64.getDecoder().decode(b64EncodedHash);
				String strHash = new String(byteHash, StandardCharsets.UTF_8);
				//stdOut.println("B64 hex string: " + strHash);
				matcher = pattern.matcher(strHash);
				//enforce char width here to prevent smaller hashes from false positives with larger hashes:
				if (matcher.matches() && matcher.group().length() == algorithm.charWidth)
				{
					stdOut.println(moduleName + ": Base64 Match: " + b64EncodedHash + " <<" + strHash + ">>");
					HashRecord hash = new HashRecord();
					int i = s.indexOf(b64EncodedHash);
					hash.markers.add(new int[] { i, (i + b64EncodedHash.length()) });
					hash.record = b64EncodedHash;
					hash.algorithm = algorithm;
					hash.encodingType = EncodingType.StringBase64;
					hash.sortMarkers();
					if (!isDupeHash(hash))
					{
						hashes.add(hash);
					}
				}

				// find base64-encoded raw hashes
				String hexHash = Utilities.byteArrayToHex(Base64.getDecoder().decode(b64EncodedHash));
				//stdOut.println("B64 raw hash: " + hexHash);
				matcher = pattern.matcher(hexHash);
				//enforce char width here to prevent smaller hashes from false positives with larger hashes:
				if (matcher.matches() && matcher.group().length() == algorithm.charWidth)
				{
					stdOut.println(moduleName + ": Base64 Match: " + b64EncodedHash + " <<" + hexHash + ">>");
					HashRecord hash = new HashRecord();
					int i = s.indexOf(b64EncodedHash);
					hash.markers.add(new int[] { i, (i + b64EncodedHash.length()) });
					hash.record = b64EncodedHash;
					hash.algorithm = algorithm;
					hash.encodingType = EncodingType.Base64;
					hash.sortMarkers();
					if (!isDupeHash(hash))
					{
						hashes.add(hash);
					}
				}
			}
			catch (IllegalArgumentException e)
			{
				stdErr.println(e);
			}
		}
	}
	
	IBurpExtenderCallbacks getCallbacks() {
		return callbacks;
	}
	
	Config getConfig() {
		return config;
	}
	
	protected List<Item> getCookieItems(List<ICookie> cookies)
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

	PrintWriter getStdErr() {
		return stdErr;
	}

	PrintWriter getStdOut() {
		return stdOut;
	}

	protected boolean isItemAHash(Item item)
	{
		//TODO: implement a check to see if the item is already a hash
		for(HashRecord hash : hashes)
		{
			if (hash.record == item.getValue())
					return true;
		}
		return false;
	}

	//TODO: add method to (re)build hashAlgorithms on config change
	private void loadConfig()
	{
		try
		{
			config = Config.load(this); // load configuration
		} 
		catch (Exception e) 
		{
			stdErr.println(moduleName + ": Error loading config: " + e);
			e.printStackTrace(stdErr);
			return;
		}
		if (config.hashAlgorithms != null || !config.hashAlgorithms.isEmpty())
		{
			//stdOut.println(moduleName + ": Succesfully loaded hash algorithm configuration.");
		}
	}

	/**
	 * SQLite
	 * TODO: load db on demand, close when not in use
	 * TODO: save only when asked by user? (!MVP)
	 */
	private void loadDatabase() {
		db = new Database(this);
		if (!db.verify()) {
			db.init();
			if (!db.verify()) {
				stdErr.println(moduleName + ": Unable to initialize database.");
			} else {
				stdOut.println(moduleName + ": Database verified.");
			}
		} else {
			stdOut.println(moduleName + ": Database verified.");
		}
		//db.close();
	}

	private void loadGui() {
		guiTab = new GuiTab(this);
		callbacks.addSuiteTab(guiTab);
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
