package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This is the "main" class of the extension. Burp begins by
 * calling {@link BurpHashScanner#registerExtenderCallbacks(IBurpExtenderCallbacks)}.
 */
public class BurpExtender implements IBurpExtender, IScannerCheck 
{
	static final String extensionName = "burp-hash";
	static final String extensionUrl = "https://burp-hash.github.io/";
	Pattern b64 = Pattern.compile("(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?");
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
		//TODO: determine if we need better dupe comparisons
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
/*
	private void createHashMatchesIssues(IHttpRequestResponse baseRequestResponse, HashRecord hash, String PlainText)
		//might not need this the way it's currently implemented
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
		HashMatchesIssueText issueText = new HashMatchesIssueText(hash, PlainText);
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
*/
	
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
		String request, response;
		URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
		if (!callbacks.isInScope(url))
		{
			// only scan in-scope URLs for performance reasons
			return null;
		}
		request = new String(baseRequestResponse.getRequest(), StandardCharsets.UTF_8);
		response = new String(baseRequestResponse.getResponse(), StandardCharsets.UTF_8);
		
		//Locate params and generate hashes first if enabled
		if (!config.reportHashesOnly)
		{
			findAndHashParameters(baseRequestResponse);
		}
		
		//Then locate hashes
		findHashes(request, baseRequestResponse, SearchType.REQUEST);
		findHashes(response, baseRequestResponse, SearchType.RESPONSE);

		//Then note any discoveries and create burp issues
		createHashDiscoveredIssues(baseRequestResponse);
		issues = sortIssues(issues);
		if (issues.size() > 0)
		{
			stdOut.println("Scanner: Added " + issues.size() + " issues.");
		}
		/*for (IScanIssue issue : issues)
		{
			stdOut.println("Begin Issue:\n" + issue.toString() + "\nEnd Issue");
		}*/
		return issues;
	}

	private void findAndHashParameters(IHttpRequestResponse baseRequestResponse)
	{
		List<Item> items = findNewParameters(baseRequestResponse);
		hashNewParameters(items);
	}
	
	private List<Item> findNewParameters(IHttpRequestResponse baseRequestResponse)
	{
		List<Item> items = new ArrayList<>();
		IRequestInfo req = helpers.analyzeRequest(baseRequestResponse);
		if (req != null)
		{
			//TODO: Find cookies from request
			//TODO: Find params in JSON request
			//TODO: Find params in request headers
			//TODO: Consider url decoding parameters before saving/comparing to db
			for (IParameter param : req.getParameters())
			{
				if (config.debug) stdOut.println("Scanner: Found Request Parameter: " + param.getName() + ":" + param.getValue());
				if (db.saveParam(param.getValue()))
				{
					items.add(new Item(param));
				}
			}
		}
		IResponseInfo resp = helpers.analyzeResponse(baseRequestResponse.getResponse());
		if (resp != null) 
		{
			//TODO: Find params in JSON response
			//TODO: Find params in response headers
			for (IParameter cookie : getCookieItems(resp.getCookies()))
			{
				if (config.debug) stdOut.println("Scanner: Found Response Cookie: " + cookie.getName() + ":" + cookie.getValue());
				if (db.saveParam(cookie.getName()))
				{
					items.add(new Item(cookie));

				}
			}
			// if (config.debug) stdOut.println("Items stored: " + items.size());
		}
		return items;
	}
	
	private void hashNewParameters(List<Item> items)
	{
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
				if (config.debug) stdOut.println("Scanner: " + algorithm.name.text);
				if (!algorithm.enabled)
				{
					if (config.debug) stdOut.println(" - disabled.");
					continue;
				}
				if (config.debug) stdOut.println(" - enabled.");
				try
				{
					ParameterHash hash = new ParameterHash();
					hash.algorithm = algorithm.name;
					hash.hashedValue = HashEngine.Hash(param.value, algorithm.name);
					param.parameterHashes.add(hash);
					if (config.debug) stdOut.println("Scanner: " + algorithm.name.text + " hash for: " + param.value + " hash=" + hash.hashedValue);
					if (this.db.saveParamWithHash(param, hash)) 
					{
						//stdOut.println("Scanner: Saved parameter with hash to db " + param.value + ":" + hash.hashedValue);
						break;
					}
				}
				catch (NoSuchAlgorithmException nsae)
				{ 
					stdOut.println("Scanner: No Such Algorithm Error" + nsae); 
				}
			}
			parameters.add(param);
		}
	}

	private void findHashes(String s, IHttpRequestResponse baseRequestResponse, SearchType searchType)
	{
		for(HashAlgorithm hashAlgorithm : config.hashAlgorithms)
		{
			if (!hashAlgorithm.enabled) { continue; }
			List<HashRecord> results = findRegex(s, hashAlgorithm.pattern, hashAlgorithm.name);
			for(HashRecord result : results)
			{
				//TODO: fix this logic to record matched hashes
				stdOut.println("Scanner: Found " + hashAlgorithm.name.text + " hash: " + result.record);
				//Let the DB do the sorting of unique hash values:
				boolean found = !db.saveHash(result);
				result.searchType = searchType;
				//TODO: same hash string with different marker values gets lost
				// ^ Is this a problem? The intent here is to observe hashes of unknown origin. 
				// Logging how many times we saw it and where is not as valuable as just logging 
				// it so we can compare it to params we may hash and match later on.  Thoughts?  [TM]
				if (found) 
				{
					hashes.add(result);
				}
			}
			if (!results.isEmpty())
			{
				//if (config.debug) stdOut.println("Scanner: Preventing hash mismatch.");
				//prevent a mismatch on a shorter hash algorithm in descending order:
				break;
			}
		}
	}

	private List<Issue> findMatchingHashes(IHttpRequestResponse baseRequestResponse)
	{
		List<Issue> issues = new ArrayList<>();
		//TODO: improve logic to compare hashed params with discovered hashes
		for(HashRecord hash : hashes)
		{
			String paramValue = db.getParamByHash(hash);
			if (paramValue != null)
			{
				stdOut.println("Scanner: " + hash.algorithm.text + " Hash Match for " + paramValue + ":" + hash.getNormalizedRecord());
			}
			ParameterHash tempPH = new ParameterHash();
				tempPH.hashedValue = hash.record;
				tempPH.algorithm = hash.algorithm;
			String foundHit = "false"; //db.exists(tempPH);
			if(foundHit != null && !foundHit.isEmpty()) {
				stdOut.println("Scanner: !!!Matching Parameter!!!:"+foundHit);
				IHttpRequestResponse[] message;
				if (hash.searchType.equals(SearchType.REQUEST))
				{ //apply markers to the request
					message = new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, hash.markers, null) };
				}
				else
				{ //apply markers to the response
					message = new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, hash.markers) };
				}
				
				HashMatchesIssueText issueText = new HashMatchesIssueText(hash, foundHit);
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
				//createHashMatchesIssues(baseRequestResponse, hash, foundHit);
			}
			/*
			for(Parameter param : parameters)
			{
				for (ParameterHash paramHash : param.parameterHashes)
				{
					String foundHit = db.exists(paramHash);
					if(foundHit != null && !foundHit.isEmpty()) {
						stdOut.println("Matching Parameter:"+foundHit);
					}
						
					if (hash.algorithm == paramHash.algorithm && hash.getNormalizedRecord() == paramHash.hashedValue)
					{
						stdOut.println("I sunk your battleship " + paramHash.hashedValue + " " + param.name);
						//TODO: Create an Issue object and add to issues collection
					}
				}
			}*/
		}
		return issues;
	}

	private List<HashRecord> findRegex(String s, Pattern pattern, HashAlgorithmName algorithm)
	{
		//TODO: Add support for f0:a3:cd style encoding (!MVP)
		//TODO: Add support for 0xFF style encoding (!MVP)
		List<HashRecord> hashes = new ArrayList<HashRecord>();
		Matcher matcher = pattern.matcher(s);
		boolean isUrlEncoded = false;
		String urlDecodedMessage = s;

		/**
		 * urlDecodedMessage.equals(s) does not work as expected because decoder seems to
		 * return different value than s even when there's nothing to decode
		 * TODO: find a better way to compare
		 **
		try
		{
			urlDecodedMessage = URLDecoder.decode(s, StandardCharsets.UTF_8.toString());
			if (!urlDecodedMessage.equals(s))
			{
				//stdOut.println("URL Encoding Detected");
				isUrlEncoded = true;
			}
		}
		catch (java.io.UnsupportedEncodingException uee) {
			stdErr.println(uee);
		}
		/*******/

		// search for hashes in raw request/response
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
			//TODO: if hash algorithm was previously not enabled in config, enable it and generate hashes on all previously saved parameters
		}

		// search for Base64-encoded data
		Matcher b64matcher = b64.matcher(urlDecodedMessage); 
		while (b64matcher.find())
		{
			String b64EncodedHash = b64matcher.group();
			String urlDecodedHash = b64EncodedHash;

			// save some cycles
			if (b64EncodedHash.isEmpty() || b64EncodedHash.length() < 16)
				continue;
			//TODO: Consider adding support for double-url encoded values (!MVP)
			try
			{
				/**
				 * B64 regex matches text with words or numbers where number of chars divisible by 4
				 * so we should handle decoding exceptions gracefully
				 */
				String hexHash = Utilities.byteArrayToHex(Base64.getDecoder().decode(urlDecodedHash));
				matcher = pattern.matcher(hexHash);
				if (matcher.matches())
				{
					stdOut.println("Scanner: Base64 Match: " + urlDecodedHash + " <<" + hexHash + ">>");
					HashRecord hash = new HashRecord();
					hash.found = true;
					if (isUrlEncoded) {
						b64EncodedHash = b64EncodedHash.replace("=", "%3D");
					}
					int i = s.indexOf(b64EncodedHash);
					hash.markers.add(new int[] { i, (i + b64EncodedHash.length()) });
//						stdOut.println("Markers: " + i + " " + (i + b64EncodedHash.length()));
					hash.record = urlDecodedHash; //TODO: Consider persisting UrlEncoded version if it was found that way
					hash.algorithm = algorithm;
					hash.encodingType = EncodingType.Base64;
					hash.sortMarkers();
					hashes.add(hash);
					//TODO: if hash algorithm was not previously enabled, enable it and generate hashes of old params
				}
			}
			catch (IllegalArgumentException iae)
			{
				stdErr.println(iae);
			}
		}
		return hashes;
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

	PrintWriter getStdErr() {
		return stdErr;
	}

	PrintWriter getStdOut() {
		return stdOut;
	}

	private boolean isItemAHash(Item item)
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
			stdErr.println("Scanner: Error loading config: " + e);
			e.printStackTrace(stdErr);
			return;
		}
		if (config.hashAlgorithms != null || !config.hashAlgorithms.isEmpty())
		{
			//stdOut.println("Scanner: Succesfully loaded hash algorithm configuration.");
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
				stdErr.println("Scanner: Unable to initialize database.");
			} else {
				stdOut.println("Scanner: Database initialized and verified.");
			}
		} else {
			stdOut.println("Scanner: Database verified.");
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
