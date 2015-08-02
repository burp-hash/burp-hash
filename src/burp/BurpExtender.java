package burp;

import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
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
		URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
		if (!callbacks.isInScope(url))
		{
			// only scan in-scope URLs for performance reasons
			return null;
		}
		stdOut.println("Scanner: Begin passive scanning: " + url + "\n...");
		
		//First locate params and generate hashes (if enabled)
		if (!config.reportHashesOnly)
		{
			//TODO: something in here may be generating duplicate hashes in memory (not in sqlite)
			// the dupe is redundant for matching hashes to params
			hashNewParameters(findNewParameters(baseRequestResponse));
		}
		
		//Observe hashes in request/response
		List<HashRecord> foundHashes = new ArrayList<>();
		foundHashes.addAll(findHashes(baseRequestResponse, SearchType.REQUEST));
		foundHashes.addAll(findHashes(baseRequestResponse, SearchType.RESPONSE));

		//Note any discoveries and create burp issues
		List<IScanIssue> discoveredHashIssues = createHashDiscoveredIssues(foundHashes, baseRequestResponse);
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
			items.addAll(findEmailRegex(new String(baseRequestResponse.getRequest(), StandardCharsets.UTF_8)));
		}
		IResponseInfo resp = helpers.analyzeResponse(baseRequestResponse.getResponse());
		if (resp != null) 
		{
			//TODO: Find params in JSON response
			//TODO: Find params in response headers
			//TODO: Find params in html body response via common regexes (email, user ID, credit card, etc.)
			for (IParameter cookie : getCookieItems(resp.getCookies()))
			{
				if (config.debug) stdOut.println(moduleName + ": Found Response Cookie: '" + cookie.getName() + "':'" + cookie.getValue() + "'");
				if (db.saveParam(cookie.getName()))
				{
					items.add(new Item(cookie));

				}
			}
			items.addAll(findEmailRegex(new String(baseRequestResponse.getResponse(), StandardCharsets.UTF_8)));
			// if (config.debug) stdOut.println("Items stored: " + items.size());
		}
		items.addAll(findParamsInJson(baseRequestResponse));
		return items;
	}
	
	private List<Item> findEmailRegex(String msg)
	{
		List<Item> items = new ArrayList<>();
		final String emailRegex = "[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,4}";
		Pattern pattern = Pattern.compile(emailRegex);
		Matcher matcher = pattern.matcher(msg);
		while (matcher.find())
		{
			String email = matcher.group();
			if (config.debug) stdOut.println(moduleName + ": Found Email by Regex: " + email);			
			items.add(new Item(email));
		}
		return items;
	}
	
	private List<Item> findParamsInJson(IHttpRequestResponse msg)
	{
		List<String> headers;
		boolean isJson;
		List<Item> items = new ArrayList<>();
		final String jsonRegex = "^content-type:.*json.*$";
		Pattern pattern = Pattern.compile(jsonRegex, Pattern.CASE_INSENSITIVE);

		// search the request
		byte[] req = msg.getRequest();
		IRequestInfo reqInfo = helpers.analyzeRequest(req);
		headers = reqInfo.getHeaders();
		isJson = false;
		for (String header : headers) {
			if (pattern.matcher(header).matches()) {
				isJson = true;
				break;
			}
		}
		if (isJson) {
			byte[] body = Arrays.copyOfRange(req, reqInfo.getBodyOffset(), req.length);
			//TODO: parse for name/value pairs
			//String val = "";
			//items.add(new Item(val));
		}

		// search the response
		byte[] resp = msg.getResponse();
		IResponseInfo respInfo = helpers.analyzeResponse(resp);
		headers = respInfo.getHeaders();
		isJson = false;
		for (String header : headers) {
			if (pattern.matcher(header).matches()) {
				isJson = true;
				break;
			}
		}
		if (isJson) {
			byte[] body = Arrays.copyOfRange(resp,  respInfo.getBodyOffset(),  resp.length);
			//TODO: parse for name/value pairs
			//String val = "";
			//items.add(new Item(val));
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
					if (config.debug) stdOut.println(moduleName + ": " + algorithm.name.text + " hash for: " + param.value + " hash=" + paramWithHash.hashedValue);
					if (db.saveParamWithHash(paramWithHash)) 
					{
						continue;
					}
				}
				catch (NoSuchAlgorithmException nsae)
				{ 
					stdOut.println(moduleName + ": No Such Algorithm Error" + nsae); 
				}
			}
			parameters.add(param);
		}
	}

	private List<HashRecord> findHashes(IHttpRequestResponse baseRequestResponse, SearchType searchType)
	{
		String s;
		List<HashRecord> currentHashes = new ArrayList<>();
		if (searchType.equals(SearchType.REQUEST)) {
			s = new String(baseRequestResponse.getRequest(), StandardCharsets.UTF_8);
		} else {
			s = new String(baseRequestResponse.getResponse(), StandardCharsets.UTF_8);
		}
		for(HashAlgorithm hashAlgorithm : config.hashAlgorithms)
		{
			if (!hashAlgorithm.enabled) { continue; }
			List<HashRecord> results = findHashRegex(s, hashAlgorithm.pattern, hashAlgorithm.name);
			for(HashRecord result : results)
			{
				result.searchType = searchType;
				stdOut.println(moduleName + ": Found " + hashAlgorithm.name.text + " hash in " + searchType + ": " + result.record);
				//TODO: same hash string with different marker values gets lost
				db.saveHash(result);
				hashes.add(result);
				currentHashes.add(result);
				break; //to avoid a false 'match' with a shorter hash algorithm
			}
			if (!results.isEmpty())
			{
				//prevent a mismatch on a shorter hash algorithm in descending order:
				break;
			}
		}
		return currentHashes;
	}
	
	private List<IScanIssue> createHashDiscoveredIssues(List<HashRecord> foundHashes, IHttpRequestResponse baseRequestResponse)
	{
		List<IScanIssue> issues = new ArrayList<>();
		for(HashRecord hash : foundHashes)
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

	private List<IScanIssue> matchParamsToHashes(IHttpRequestResponse baseRequestResponse)
	{
		if (config.debug) stdOut.println(moduleName + ": Matching Params to " + hashes.size() + " observed hashes.");
		List<IScanIssue> issues = new ArrayList<>();
		for(HashRecord hash : hashes)
		{
			String paramValue = db.getParamByHash(hash);
			if (paramValue != null)
			{
				stdOut.println(moduleName + ": " + hash.algorithm.text + " ***HASH MATCH*** for parameter'" + paramValue + "' = '" + hash.getNormalizedRecord() + "'");
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
				if (config.debug) stdOut.println(moduleName + ": Did not find plaintext match for " + hash.algorithm.text + " hash: '" + hash.getNormalizedRecord() + "'");
			}
		}
		return issues;
	}

	private List<HashRecord> findHashRegex(String s, Pattern pattern, HashAlgorithmName algorithm)
	{
		//TODO: Add support for f0:a3:cd style encoding (!MVP)
		//TODO: Add support for 0xFF style encoding (!MVP)
		List<HashRecord> hashes = new ArrayList<>();
		Matcher matcher = pattern.matcher(s);

		/**
		 * urlDecodedMessage.equals(s) does not work as expected because decoder seems to
		 * return different value than s even when there's nothing to decode
		 * TODO: find a better way to compare
		 * TODO: Consider adding support for double-url encoded values (!MVP)
		 **
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
		catch (java.io.UnsupportedEncodingException uee) {
			stdErr.println(uee);
		}
		/*******/

		// search for hashes in raw request/response
		while (matcher.find())
		{
			HashRecord hash = new HashRecord();
			hash.markers.add(new int[] { matcher.start(), matcher.end() });
			hash.record = matcher.group();
			hash.algorithm = algorithm;
			hash.encodingType = EncodingType.Hex;
			hash.sortMarkers();
			hashes.add(hash);
			//TODO: if hash algorithm was previously not enabled in config, enable it 
			//and generate hashes on all previously saved parameters (probably !MVP)
		}

		// search for Base64-encoded data
		Matcher b64matcher = b64.matcher(s);
		while (b64matcher.find())
		{
			String b64EncodedHash = b64matcher.group();

			// save some cycles
			if (b64EncodedHash.isEmpty() || b64EncodedHash.length() < 16)
				continue;

			try
			{
				// find base64-encoded hex strings representing hashes
				byte[] byteHash = Base64.getDecoder().decode(b64EncodedHash);
				String strHash = new String(byteHash, StandardCharsets.UTF_8);
				matcher = pattern.matcher(strHash);
				if (matcher.matches()) {
					stdOut.println(moduleName + ": Base64 Match: " + b64EncodedHash + " <<" + strHash + ">>");
					HashRecord hash = new HashRecord();
					int i = s.indexOf(b64EncodedHash);
					hash.markers.add(new int[] { i, (i + b64EncodedHash.length()) });
					hash.record = b64EncodedHash;
					hash.algorithm = algorithm;
					hash.encodingType = EncodingType.StringBase64;
					hash.sortMarkers();
					hashes.add(hash);
				}

				// find base64-encoded raw hashes
				String hexHash = Utilities.byteArrayToHex(Base64.getDecoder().decode(b64EncodedHash));
				matcher = pattern.matcher(hexHash);
				if (matcher.matches())
				{
					stdOut.println(moduleName + ": Base64 Match: " + b64EncodedHash + " <<" + hexHash + ">>");
					HashRecord hash = new HashRecord();
					int i = s.indexOf(b64EncodedHash);
					hash.markers.add(new int[] { i, (i + b64EncodedHash.length()) });
					hash.record = b64EncodedHash;
					hash.algorithm = algorithm;
					hash.encodingType = EncodingType.Base64;
					hash.sortMarkers();
					hashes.add(hash);
					//TODO: if hash algorithm was previously not enabled in config, enable it 
					//and generate hashes on all previously saved parameters (probably !MVP)
					// ^ also see above
				}
			}
			catch (IllegalArgumentException e)
			{
				stdErr.println(e);
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
