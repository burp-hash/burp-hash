package burp;

import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.Base64;
import java.net.URLDecoder;
import java.util.EnumSet;
import java.net.URL;
import java.security.*;

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
	private List<HashRecord> hashes = new ArrayList<>();
	private List<Parameter> parameters = new ArrayList<>();

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
		
		//Load persisted hashes/parameters for resuming testing from a previous test:
		LoadHashes();
		LoadHashedParameters();
	}

	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
	{
		return null; // doActiveScan is required but not used
	}
	
	private List<HashRecord> FindRegex(String s, Pattern pattern, HashAlgorithmName algorithm)
	{
		//TODO: Regex will flag on longer hex values - fix this.  Update 6/24: haven't seen this repeated in awhile. Needs more testing to confirm.
		//TODO: Add support for f0:a3:cd style encoding (Not MVP)
		//TODO: Add support for 0xFF style encoding (Not MVP)
		List<HashRecord> hashes = new ArrayList<HashRecord>();
		Matcher matcher = pattern.matcher(s);
		boolean isUrlEncoded = false;
		String urlDecodedMessage = s;
		try
		{
			urlDecodedMessage = URLDecoder.decode(s, "UTF-8");
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
		
	private List<Issue> FindHashes(String s, IHttpRequestResponse baseRequestResponse, SearchType searchType)
	{
		for(HashAlgorithm hashAlgorithm : hashAlgorithms)
		{
			List<HashRecord> results = FindRegex(s, hashAlgorithm.pattern, hashAlgorithm.name);
			for(HashRecord result : results)
			{
				if (result.found) //this check may be unnecessary now
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
		SaveHashes();
		return CreateHashDiscoveredIssues(baseRequestResponse, searchType);
	}
	
	private void SaveHashes()
	{
		//TODO: Persist hashes later (!MVP)
	}
	
	private void LoadHashes()
	{
		//TODO: Implement retrieving hashes from disk later (!MVP)
	}
	
	private void SaveHashedParameters()
	{
		//TODO: Persist hashed params later (!MVP)
	}
	
	private void LoadHashedParameters()
	{
		//TODO: Implement retrieving hashed params from disk later (!MVP)
	}
	
	private List<Issue> CreateHashDiscoveredIssues(IHttpRequestResponse baseRequestResponse, SearchType searchType)
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
	
	private List<Item> GetCookieItems(List<ICookie> cookies)
	{
		List<Item> items = new ArrayList<>();
		for (ICookie cookie : cookies) 
		{
			items.add(new Item(cookie));
		}
		return items;
	}
	
	private List<Item> GetParameterItems(IHttpRequestResponse baseRequestResponse)
	{
		List<Item> items = new ArrayList<>();
		//TODO: Verify req and resp objects are not null on the opposite message type
		IRequestInfo req = this.helpers.analyzeRequest(baseRequestResponse);
		List<IParameter> params = req.getParameters();
		//TODO: Need to find a way to get cookies from requests to include any client side created cookies. This fails to build:
		//items.addAll(req.getCookies());
		//TODO: Find params in JSON
		//TODO: Find params in headers
		for (IParameter param : params)
		{
			items.add(new Item(param));
		}
		IResponseInfo resp = this.helpers.analyzeResponse(baseRequestResponse.getResponse());
		items.addAll(GetCookieItems(resp.getCookies()));
		// this.stdOut.println("Items stored: " + items.size());
		return items;
	}
	
	private boolean IsItemAHash(Item item)
	{
		//TODO: implement a check to see if the item is already a hash
		return false;
	}
	
	private void GenerateParameterHashes(List<Item> items)
	{
		for(Item item : items)
		{
			if (IsItemAHash(item))
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
					MessageDigest md = MessageDigest.getInstance(algorithm.toString());
					byte[] digest = md.digest(param.value.getBytes("UTF-8"));
					hash.hashedValue = Utilities.byteArrayToHex(digest);
					param.parameterHashes.add(hash);
					stdOut.println("Algorithm: " + algorithm + " " + param.name + ":" + param.value + " hash: " + hash.hashedValue);
				}
				catch (NoSuchAlgorithmException nsae)
				{ }
				catch (UnsupportedEncodingException uee)
				{ }
			}			
			parameters.add(param);
		}
	}
	
	private List<Issue> FindMatchingHashes()
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
	
	private List<Issue> FindHashedParameters(IHttpRequestResponse baseRequestResponse)
	{
		List<Issue> issues = new ArrayList<>();		
		List<Item> items = GetParameterItems(baseRequestResponse);
		GenerateParameterHashes(items);
		issues.addAll(FindMatchingHashes());
		return issues;
	}
		
	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) 
	{
		List<IScanIssue> issues = new ArrayList<>();
		URL url = helpers.analyzeRequest(baseRequestResponse).getUrl();
		if (!callbacks.isInScope(url)) 
		{
			//only hash in-scope URL's params for performance reasons
			return issues;
		}
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
			//TODO: find a way to go back and update identified params with new hash algorithms 
			//if new hash algorithms are added to the hashTracker
			issues.addAll(FindHashedParameters(baseRequestResponse));
		}
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

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) 
	{
		//TODO: determine if we want to remove dupes or not
		return 0;
		//disabling the filtering for now, we may want this later:
/*		if (existingIssue.getIssueDetail() == newIssue.getIssueDetail()) {
			return -1; // discard new issue
		} else {
			return 0; // use both issues
		}*/
	}
}
