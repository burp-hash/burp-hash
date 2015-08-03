package burp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Manages settings for the extension. It's crude, but it works. This object is serialized
 * and stored as a string using Burp's extension settings functionality.
 */
class Config implements Serializable {
	private static final long serialVersionUID = 1L;
	private static final String moduleName = "Config";

	/**
	 * load saved config if it exists
	 * otherwise return default config
	 */
	static Config load(BurpExtender b) throws Exception {
		IBurpExtenderCallbacks c = b.getCallbacks();
		String encodedConfig = c.loadExtensionSetting(BurpExtender.extensionName);
		if (encodedConfig == null) {
			return new Config(b);
		}
		byte[] decodedConfig = Base64.getDecoder().decode(encodedConfig);
		ByteArrayInputStream bytes = new ByteArrayInputStream(decodedConfig);
		ObjectInputStream in = new ObjectInputStream(bytes);
		Config cfg = (Config) in.readObject();
		cfg.callbacks = c;
		cfg.stdErr = b.getStdErr();
		cfg.stdOut = b.getStdOut();
		cfg.loadHashAlgorithms(); //get a fresh copy of the algorithms so old regexes are not captured here.
		if (cfg.hashAlgorithms == null || cfg.hashAlgorithms.isEmpty()) 
		{
			cfg.stdOut.println(moduleName + ": Hash algorithm configuration is missing ... rebuilding defaults.");
			cfg.hashAlgorithms = new ArrayList<HashAlgorithm>();
			cfg.loadHashAlgorithms();
		}
		cfg.stdOut.println(moduleName + ": Successfully loaded settings.");
		return cfg;
	}

	private transient IBurpExtenderCallbacks callbacks;
	private transient PrintWriter stdErr;
	private transient PrintWriter stdOut;

	// variables below are the extension settings
	String databaseFilename;
	boolean reportHashesOnly;	
	boolean debug = true;
	public List<HashAlgorithm> hashAlgorithms = new ArrayList<HashAlgorithm>();

	/**
	 * constructor used only when saved config is not found
	 */
	private Config(BurpExtender b) 
	{
		callbacks = b.getCallbacks();
		stdErr = b.getStdErr();
		stdOut = b.getStdOut();
		setDefaults();
		stdOut.println(moduleName + ": No saved settings found - using defaults.");
	}

	/**
	 * reset to default config
	 */
	void reset() 
	{
		callbacks.saveExtensionSetting(BurpExtender.extensionName, null);
		setDefaults();
	}

	/**
	 * save serialized Config object into Burp extension settings
	 */
	void save() 
	{
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		try 
		{
			ObjectOutputStream out = new ObjectOutputStream(bytes);
			out.writeObject(this);
		}
		catch (IOException e) 
		{
			stdErr.println(moduleName + ": Error saving configuration: " + e);
			return;
		}
		String encoded = Base64.getEncoder().encodeToString(bytes.toByteArray());
		callbacks.saveExtensionSetting(BurpExtender.extensionName, encoded);
	}

	/**
	 * set default values in Config properties
	 */
	private void setDefaults() 
	{
		databaseFilename = BurpExtender.extensionName + ".sqlite";
		loadHashAlgorithms();
	}

	void loadHashAlgorithms()
	{
		hashAlgorithms = new ArrayList<>();
		//As of now, we're always enabling all algorithms:
		hashAlgorithms.add(new HashAlgorithm(128, HashAlgorithmName.SHA_512, 6, true));
		hashAlgorithms.add(new HashAlgorithm(96, HashAlgorithmName.SHA_384, 5, true));
		hashAlgorithms.add(new HashAlgorithm(64, HashAlgorithmName.SHA_256, 4, true));
		hashAlgorithms.add(new HashAlgorithm(56, HashAlgorithmName.SHA_224, 3, true));
		hashAlgorithms.add(new HashAlgorithm(40, HashAlgorithmName.SHA_1, 2, true));
		hashAlgorithms.add(new HashAlgorithm(32, HashAlgorithmName.MD5, 1, true));
	}

	void toggleHashAlgorithm(HashAlgorithmName name, boolean enabled)
	{
		for (HashAlgorithm algo : hashAlgorithms)
		{
			if (algo.name.equals(name))
			{
				algo.enabled = enabled;
			}
		}
	}

	boolean isHashEnabled(HashAlgorithmName name)
	{		
		if (hashAlgorithms == null || hashAlgorithms.size() < 1) { 
			stdErr.println(moduleName + ": Hash algorithm configuration is missing or empty. Cannot check if " + name.toString() + " is enabled.");
			return false; 
		}
		for (HashAlgorithm algo: hashAlgorithms)
		{
			if (algo.name.equals(name))
			{
				return algo.enabled;
			}
		}
		return false;
	}

	int getHashId(HashAlgorithmName name)
	{
		for (HashAlgorithm algo : hashAlgorithms)
		{
			if (algo.name.equals(name))
			{
				return algo.id;
			}
		}
		return 0;
	}
}