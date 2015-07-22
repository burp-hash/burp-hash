package burp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.Serializable;
import java.util.Base64;

/**
 * Manages settings for the extension. It's crude, but it works. This object is serialized
 * and stored as a string using Burp's extension settings functionality.
 */
class Config implements Serializable {
	private static final long serialVersionUID = 1L;

	/**
	 * load saved config if it exists
	 * otherwise return default config
	 */
	public static Config load(BurpExtender b) throws Exception {
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
		cfg.stdOut.println("Successfully loaded settings.");
		return cfg;
	}

	private transient IBurpExtenderCallbacks callbacks;
	private transient PrintWriter stdErr;
	private transient PrintWriter stdOut;

	// variables below are the extension settings
	// TODO: convert the list below to use an EnumSet with the
	// <HashAlgorithmName> enum:
	public String databaseFilename;
	public boolean isMd5Enabled;
	public boolean isSha1Enabled;
	public boolean isSha224Enabled;
	public boolean isSha256Enabled;
	public boolean isSha384Enabled;
	public boolean isSha512Enabled;
	public boolean reportHashesOnly;

	/**
	 * constructor used only when saved config is not found
	 */
	private Config(BurpExtender b) {
		callbacks = b.getCallbacks();
		stdErr = b.getStdErr();
		stdOut = b.getStdOut();
		setDefaults();
		stdOut.println("No saved settings found - using defaults.");
	}

	/**
	 * reset to default config
	 */
	public void reset() {
		callbacks.saveExtensionSetting(BurpExtender.extensionName, null);
		setDefaults();
	}

	/**
	 * save serialized Config object into Burp extension settings
	 */
	public void save() {
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		try {
			ObjectOutputStream out = new ObjectOutputStream(bytes);
			out.writeObject(this);
		}
		catch (IOException e) {
			stdErr.println("Error saving configuration: " + e.getMessage());
			return;
		}
		String encoded = Base64.getEncoder().encodeToString(bytes.toByteArray());
		callbacks.saveExtensionSetting(BurpExtender.extensionName, encoded);
	}

	/**
	 * set default values in Config properties
	 */
	private void setDefaults() {
		isMd5Enabled = isSha1Enabled = isSha256Enabled = true;
		isSha224Enabled = isSha384Enabled = isSha512Enabled = reportHashesOnly = false;
		databaseFilename = BurpExtender.extensionName + ".db";
	}
}