package burp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.Serializable;
import java.util.Base64;

/**
 * Manages settings for the extension.
 * It's crude, but it works.
 */
class Config implements Serializable {
	private static final long serialVersionUID = 1L;
	private transient IBurpExtenderCallbacks callbacks;
	private transient PrintWriter stdErr;
	private transient PrintWriter stdOut;
	// variables below are the extension settings
	public boolean isMd5Enabled = true;
	public boolean isSha1Enabled = true;
	public boolean isSha224Enabled = false;
	public boolean isSha256Enabled = true;
	public boolean isSha384Enabled = false;
	public boolean isSha512Enabled = false;

	private Config(IBurpExtenderCallbacks c) {
		callbacks = c;
		stdErr = new PrintWriter(c.getStderr(), true);
		stdOut = new PrintWriter(c.getStdout(), true);
		stdOut.println("No saved settings found — using defaults.");
	}

	public static Config load(IBurpExtenderCallbacks c) throws Exception {
		String encodedConfig = c.loadExtensionSetting("burp-hash");
		if (encodedConfig == null) {
			return new Config(c);
		}
		byte[] decodedConfig = Base64.getDecoder().decode(encodedConfig);
		ByteArrayInputStream b = new ByteArrayInputStream(decodedConfig);
		ObjectInputStream in = new ObjectInputStream(b);
		Config cfg = (Config) in.readObject();
		cfg.callbacks = c;
		cfg.stdErr = new PrintWriter(c.getStderr(), true);
		cfg.stdOut = new PrintWriter(c.getStdout(), true);
		cfg.stdOut.println("Successfully loaded settings.");
		return cfg;
	}

	public void save() throws Exception {
		ByteArrayOutputStream b = new ByteArrayOutputStream();
		ObjectOutputStream out = new ObjectOutputStream(b);
		out.writeObject(this);
		String encoded = Base64.getEncoder().encodeToString(b.toByteArray());
		callbacks.saveExtensionSetting("burp-hash", encoded);
		stdOut.println("Successfully saved settings.");
	}
}