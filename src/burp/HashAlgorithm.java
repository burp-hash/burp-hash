package burp;

import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class HashAlgorithm
{
	public int charWidth;
	public HashAlgorithmName name;
	public Pattern pattern;
	private static final String hexRegex = "([a-fA-F0-9]{%s})";
	
	public HashAlgorithm(int charWidth, HashAlgorithmName name)
	{
		this.charWidth = charWidth;
		this.name = name;
		this.pattern = Pattern.compile(String.format(hexRegex, charWidth));
	}
}