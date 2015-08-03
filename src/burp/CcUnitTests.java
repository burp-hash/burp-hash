package burp;

import static org.junit.Assert.*;

import java.util.regex.Matcher;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class CcUnitTests {

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void test() {
		fail("Not yet implemented");
	}
	
	BurpExtender burpExtender = new BurpExtender();
	
	@Test
	public void emailregex0()
	{
		String req = "&CC=4929001695946994&cvv=123";
		Matcher matcher = burpExtender.ccRegex.matcher(req);
		assertTrue(matcher.find() && matcher.group().equals("4929001695946994"));
	}

	@Test
	public void emailregex1()
	{
		String req = "{\"cc\":\"4929001695946994\"}";
		Matcher matcher = burpExtender.ccRegex.matcher(req);
		assertTrue(matcher.find() && matcher.group().equals("4929001695946994"));
	}

	@Test
	public void emailregex2()
	{
		String req = "{cc:4929001695946994}";
		Matcher matcher = burpExtender.ccRegex.matcher(req);
		assertTrue(matcher.find() && matcher.group().equals("4929001695946994"));
	}
	
	@Test
	public void emailregex3()
	{
		String req = "&CC=5493144048785645&cvv=123";
		Matcher matcher = burpExtender.ccRegex.matcher(req);
		assertTrue(matcher.find() && matcher.group().equals("5493144048785645"));
	}
	
	@Test
	public void emailregex4()
	{
		String req = "&CC=5493-1440-4878-5645&cvv=123";
		Matcher matcher = burpExtender.ccRegex.matcher(req);
		assertTrue(matcher.find() && matcher.group().equals("5493-1440-4878-5645"));
	}
}
