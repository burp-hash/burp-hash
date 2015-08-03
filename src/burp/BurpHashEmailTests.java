package burp;

import static org.junit.Assert.*;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.net.URLDecoder;
import java.util.ArrayList;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class BurpHashEmailTests 
{
	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testJunitIsWorking() {
		String str= "Junit is working fine";
		assertEquals("Junit is working fine",str);
	}
	
	@Test
	public void emailregex0()
	{
		String email = "joe@example.com";
		Matcher matcher = burpExtender.emailRegex.matcher(email);
		assertTrue(matcher.find() && matcher.group().equals("joe@example.com"));
	}

	
	@Test
	public void emailregex1()
	{
		String email = "&email=joe@example.com&";
		Matcher matcher = burpExtender.emailRegex.matcher(email);
		assertTrue(matcher.find() && matcher.group().equals("joe@example.com"));
	}

	@Test
	public void emailregex2()
	{
		String email = "{\"email\":\"foo@bar.com\"}";
		Matcher matcher = burpExtender.emailRegex.matcher(email);
		assertTrue(matcher.find() && matcher.group().equals("foo@bar.com"));
	}
	
	@Test
	public void emailregex3()
	{
		String email = "{\"email\":\"foo-foo@bar-bar.com\"}";
		Matcher matcher = burpExtender.emailRegex.matcher(email);
		assertTrue(matcher.find() && matcher.group().equals("foo-foo@bar-bar.com"));
	}
	
	@Test
	public void emailregex4()
	{
		String email = "{\"email\":\"foo.foo@bar.bar.com\"}";
		Matcher matcher = burpExtender.emailRegex.matcher(email);
		assertTrue(matcher.find() && matcher.group().equals("foo.foo@bar.bar.com"));
	}
	
	@Test
	public void emailregex5()
	{
		String email = "{email:foo-bar@yo-domain.com}";
		Matcher matcher = burpExtender.emailRegex.matcher(email);
		assertTrue(matcher.find() && matcher.group().equals("foo-bar@yo-domain.com"));
	}
	
	@Test
	public void emailregex6()
	{
		String email = "foo=joe.smith@somewhere.cc&this=not_yours;";
		Matcher matcher = burpExtender.emailRegex.matcher(email);
		assertTrue(matcher.find() && matcher.group().equals("joe.smith@somewhere.cc"));
	}

	@Test
	public void emailregex7()
	{
		String email = "foo=;asdf-asdf@gmail.com;";
		Matcher matcher = burpExtender.emailRegex.matcher(email);
		assertTrue(matcher.find() && matcher.group().equals("asdf-asdf@gmail.com"));
	}
	
	@Test
	public void emailregex8()
	{
		String email = "foo=;asdf-asdf%40gmail.com;";
		Matcher matcher = burpExtender.emailRegex.matcher(URLDecoder.decode(email));
		assertTrue(matcher.find() && matcher.group().equals("asdf-asdf@gmail.com"));
	}
	
	@Test
	public void emailregex9()
	{
		String email = "&email=joe@joe.com&acceptTerms=true";
		Matcher matcher = burpExtender.emailRegex.matcher(URLDecoder.decode(email));
		matcher.find();
		String result = matcher.group();
		assertTrue(result.equals("joe@joe.com&acceptterms"));
		result = result.split("&")[0];
		//assertTrue(result.equals("joe@joe.com"));
	}

	
	BurpExtender burpExtender = new BurpExtender();
	
	String requestWithUrlEncodedEmail = "POST /blog/forgot2 HTTP/1.1\r\n" +
		"Host: 192.168.13.216:999\r\n" +
		"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:39.0) Gecko/20100101 Firefox/39.0\r\n" +
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n" +
		"Accept-Language: en-US,en;q=0.5\r\n" +
		"Accept-Encoding: gzip, deflate\r\n" +
		"Referer: http://192.168.13.216:999/blog/reset\r\n" +
		"Cookie: csrftoken=5865246ded13f3543adef0a39ed494b3\r\n" +
		"Connection: keep-alive\r\n" + 
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: 87\r\n" +
		"\r\n" +
		"csrfmiddlewaretoken=5865246ded13f3543adef0a39ed494b3&email=joe%40joe.com&acceptTerms=on\r\n"; 
	
	@Test
	public void FindEmail_urlEncoded_returnsEmptyCollection()
	{
		List<Item> items = new ArrayList<>();
		items.addAll(burpExtender.findEmailRegex(requestWithUrlEncodedEmail));
		assertTrue(items.isEmpty());
	}
	
	@Test
	public void FindEmail_urlDecoded_returnsNonEmptyCollection()
	{
		List<Item> items = new ArrayList<>();
		String urlDecoded = URLDecoder.decode(requestWithUrlEncodedEmail);
		items.addAll(burpExtender.findEmailRegex(urlDecoded));
		assertFalse(items.isEmpty());
	}
	
	
	@Test
	public void FindEmail_returnsExpectedEmail()
	{
		List<Item> items = new ArrayList<>();
		String urlDecoded = URLDecoder.decode(requestWithUrlEncodedEmail);
		items.addAll(burpExtender.findEmailRegex(urlDecoded));
		String expected = "joe@joe.com";
		String actual = items.get(0).getValue();
		assertTrue(expected.equals(actual));
	}

}
