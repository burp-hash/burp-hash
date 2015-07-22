package burp;

import java.util.ArrayList;
import java.util.List;

/**
 * Stores parameters and a list of their {@link ParameterHash}es.
 */
public class Parameter
{
	public String name = "", value = "";
	public List<ParameterHash> parameterHashes = new ArrayList<ParameterHash>();	
}
