package burp;

import java.util.ArrayList;
import java.util.List;

/**
 * Stores parameters and a list of their {@link ParameterHash}es.
 */
class Parameter
{
	String name = "", value = "";
	List<ParameterHash> parameterHashes = new ArrayList<>();
}
