package transport;

import java.net.URI;
import java.util.Arrays;

import transport.security.SecurityMode;
import transport.security.SecurityPolicy;
import utils.ObjectUtils;

public class Endpoint {
	
	SecurityMode[] modes;
	String endpointUrl;
	
	private int hash;
	
	public Endpoint(URI endpointUrl, SecurityMode...modes)
	{
		if (modes == null || endpointUrl == null)
			throw new IllegalArgumentException("null args");
		for (SecurityMode m: modes){
			if (m == null) throw new IllegalArgumentException("null arg");
			hash = 13*hash + m.hashCode();
		}
		this.endpointUrl = endpointUrl.toString();
		this.modes = modes;
		hash = 13*hash + endpointUrl.hashCode();
	}
	
	public String getEndpointUrl()
	{
		return endpointUrl;
	}
	public SecurityMode[] getSecurityModes()
	{
		return modes;
	}
	public boolean supportsSecurityPolicy(SecurityPolicy policy)
	{
		for (SecurityMode m: modes)
			if (m.getSecurityPolicy().equals(policy)) return true;
		return false;
	}
	
	public int hashCode()
	{
		return hash;
	}
	
	public boolean equals(Object obj){
		if (! (obj instanceof Endpoint)) return false;
		Endpoint other = (Endpoint) obj;
		if (!ObjectUtils.objectEquals(other.getEndpointUrl(), getEndpointUrl())) return false;
		if(!Arrays.deepEquals(modes, other.modes)) return false;
		return true;
	}
	
	public String toString() {
		return endpointUrl+" "+Arrays.toString(modes);
	}
}

