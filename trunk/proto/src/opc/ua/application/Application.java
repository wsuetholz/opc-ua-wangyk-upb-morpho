package opc.ua.application;

/**
 * This class includes commen funciton for client and server
 */

public class Application{
	
	protected String applicationDescription = new String();
	
	protected String secretKey = new String();
	
	protected String certificate = new String();
	
	public Application()
	{
		String HostAddress = "127.0.0.1";
				
	}
	
	public String getApplicationDescription()
	{
		return applicationDescription;
	}
	
	public void setApplicationDescription(String des)
	{
		this.applicationDescription = des;
	}
	
	public String getSoftwareCertificates()
	{
		return certificate;
	}
	
	public void addSoftwareCertificate(String cert)
	{
		this.certificate = cert;		
	}
	
	public void removeSoftwareCertificate()
	{
		this.certificate = "";
	}
	
	public void setKey(String sKey)
	{
		this.secretKey = sKey ;
	}
}
