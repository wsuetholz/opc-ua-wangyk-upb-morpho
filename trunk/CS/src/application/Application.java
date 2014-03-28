package application;

import java.net.InetAddress;
import java.net.UnknownHostException;


import core.SignedSoftwareCertificate;

/** application class that fits for both client and server
 * 
 * @author G511284
 *
 */

public class Application {
	
	protected String applicationDescription;
	protected SignedSoftwareCertificate softwareCertificates = new SignedSoftwareCertificate();
	
	
	public Application()
	{
		String publicHostname = "";
		try{
			publicHostname = InetAddress.getLocalHost().getHostName();
		}catch(UnknownHostException e){
			
		}
		
	}
	public void setApplicationDescription(String input)
	{
		this.applicationDescription = input;
	}
	public String getApplicationDescription()
	{
		return applicationDescription;
	}
	public void setSoftewareCertificate(byte[] cert, byte[] sig)
	{
		softwareCertificates.setSoftwareCertificate(cert, sig);
	}
	
	public byte[] getSoftwareCertificates()
	{
		return softwareCertificates.getCertificate();
	}
	public byte[] getSotewareSignature()
	{
		return softwareCertificates.getSignature();
	}
	
}
