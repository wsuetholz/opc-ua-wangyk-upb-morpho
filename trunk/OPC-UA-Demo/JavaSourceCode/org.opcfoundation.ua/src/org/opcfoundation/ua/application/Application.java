/* ========================================================================
 * Copyright (c) 2005-2010 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Reciprocal Community License ("RCL") Version 1.00
 * 
 * Unless explicitly acquired and licensed from Licensor under another 
 * license, the contents of this file are subject to the Reciprocal 
 * Community License ("RCL") Version 1.00, or subsequent versions as 
 * allowed by the RCL, and You may not copy or use this file in either 
 * source code or executable form, except in compliance with the terms and 
 * conditions of the RCL.
 * 
 * All software distributed under the RCL is provided strictly on an 
 * "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, 
 * AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT 
 * LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR 
 * PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RCL for specific 
 * language governing rights and limitations under the RCL.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/RCL/1.00/
 * ======================================================================*/

package org.opcfoundation.ua.application;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import org.opcfoundation.ua.builtintypes.LocalizedText;
import org.opcfoundation.ua.core.ApplicationDescription;
import org.opcfoundation.ua.core.SignedSoftwareCertificate;
import org.opcfoundation.ua.transport.security.KeyPair;

/**
 * This class contains the mechanisms that are commong for both client and server
 * application.
 * 
 * @see Client OPC UA Client Application
 * @see Server OPC UA Server Application
 */
public class Application {

	/** Application description */
	protected ApplicationDescription applicationDescription = new ApplicationDescription();
	
	/** Application Instance Certificates */
	protected List<KeyPair> applicationInstanceCertificates = new CopyOnWriteArrayList<KeyPair>();
	
	/** Software Certificates */
	protected List<SignedSoftwareCertificate> softwareCertificates = new CopyOnWriteArrayList<SignedSoftwareCertificate>();
	
	/** Locales */
	protected List<Locale> locales = new CopyOnWriteArrayList<Locale>();
	
	public Application(/*CertificatePrivateKeyPair applicationInstanceCertificate*/)
	{
//		System.out.println(applicationInstanceCertificate.getCertificate());
//		this.addApplicationInstanceCertificate(applicationInstanceCertificate);
//		X509Certificate cert = (X509Certificate) applicationInstanceCertificate.getCertificate().getCertificate();
//		cert.get
		
		// Create application name
		String publicHostname = "";
		try {
			publicHostname = InetAddress.getLocalHost().getHostName();
		} catch (UnknownHostException e) {
		}
		
		applicationDescription.setApplicationUri( "urn:"+publicHostname+":"+UUID.randomUUID() );	
	}
	
	public ApplicationDescription getApplicationDescription()
	{
		return applicationDescription;
	}
	
	public SignedSoftwareCertificate[] getSoftwareCertificates()
	{
		return softwareCertificates.toArray( new SignedSoftwareCertificate[softwareCertificates.size()] );
	}
	
	public void addSoftwareCertificate(SignedSoftwareCertificate cert)
	{
		if (cert==null) throw new IllegalArgumentException("null arg");
		softwareCertificates.add(cert);
	}
	
	public KeyPair[] getApplicationInstanceCertificates()
	{
		return applicationInstanceCertificates.toArray( new KeyPair[applicationInstanceCertificates.size()] );
	}
	
	public void addApplicationInstanceCertificate(KeyPair cert)
	{
		if (cert==null) throw new IllegalArgumentException("null arg");
		applicationInstanceCertificates.add(cert);
	}

	public void removeApplicationInstanceCertificate(KeyPair applicationInstanceCertificate)
	{
		applicationInstanceCertificates.remove( applicationInstanceCertificate );
	}

	public KeyPair getApplicationInstanceCertificate(byte[] thumb) 
	{
		for (KeyPair cert : applicationInstanceCertificates)
			if ( Arrays.equals( cert.getCertificate().getEncodedThumbprint(), thumb ) )
				return cert;
		return null;
	}
		
	public KeyPair getApplicationInstanceCertificate()
	{
		final int index = applicationInstanceCertificates.size()-1;
		if (index < 0)
			return null;
		return applicationInstanceCertificates.get(index);
	}
	
	public String getApplicationUri()
	{
		return applicationDescription.getApplicationUri();
	}
	
	public void setApplicationUri(String applicationUri)
	{
		applicationDescription.setApplicationUri(applicationUri);
	}

	public void setApplicationName(LocalizedText applicationName)
	{
		applicationDescription.setApplicationName(applicationName);
	}

	public String getProductUri() 
	{
		return applicationDescription.getProductUri();
	}

	public void setProductUri(String productUri) 
	{
		applicationDescription.setProductUri( productUri );
	}
	
	public void addLocale(Locale locale)
	{
		if (locale==null)
			throw new IllegalArgumentException("null arg");
		locales.add(locale);
	}
	
	public void removeLocale(Locale locale)
	{
		locales.remove(locale);
	}
	
	public Locale[] getLocales()
	{
		return locales.toArray( new Locale[0] );
	}
	
	public String[] getLocaleIds()
	{
		ArrayList<String> result = new ArrayList<String>(locales.size());
		for (Locale l : locales)
			result.add( LocalizedText.toLocaleId(l) );
		return result.toArray( new String[ result.size() ] );
	}
	
}
