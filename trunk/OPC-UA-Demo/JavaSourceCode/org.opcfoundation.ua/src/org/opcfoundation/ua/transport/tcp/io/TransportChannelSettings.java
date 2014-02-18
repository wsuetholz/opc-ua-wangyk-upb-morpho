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

package org.opcfoundation.ua.transport.tcp.io;

import java.security.cert.X509Certificate;
import java.util.EnumSet;

import org.opcfoundation.ua.common.NamespaceTable;
import org.opcfoundation.ua.common.RuntimeServiceResultException;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.EndpointConfiguration;
import org.opcfoundation.ua.core.EndpointDescription;
import org.opcfoundation.ua.transport.security.Cert;
import org.opcfoundation.ua.transport.security.CertificateValidator;
import org.opcfoundation.ua.transport.security.PrivKey;

/**
 * Transport channel settings. These are common to binary and soap (?).
 */
public class TransportChannelSettings implements Cloneable {

	EndpointDescription description;
	EndpointConfiguration configuration;
	PrivKey privKey;
	Cert clientCertificate;
	CertificateValidator certificateValidator;
	NamespaceTable namespaceUris;
	EnumSet<Flag> flags = EnumSet.noneOf(Flag.class);
	
	public enum Flag {
		/**
		 * In multithread mode, depending on implementation, channels 
		 * encrypt & decrypt messages simultaneously in multiple threads.
		 * 
		 * This allows higher throughput in secured data intensive applications with 
		 * large messages.
		 */
		MultiThread
	}

	
	public TransportChannelSettings() {}
	
	public TransportChannelSettings(
			EndpointDescription description,
			EndpointConfiguration configuration,
			Cert clientCertificate,
			PrivKey privateKey,
			CertificateValidator certificateValidator,
			NamespaceTable namespaceUris, 
			EnumSet<Flag> flags) 
	throws RuntimeServiceResultException {
		super();
		setDescription(description);
		this.configuration = configuration;
		this.clientCertificate = clientCertificate;
		this.certificateValidator = certificateValidator;
		this.privKey = privateKey;
		this.namespaceUris = namespaceUris;
		this.flags = flags;
	}
	public EndpointDescription getDescription() {
		return description;
	}
	public void setDescription(EndpointDescription description) throws RuntimeServiceResultException {
		this.description = description;
	}
	public EndpointConfiguration getConfiguration() {
		return configuration;
	}
	public void setConfiguration(EndpointConfiguration configuration) {
		this.configuration = configuration;
	}
	public Cert getClientCertificate() {
		return clientCertificate;
	}
	public void setClientCertificate(X509Certificate clientCertificate) {
		this.clientCertificate = new Cert(clientCertificate);
	}
	public Cert getServerCertificate() {
		try {
			return (this.description!=null && this.description.getServerCertificate()!=null) ? new Cert(this.description.getServerCertificate()) : null;
		} catch (ServiceResultException e) {
			throw new RuntimeServiceResultException(e);
		} 			
	}
	public CertificateValidator getCertificateValidator() {
		return certificateValidator;
	}
	public void setCertificateValidator(CertificateValidator certificateValidator) {
		this.certificateValidator = certificateValidator;
	}
	public NamespaceTable getNamespaceUris() {
		return namespaceUris;
	}
	public void setNamespaceUris(NamespaceTable namespaceUris) {
		this.namespaceUris = namespaceUris;
	}

	public PrivKey getPrivKey() {
		return privKey;
	}

	public void setPrivKey(PrivKey privKey) {
		this.privKey = privKey;
	}

	public void setClientCertificate(Cert clientCertificate) {
		this.clientCertificate = clientCertificate;
	}

	public EnumSet<Flag> getFlags() {
		return flags;
	}

	public void setFlags(EnumSet<Flag> flags) {
		this.flags = flags;
	}

	@Override
	public TransportChannelSettings clone() {
		TransportChannelSettings result = new TransportChannelSettings();
		if (description!=null)
			result.setDescription(description.clone());
		if (configuration!=null)
			result.setConfiguration(configuration.clone());
		result.setClientCertificate(clientCertificate);
		result.setCertificateValidator(certificateValidator);
		result.setNamespaceUris(namespaceUris);
		result.setPrivKey(privKey);
		return result;
	}
		
}
