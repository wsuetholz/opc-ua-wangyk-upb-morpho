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

package org.opcfoundation.ua.transport.security;

import static org.opcfoundation.ua.utils.CertificateUtils.createThumbprint;
import static org.opcfoundation.ua.utils.CertificateUtils.decodeX509Certificate;
import static org.opcfoundation.ua.utils.CertificateUtils.encodeCertificate;
import static org.opcfoundation.ua.utils.CertificateUtils.readX509Certificate;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.StatusCodes;
import org.opcfoundation.ua.utils.CertificateUtils;
import org.opcfoundation.ua.utils.FileUtil;

/**
 * Cert is a X509 certificate that contains a public key.
 * The instance is valid and encodedable.
 * Wrapper to {@link java.security.cert.Certificate}.
 * <p>
 * To Create a new certificate See {@link CertificateUtils#generateKeyPair(String)}
 * 
 * @author Mikko Salonen
 * @author Toni Kalajainen (toni.kalajainen@iki.fi)
 */
public class Cert {

	public final X509Certificate certificate;
	public final byte[] encodedCertificate; 
	public final byte[] encodedCertificateThumbprint;
	
	/** 
	 * Load X.509 Certificate from an url
	 * 
	 * @param url
	 * @return Certificate
	 * @throws IOException 
	 */
	public static Cert load(URL url) 
	throws IOException
	{
		X509Certificate cert = readX509Certificate(url);
		return new Cert(cert);
	}
	
	/** 
	 * Load X.509 Certificate from a file
	 * 
	 * @param file
	 * @return Certificate
	 * @throws IOException 
	 */
	public static Cert load(File file) 
	throws IOException
	{
		return load(file.toURI().toURL());
	}
	
	public void save(File file)
	throws IOException
	{
		FileUtil.writeFile(file, encodedCertificate);
	}
	
	/**
	 * Create Certificate 
	 * 
	 * @param data encoded Certificate
	 * @throws ServiceResultException
	 */
	public Cert(byte[] data) 
	throws ServiceResultException
	{
		try {
			encodedCertificate = data;
			certificate = decodeX509Certificate(data);
			encodedCertificateThumbprint = createThumbprint(encodedCertificate);
		} catch (CertificateNotYetValidException ce) {
			throw new ServiceResultException(StatusCodes.Bad_CertificateTimeInvalid, ce);
		} catch (CertificateExpiredException ce) {
			throw new ServiceResultException(StatusCodes.Bad_CertificateTimeInvalid, ce);
		} catch (CertificateParsingException ce) {
			throw new ServiceResultException(StatusCodes.Bad_CertificateInvalid, ce);
		} catch (CertificateException ce) {
			throw new ServiceResultException(StatusCodes.Bad_CertificateInvalid, ce);
		}
	}
	
	public Cert(X509Certificate certificate)
	{
		encodedCertificate = encodeCertificate(certificate);
		this.certificate = certificate;
		encodedCertificateThumbprint = createThumbprint(encodedCertificate);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(encodedCertificate);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Cert other = (Cert) obj;
		if (!Arrays.equals(encodedCertificate, other.encodedCertificate))
			return false;
		return true;
	}

	public X509Certificate getCertificate() {
		return certificate;
	}

	public byte[] getEncoded() {
		return encodedCertificate;
	}
	
	public byte[] getEncodedThumbprint() {
		return encodedCertificateThumbprint;
	}
	
	@Override
	public String toString() {
		return certificate.toString();
	}
	
}
