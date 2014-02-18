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

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;

import org.opcfoundation.ua.utils.CertificateUtils;
import org.opcfoundation.ua.utils.FileUtil;

import static org.opcfoundation.ua.utils.CertificateUtils.*;

/**
 * Valid and encodeable private key.
 * Wrapper to {@link java.security.PrivateKey}
 * 
 * @author Mikko Salonen
 * @author Toni Kalajainen (toni.kalajainen@iki.fi)
 */
public class PrivKey {

	public final RSAPrivateKey privateKey;
	public final byte[] encodedPrivateKey;
	
	/**
	 * Load private key from a key store
	 * 
	 * @param keystoreUrl url to key store
	 * @param password password to key store
	 * @return private key
	 * @throws IOException
	 */
	public static PrivKey loadFromKeyStore(URL keystoreUrl, String password) throws IOException
	{
		RSAPrivateKey key = CertificateUtils.loadFromKeyStore(keystoreUrl, password);
		return new PrivKey(key);
	}	
	
	/**
	 * Load private key from a file
	 * 
	 * @param url key file
	 * @return private key
	 * @throws IOException
	 * @throws InvalidKeySpecException 
	 */
	public static PrivKey load(URL url) throws IOException, InvalidKeySpecException
	{
		byte[] encoded = FileUtil.readFile(url);
		return new PrivKey( encoded );
	}	

	public static PrivKey load(File file) throws IOException, InvalidKeySpecException
	{
		byte[] encoded = FileUtil.readFile(file);
		return new PrivKey( encoded );
	}	
	
	/**
	 * Load private key from a file
	 * 
	 * @param file key store file
	 * @param password password to key store
	 * @return private key
	 * @throws IOException
	 */
	public static PrivKey loadFromKeyStore(File file, String password) throws IOException
	{
		return loadFromKeyStore( file.toURI().toURL(), password );
	}
	
	public void save(File file)
	throws IOException
	{
		FileUtil.writeFile(file, encodedPrivateKey);
	}

	public PrivKey(byte[] encodedPrivateKey) 
	throws IOException, InvalidKeySpecException
	{
		if (encodedPrivateKey==null) throw new IllegalArgumentException("null arg");
		this.encodedPrivateKey = encodedPrivateKey;
		this.privateKey = decodeRSAPrivateKey(encodedPrivateKey);
	}

	public PrivKey(RSAPrivateKey privateKey)
	{
		this.privateKey = privateKey;
		encodedPrivateKey = encodePrivateKey(privateKey);
	}
	
	public byte[] getEncodedPrivateKey() 
	{
		return encodedPrivateKey;
	}
	
	public RSAPrivateKey getPrivateKey()
	{
		return privateKey;
	}
	
}
