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

import java.nio.charset.Charset;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.StatusCodes;
import org.opcfoundation.ua.utils.CryptoUtil;
import org.opcfoundation.ua.utils.ObjectUtils;

/**
 * Security Policy determines which algorithms to use during asymmetric and symmetric
 * encryption.   
 * 
 * @see CryptoUtil for instantiating cryptographics objects
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi)
 * @author Mikko Salonen
 */
public final class SecurityPolicy {

	private static final Charset UTF8 = Charset.forName("utf-8");
	
	// Global Well known Security policies //  	
	public static final SecurityPolicy NONE = new SecurityPolicy(
			SecurityConstants.SECURITY_POLICY_URI_BINARY_NONE,
			null,
			null,
			null,
			null,
			null,
			null,
			0);
	
	public static final SecurityPolicy BASIC128RSA15 = new SecurityPolicy(
			SecurityConstants.SECURITY_POLICY_URI_BINARY_BASIC128RSA15,
			SecurityConstants.HmacSha1, // Symmetric signature 
			SecurityConstants.Aes128,   // Symmetric encryption
			SecurityConstants.RsaSha1,  // Asymmetric signature
			SecurityConstants.KwRsa15,  // Asymmetric keywrap
			SecurityConstants.Rsa15,    // Asymmetric encryption
			SecurityConstants.PSha1,    // key derivation
			128);
	
	public static final SecurityPolicy BASIC256 = new SecurityPolicy(
			SecurityConstants.SECURITY_POLICY_URI_BINARY_BASIC256,
			SecurityConstants.HmacSha1, // Symmetric signature
			SecurityConstants.Aes256,   // Symmetric encryption
			SecurityConstants.RsaSha1,  // Asymmetric signature
			SecurityConstants.KwRsaOaep,// Asymmetric keywrap
			SecurityConstants.RsaOaep,  // Asymmetric encryption
			SecurityConstants.PSha1,    // key derivation
			192);	

	/** Security policy map */
	private static Map<String, SecurityPolicy> policies = Collections.synchronizedMap( new HashMap<String, SecurityPolicy>() );

	/**
	 * Add new security policy to stack
	 * @param policy
	 */
	public static void addSecurityPolicy(SecurityPolicy policy)
	{
		policies.put(policy.policyUri, policy);
	}

	static {
		addSecurityPolicy(NONE);
		addSecurityPolicy(BASIC128RSA15);
		addSecurityPolicy(BASIC256);
	}
	
	/**
	 * Get security policy by policy uri
	 * 
	 * @param securityPolicyUri security policy uri
	 * @return security policy
	 * @throws ServiceResultException Bad_SecurityPolicyRejected if policy is unknown
	 */
	public static SecurityPolicy getSecurityPolicy(String securityPolicyUri)
	throws ServiceResultException
	{		
		if (securityPolicyUri == null) return NONE;
		SecurityPolicy result = policies.get(securityPolicyUri);
		if (result == null)
			throw new ServiceResultException( StatusCodes.Bad_SecurityPolicyRejected ); 
		return result;  
		
	}
	
	/**
	 * Get all security policies supported by the stack
	 * 
	 * @return security policies
	 */
	public static SecurityPolicy[] getAllSecurityPolicies()
	{
		return policies.values().toArray(new SecurityPolicy[policies.size()]);
	}

	private final String policyUri;
	private final String symmetricSignatureAlgorithmUri;
	private final String symmetricEncryptionAlgorithmUri;
	private final String asymmetricSignatureAlgorithmUri;
	private final String asymmetricKeyWrapAlgorithmUri;
	private final String asymmetricEncryptionAlgorithmUri;
	private final String keyDerivationAlgorithmUri;
	private final int derivedSignatureKeyLength;
	private final byte[] encodedPolicyUri;
	private int hash;
	
	SecurityPolicy(
			String policyUri,
			String symmetricSignatureAlgorithmUri,
			String symmetricEncryptionAlgorithmUri,
			String asymmetricSignatureAlgorithmUri,
			String asymmetricKeyWrapAlgorithmUri,
			String asymmetricEncryptionAlgorithmUri,
			String keyDerivationAlgorithmUri,
			int derivedSignatureKeyLength 
			) {
		this.asymmetricEncryptionAlgorithmUri = asymmetricEncryptionAlgorithmUri;
		this.asymmetricKeyWrapAlgorithmUri = asymmetricKeyWrapAlgorithmUri;
		this.asymmetricSignatureAlgorithmUri = asymmetricSignatureAlgorithmUri;
		this.derivedSignatureKeyLength = derivedSignatureKeyLength;
		this.keyDerivationAlgorithmUri = keyDerivationAlgorithmUri;
		this.policyUri = policyUri;
		this.symmetricEncryptionAlgorithmUri = symmetricEncryptionAlgorithmUri;
		this.symmetricSignatureAlgorithmUri = symmetricSignatureAlgorithmUri;
		this.encodedPolicyUri = policyUri.getBytes(UTF8);
		
		hash = policyUri.hashCode();
		if (asymmetricEncryptionAlgorithmUri!=null) hash = 7*hash + asymmetricEncryptionAlgorithmUri.hashCode(); 
		if (asymmetricKeyWrapAlgorithmUri!=null) hash = 7*hash + asymmetricKeyWrapAlgorithmUri.hashCode(); 
		if (asymmetricSignatureAlgorithmUri!=null) hash = 7*hash + asymmetricSignatureAlgorithmUri.hashCode(); 
		if (keyDerivationAlgorithmUri!=null) hash = 7*hash + keyDerivationAlgorithmUri.hashCode(); 
		if (symmetricEncryptionAlgorithmUri!=null) hash = 7*hash + symmetricEncryptionAlgorithmUri.hashCode(); 
		if (symmetricSignatureAlgorithmUri!=null) hash = 7*hash + symmetricSignatureAlgorithmUri.hashCode(); 
	}

	@Override
	public int hashCode() {
		return hash;
	}
	
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof SecurityPolicy)) return false;
		SecurityPolicy other = (SecurityPolicy) obj;
		
		if (!ObjectUtils.objectEquals(policyUri, other.policyUri)) return false;
		if (!ObjectUtils.objectEquals(asymmetricEncryptionAlgorithmUri, other.asymmetricEncryptionAlgorithmUri)) return false;
		if (!ObjectUtils.objectEquals(asymmetricKeyWrapAlgorithmUri, other.asymmetricKeyWrapAlgorithmUri)) return false;
		if (!ObjectUtils.objectEquals(asymmetricSignatureAlgorithmUri, other.asymmetricSignatureAlgorithmUri)) return false;
		if (!ObjectUtils.objectEquals(keyDerivationAlgorithmUri, other.keyDerivationAlgorithmUri)) return false;
		if (!ObjectUtils.objectEquals(symmetricEncryptionAlgorithmUri, other.symmetricEncryptionAlgorithmUri)) return false;
		if (!ObjectUtils.objectEquals(symmetricSignatureAlgorithmUri, other.symmetricSignatureAlgorithmUri)) return false;
		
		return true;
	}
	
	@Override
	public String toString() {
		return policyUri;
	}
	
	public String getPolicyUri() {
		return policyUri;
	}

	public String getSymmetricSignatureAlgorithmUri() {
		return symmetricSignatureAlgorithmUri;
	}

	public String getSymmetricEncryptionAlgorithmUri() {
		return symmetricEncryptionAlgorithmUri;
	}

	public String getAsymmetricSignatureAlgorithmUri() {
		return asymmetricSignatureAlgorithmUri;
	}

	public String getAsymmetricKeyWrapAlgorithmUri() {
		return asymmetricKeyWrapAlgorithmUri;
	}

	public String getAsymmetricEncryptionAlgorithmUri() {
		return asymmetricEncryptionAlgorithmUri;
	}

	public String getKeyDerivationAlgorithmUri() {
		return keyDerivationAlgorithmUri;
	}

	public int getDerivedSignatureKeyLength() {
		return derivedSignatureKeyLength;
	}

	public byte[] getEncodedPolicyUri() {
		return encodedPolicyUri;
	}
	
	
}
