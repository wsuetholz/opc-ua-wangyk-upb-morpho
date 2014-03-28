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

package transport.security;

import core.MessageSecurityMode;

/**
 * Binding of {@link SecurityPolicy} and {@link MessageSecurityMode}.
 * <p>
 * Security Policy determines which algorithms to use during asymmetric and symmetric
 * encryption.   
 * <p>
 * MessageSecurityMode determines wheter to use encryption and wether to use signing
 * during _symmetric_ encryption, which is after hand-shake. 
 * 
 * @author Toni Kalajainen (toni.kalajainen@iki.fi)
 */
public final class SecurityMode {
		
	// Secure Security Modes
	public final static SecurityMode BASIC128RSA15_SIGN_ENCRYPT = new SecurityMode(SecurityPolicy.BASIC128RSA15, MessageSecurityMode.SignAndEncrypt);
	public final static SecurityMode BASIC128RSA15_SIGN = new SecurityMode(SecurityPolicy.BASIC128RSA15, MessageSecurityMode.Sign);
	public final static SecurityMode BASIC256_SIGN_ENCRYPT = new SecurityMode(SecurityPolicy.BASIC256, MessageSecurityMode.SignAndEncrypt);
	public final static SecurityMode BASIC256_SIGN = new SecurityMode(SecurityPolicy.BASIC256, MessageSecurityMode.Sign);

	// Unsecure Security Mode
	public final static SecurityMode NONE = new SecurityMode(SecurityPolicy.NONE, MessageSecurityMode.None);
	
	// Secure hand-shake, unsecure transmission, quite useless combinations 
	public final static SecurityMode BASIC128RSA15_NO_ENCRYPTION = new SecurityMode(SecurityPolicy.BASIC128RSA15, MessageSecurityMode.Sign);
	public final static SecurityMode BASIC256_NO_ENCRYPTION = new SecurityMode(SecurityPolicy.BASIC256, MessageSecurityMode.Sign);

	// Completely useless combinations
	public final static SecurityMode NONE_SIGN = new SecurityMode(SecurityPolicy.NONE, MessageSecurityMode.Sign);
	public final static SecurityMode NONE_SIGN_ENCRYPT = new SecurityMode(SecurityPolicy.NONE, MessageSecurityMode.SignAndEncrypt);
	
	// Security Mode Sets
	public final static SecurityMode[] ALL = new SecurityMode[] {NONE, BASIC128RSA15_SIGN_ENCRYPT, BASIC128RSA15_SIGN, BASIC256_SIGN_ENCRYPT, BASIC256_SIGN, BASIC128RSA15_NO_ENCRYPTION, BASIC256_NO_ENCRYPTION}; 
	public final static SecurityMode[] SECURE = new SecurityMode[] {BASIC128RSA15_SIGN_ENCRYPT, BASIC128RSA15_SIGN, BASIC256_SIGN_ENCRYPT, BASIC256_SIGN}; 
	public final static SecurityMode[] NON_SECURE = new SecurityMode[] {NONE, BASIC128RSA15_NO_ENCRYPTION, BASIC256_NO_ENCRYPTION}; 	
	
	public final SecurityPolicy securityPolicy;
	public final MessageSecurityMode messageSecurityMode;
		
	public SecurityMode(SecurityPolicy securityPolicy, MessageSecurityMode messageSecurityMode) {
		if (securityPolicy==null || messageSecurityMode==null) 
			throw new IllegalArgumentException("null arg");
		this.securityPolicy = securityPolicy;
		this.messageSecurityMode = messageSecurityMode;
	}
	
	public SecurityPolicy getSecurityPolicy() {
		return securityPolicy;
	}
	
	public MessageSecurityMode getMessageSecurityMode() {
		return messageSecurityMode;
	}
	
	@Override
	public int hashCode() {
		return securityPolicy.hashCode() ^ messageSecurityMode.hashCode();
	}
	
	@Override
	public boolean equals(Object obj) {
		if (!(obj instanceof SecurityMode)) return false;
		SecurityMode other = (SecurityMode) obj;
		return other.securityPolicy == securityPolicy && other.messageSecurityMode == messageSecurityMode;
	}

	@Override
	public String toString() {
		return "["+securityPolicy.getPolicyUri()+","+messageSecurityMode+"]";
	}
	
}
