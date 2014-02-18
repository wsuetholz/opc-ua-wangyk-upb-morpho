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

package org.opcfoundation.ua.utils;

import java.lang.reflect.Array;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.AnonymousIdentityToken;
import org.opcfoundation.ua.core.EndpointDescription;
import org.opcfoundation.ua.core.IssuedIdentityToken;
import org.opcfoundation.ua.core.MessageSecurityMode;
import org.opcfoundation.ua.core.StatusCodes;
import org.opcfoundation.ua.core.UserIdentityToken;
import org.opcfoundation.ua.core.UserNameIdentityToken;
import org.opcfoundation.ua.core.UserTokenPolicy;
import org.opcfoundation.ua.core.UserTokenType;
import org.opcfoundation.ua.encoding.binary.BinaryEncoder;
import org.opcfoundation.ua.transport.security.Cert;
import org.opcfoundation.ua.transport.security.SecurityConstants;
import org.opcfoundation.ua.transport.security.SecurityPolicy;
import org.opcfoundation.ua.utils.bytebuffer.ByteBufferUtils;


/**
 * Discovery client enumerates endpoints.
 * Current version supports only opc.tcp protocol. 
 * 
 * @author Toni Kalajainen (toni.kalajainen@iki.fi)
 */
public class EndpointUtil {

	
	
	/**
	 * Select an endpoint that is supported by the stack and has
	 * the highest security level.
	 * 
	 * @param endpoints
	 * @return encrypted endpoint
	 * @throws ServiceResultException error
	 */
	public static EndpointDescription select(EndpointDescription[] endpoints)
	throws ServiceResultException
	{
		// Filter out all but opc.tcp protocol endpoints
		endpoints = EndpointUtil.selectByProtocol(endpoints, "opc.tcp");
		// Filter out all but Signed & Encrypted endpoints
		endpoints = EndpointUtil.selectByMessageSecurityMode(endpoints, MessageSecurityMode.SignAndEncrypt);
		// 
		if (endpoints.length==0) throw new ServiceResultException("No compatible endpoint was found");
		// Sort endpoints by security level. The lowest level at the beginning, the highest at the end of the array
		endpoints = EndpointUtil.sortBySecurityLevel(endpoints);
		// Choose one endpoint
		EndpointUtil.reverse(endpoints);
		return endpoints[0];
	}
	
	/**
	 * Filter endpoints by various criteria
	 * 
	 * @param searchSet set of endpoints 
	 * @param url filter by url (inclusive, case insensitive) or null
	 * @param protocol filter by protocol (inclusive) or null
	 * @param mode filter by mode or null
	 * @param policy filter by policy or null
	 * @return filtered endpoints
	 */
	public static EndpointDescription[] select(EndpointDescription[] searchSet, String url, String protocol, MessageSecurityMode mode, SecurityPolicy policy, byte[] serverCertificate)
	{
		List<EndpointDescription> result = new ArrayList<EndpointDescription>();
		for (EndpointDescription d : searchSet) {
			if (protocol!=null && !d.getEndpointUrl().toLowerCase().startsWith(protocol.toLowerCase())) continue;
			if (url!=null && !ObjectUtils.objectEquals(d.getEndpointUrl().toLowerCase(), url.toLowerCase())) continue;
			if (mode!=null && !ObjectUtils.objectEquals(d.getSecurityMode(), mode)) continue;
			if (policy!=null && !ObjectUtils.objectEquals(d.getSecurityPolicyUri(), policy.getPolicyUri())) continue;
			if (serverCertificate!=null && !Arrays.equals(serverCertificate, d.getServerCertificate())) continue;
			result.add(d);
		}
		return result.toArray(new EndpointDescription[result.size()]);		
	}
	
	/**
	 * Selects all endpoints that conform to given protcol
	 * 
	 * @param searchSet
	 * @param protocol
	 * @return A subset of searchSet whose elements use given protocol 
	 */
	public static EndpointDescription[] selectByProtocol(EndpointDescription[] searchSet, String protocol)
	{
		List<EndpointDescription> result = new ArrayList<EndpointDescription>();
		for (EndpointDescription d : searchSet)
			if (d.getEndpointUrl().toLowerCase().startsWith(protocol.toLowerCase()))
				result.add(d);
		return result.toArray(new EndpointDescription[result.size()]);
	}

	/**
	 * Selects all endpoints that conform to given message security mode
	 * 
	 * @param searchSet
	 * @param mode
	 * @return A subset of searchSet whose elements use given message security mode
	 */
	public static EndpointDescription[] selectByMessageSecurityMode(EndpointDescription[] searchSet, MessageSecurityMode mode)
	{
		List<EndpointDescription> result = new ArrayList<EndpointDescription>();
		for (EndpointDescription d : searchSet)
			if (d.getSecurityMode() == mode)
				result.add(d);
		return result.toArray(new EndpointDescription[result.size()]);
	}
	
	/**
	 * Selects all endpoints that conform to given message security mode
	 * 
	 * @param searchSet
	 * @param policy
	 * @return A subset of searchSet whose elements use given message security mode
	 */
	public static EndpointDescription[] selectBySecurityPolicy(EndpointDescription[] searchSet, SecurityPolicy policy)
	{
		List<EndpointDescription> result = new ArrayList<EndpointDescription>();
		for (EndpointDescription d : searchSet)
			if (ObjectUtils.objectEquals( d.getSecurityPolicyUri(), policy.getPolicyUri() ) )
				result.add(d);
		return result.toArray(new EndpointDescription[result.size()]);
	}
	
	/**
	 * Selects all endpoints with the given url. Compare is case-insensitive.
	 * 
	 * @param searchSet an array of urls
	 * @param url
	 * @return A subset of searchSet whose elements use given message security mode
	 */
	public static EndpointDescription[] selectByUrl(EndpointDescription[] searchSet, String url)
	{
		List<EndpointDescription> result = new ArrayList<EndpointDescription>();
		for (EndpointDescription d : searchSet)
			if (url.equalsIgnoreCase(d.getEndpointUrl()))
				result.add(d);
		return result.toArray(new EndpointDescription[result.size()]);
	}	

	/**
	 * Sorts endpoints by their security level. The highest security level last.
	 * 
	 * @param set set of endpoints
	 * @return sorted array of endpoints
	 */
	public static EndpointDescription[] sortBySecurityLevel(EndpointDescription[] set)
	{
		Comparator<EndpointDescription> securityLevelComparator = new Comparator<EndpointDescription>() {
			public int compare(EndpointDescription o1, EndpointDescription o2) {
				return o1.getSecurityLevel().intValue() - o2.getSecurityLevel().intValue();
			}}; 
		EndpointDescription[] result = set.clone();
		Arrays.sort(result, securityLevelComparator);
		return result;
	}
	
	/**
	 * Select the most suitable endpoint.
	 * <p>
	 * Selection uses the following precedence:
	 *   1) Protocol must be opc.tcp (as http is not implemented)
	 *   2) Security uses sign & encrypt
	 *   3) Select highest security level (determined by the server)
	 *   4) Prefer hostname over localhost 
	 * 
	 * @param endpoints
	 * @return compatible endpoint or null 
	 */
	public static EndpointDescription selectEndpoint(EndpointDescription[] endpoints)
	{
		if (endpoints==null) 
			throw new IllegalArgumentException("null arg");
		// Filter out all but opc.tcp protocol endpoints
		endpoints = EndpointUtil.selectByProtocol(endpoints, "opc.tcp");
		// Filter out all but Signed & Encrypted endpoints
		endpoints = EndpointUtil.selectByMessageSecurityMode(endpoints, MessageSecurityMode.SignAndEncrypt);
		// 
		if (endpoints.length==0) return null;
		// Sort endpoints by security level. The lowest level at the beginning, the highest at the end of the array
		endpoints = EndpointUtil.sortBySecurityLevel(endpoints);
		EndpointUtil.reverse(endpoints);
		return endpoints[0]; 		
	}
	
	/**
	 * Reverse elements of an array
	 * @param array
	 */
	public static void reverse(Object array) {
		int length = Array.getLength(array);
		for (int i=0; i<length/2; i++) {
			Object x = Array.get(array, i);
			Object y = Array.get(array, length-1-i);
			Array.set(array, i, y);
			Array.set(array, length-i-1, x);
		}
	}
		
	/**
	 * Create user identity token based on username and password
	 * 
	 * @param ep
	 * @param username
	 * @param password
	 * @return user identity token 
	 * @throws ServiceResultException if endpoint or the stack doesn't support UserName token policy
	 */
	public static UserIdentityToken createUserNameIdentityToken(EndpointDescription ep, byte[] senderNonce, String username, String password)	
	throws ServiceResultException
	{
		UserTokenPolicy policy = ep.findUserTokenPolicy(UserTokenType.UserName);
		if (policy==null) throw new ServiceResultException("UserName not supported");
		String securityPolicyUri = policy.getSecurityPolicyUri();
		if (securityPolicyUri==null) securityPolicyUri = ep.getSecurityPolicyUri();
		SecurityPolicy securityPolicy = SecurityPolicy.getSecurityPolicy( securityPolicyUri );
		if (securityPolicy==null) securityPolicy = SecurityPolicy.NONE;
		UserNameIdentityToken token = new UserNameIdentityToken();
		
		token.setUserName( username );
		token.setPolicyId( policy.getPolicyId() );
		
		// Encrypt the password
		String algorithmUri = securityPolicy.getAsymmetricEncryptionAlgorithmUri();
		if (algorithmUri==null) algorithmUri = SecurityConstants.RsaOaep;
		try {
			Cert serverCert = new Cert(ep.getServerCertificate());
			byte[] pw = password.getBytes( BinaryEncoder.UTF8 );
			pw = ByteBufferUtils.concatenate( toArray(pw.length+senderNonce.length), pw, senderNonce );			
			pw = CryptoUtil.asymmEncrypt(pw, serverCert.getCertificate().getPublicKey(), algorithmUri);
			token.setPassword( pw );			
			token.setEncryptionAlgorithm(algorithmUri);
			
		} catch (InvalidKeyException e) {
			// Server certificiate doesnot have encrypt usage
			throw new ServiceResultException(StatusCodes.Bad_CertificateInvalid, "Server certificate in endpoint is invalid: "+e.getMessage());
		} catch (IllegalBlockSizeException e) {
			throw new ServiceResultException(StatusCodes.Bad_SecurityPolicyRejected, e.getClass().getName()+":"+e.getMessage());
		} catch (BadPaddingException e) {
			throw new ServiceResultException(StatusCodes.Bad_CertificateInvalid, "Server certificate in endpoint is invalid: "+e.getMessage());
		}
		
		return token;		
	}

	/**
	 * Create user identity token based on username and password
	 * 
	 * @param ep
	 * @param senderNonce
	 * @param issuedIdentityToken
	 * @return user identity token 
	 * @throws ServiceResultException if endpoint or the stack doesn't support UserName token policy
	 */
	public static UserIdentityToken createIssuedIdentityToken(EndpointDescription ep, byte[] senderNonce, byte[] issuedIdentityToken)	
	throws ServiceResultException
	{
		UserTokenPolicy policy = ep.findUserTokenPolicy(UserTokenType.UserName);
		if (policy==null) throw new ServiceResultException("UserName not supported");
		String securityPolicyUri = policy.getSecurityPolicyUri();
		if (securityPolicyUri==null) securityPolicyUri = ep.getSecurityPolicyUri();
		SecurityPolicy securityPolicy = SecurityPolicy.getSecurityPolicy( securityPolicyUri );
		if (securityPolicy==null) securityPolicy = SecurityPolicy.NONE;
		IssuedIdentityToken token = new IssuedIdentityToken();		
		token.setTokenData( issuedIdentityToken );
		
		// Encrypt the password
		String algorithmUri = securityPolicy.getAsymmetricEncryptionAlgorithmUri();
		if (algorithmUri==null) algorithmUri = SecurityConstants.RsaOaep;
		try {
			Cipher cipher = CryptoUtil.getAsymmetricCipher(algorithmUri);
			Cert serverCert = new Cert(ep.getServerCertificate());
			cipher.init(Cipher.ENCRYPT_MODE, serverCert.getCertificate());
			byte[] tokenData = ByteBufferUtils.concatenate( toArray(issuedIdentityToken.length+senderNonce.length), issuedIdentityToken, senderNonce );
			token.setTokenData( cipher.doFinal(tokenData) );
			token.setEncryptionAlgorithm(algorithmUri);
			
		} catch (InvalidKeyException e) {
			// Server certificiate doesnot have encrypt usage
			throw new ServiceResultException(StatusCodes.Bad_CertificateInvalid, "Server certificate in endpoint is invalid: "+e.getMessage());
		} catch (IllegalBlockSizeException e) {
			throw new ServiceResultException(StatusCodes.Bad_SecurityPolicyRejected, e.getClass().getName()+":"+e.getMessage());
		} catch (BadPaddingException e) {
			throw new ServiceResultException(StatusCodes.Bad_CertificateInvalid, "Server certificate in endpoint is invalid: "+e.getMessage());
		}
		
		return token;		
	}


	/**
	 * Get all internet addresses of this computer
	 * 
	 * @return all internet addresses of this computer
	 * @throws SocketException
	 */
	public static Set<InetAddress> getInetAddresses() 
	throws SocketException
	{
		Set<InetAddress> result = new HashSet<InetAddress>();
		Enumeration<NetworkInterface> nids = NetworkInterface.getNetworkInterfaces();
		for (;nids.hasMoreElements();) 
		{
			Enumeration<InetAddress> addrs = nids.nextElement().getInetAddresses(); 
			for (;addrs.hasMoreElements();) {
				InetAddress addr = addrs.nextElement();
//				if (addr instanceof Inet6Address) continue;
				result.add(addr);
			}
		}
		return result;
	}
	
	/**
	 * Get all internet address names of this computer.
	 * 
	 * @return all internet address names of this computer in URL compatible format
	 * @throws SocketException
	 */
	public static Set<String> getInetAddressNames() 
	throws SocketException
	{
 		Set<String> result = new HashSet<String>();
		Enumeration<NetworkInterface> nids = NetworkInterface.getNetworkInterfaces();
		for (;nids.hasMoreElements();) 
		{
			Enumeration<InetAddress> addrs = nids.nextElement().getInetAddresses(); 
			for (;addrs.hasMoreElements();)
			{
				InetAddress addr = addrs.nextElement();
				String hostname = addr.getHostName();
				String hostaddr = addr.getHostAddress();				
				boolean hasName = !hostname.equals(hostaddr);
				boolean IPv6 = addr instanceof Inet6Address;
				
				if (hasName) result.add( hostname );
				if (IPv6) result.add( "["+hostaddr+"]");
				else result.add( hostaddr );
			}
		}
		return result;
	}
	

	
	/**
	 * Create anonymous user identity token 
	 * @param ep
	 * @return user identity token 
	 * @throws ServiceResultException if endpoint or the stack doesn't support Anonymous token policy
	 */
	public static UserIdentityToken createAnonymousIdentityToken(EndpointDescription ep)	
	throws ServiceResultException
	{
		UserTokenPolicy policy = ep.findUserTokenPolicy(UserTokenType.Anonymous);
		if (policy==null) throw new ServiceResultException("Anonymous UserTokenType is not supported");
		return new AnonymousIdentityToken( policy.getPolicyId() );
	}
	
	
	private static byte[] toArray(int value)
	{
		// Little Endian
		return new byte[] {(byte)value, (byte)(value>>8), (byte)(value>>16), (byte)(value>>24)};
		
		// Big-endian
//		return new byte[] {(byte)(value>>24), (byte)(value>>16), (byte)(value>>8), (byte)(value)};
	}
	
}
