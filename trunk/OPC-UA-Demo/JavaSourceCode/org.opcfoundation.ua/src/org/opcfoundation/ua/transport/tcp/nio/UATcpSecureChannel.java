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

package org.opcfoundation.ua.transport.tcp.nio;

import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.log4j.Logger;
import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.core.MessageSecurityMode;
import org.opcfoundation.ua.transport.CloseableObjectState;
import org.opcfoundation.ua.transport.security.SecurityPolicy;
import org.opcfoundation.ua.transport.tcp.impl.SecurityToken;
import org.opcfoundation.ua.transport.tcp.nio.UATcpServer.UATcpServerConnection.UATcpServerSecureChannel;
import org.opcfoundation.ua.utils.AbstractState;
import org.opcfoundation.ua.utils.StackUtils;

/**
 * This class contains mechanisms that is commont to its sub-classes {@link UATcpClientSecureChannel} and 
 * {@link UATcpServerSecureChannel}.
 * 
 * Common mechanism:
 *  - Secure channel id
 *  - Security tokens
 *  - State & Error State
 *  - The sequence numbers of input and output channels 
 */
public abstract class UATcpSecureChannel extends AbstractState<CloseableObjectState, ServiceResultException> {

	/** Globally Unique Secure Channel ID */
	protected int					secureChannelId;
	/** The error - In case the channel is in error state */
	protected Exception				error;
	/** Collection of all Security Tokens */
	protected Map<Integer, SecurityToken> tokens = new ConcurrentHashMap<Integer, SecurityToken>();
	/** The active token, This token is used in write operations */
	protected SecurityToken			activeToken;
	/** Sequence number counter of outbound messages */
	protected AtomicInteger			sendSequenceNumber = new AtomicInteger( new Random().nextInt(1024) );
	/** Sequence number counter of inbound messages */
	protected AtomicInteger			recvSequenceNumber = new AtomicInteger();
	
	/** Logger */
	static Logger log = Logger.getLogger(UATcpSecureChannel.class);
	
	public UATcpSecureChannel() {
		super(CloseableObjectState.Closed);
	}

	public int getSecureChannelId() {
		return secureChannelId;
	}

	public SecurityToken getActiveSecurityToken() {
		return activeToken;
	}
	
	public void setActiveSecurityToken(SecurityToken token) {
		if (token==null) 
			throw new IllegalArgumentException("null");
		log.debug("Switching to new security token "+token.getTokenId());
		this.activeToken = token;
		pruneInvalidTokens();
	}
	
	public synchronized SecurityToken getSecurityToken(int tokenId) {
		log.debug("tokens("+tokens.size()+")="+tokens.values());
		return tokens.get(tokenId);
	}
	
	private void pruneInvalidTokens()
	{	
		log.debug("pruneInvalidTokens: tokens("+tokens.size()+")="+tokens.values());
		for (SecurityToken t : tokens.values())
			if (!t.isValid()) {
				log.debug("pruneInvalidTokens: remove Id="+t.getTokenId());
				tokens.remove(t.getTokenId());
			}
	}

	public MessageSecurityMode getMessageSecurityMode() {
		SecurityToken token = getActiveSecurityToken();
		return token==null ? null : token.getMessageSecurityMode();
	}

	public SecurityPolicy getSecurityPolicy() {
		SecurityToken token = getActiveSecurityToken();
		return token==null ? null : token.getSecurityPolicy();
	}	
	
	public synchronized SecurityToken getLatestNonExpiredToken()
	{
		SecurityToken result = null;
		for (SecurityToken t : tokens.values())
		{
			if (t.isExpired()) continue;
			if (result==null) result = t;
			if (t.getCreationTime() > result.getCreationTime()) result = t;
		}
		return result;
	}
	
	public synchronized void setError(ServiceResultException e) {
		super.setError( e );
	}

	@Override
	protected void onListenerException(RuntimeException rte) {
		setError( StackUtils.toServiceResultException(rte) );
	}

	@Override
	public String toString() {
		CloseableObjectState s = getState();
		return "SecureChannel (state="+s+(s.isOpen()?", id="+secureChannelId:"")+")";
	}	
	
}
