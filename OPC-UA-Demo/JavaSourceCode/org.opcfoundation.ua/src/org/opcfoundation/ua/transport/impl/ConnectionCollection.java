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

package org.opcfoundation.ua.transport.impl;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import org.opcfoundation.ua.common.ServiceResultException;
import org.opcfoundation.ua.transport.Connection;
import org.opcfoundation.ua.transport.ConnectionMonitor;
import org.opcfoundation.ua.transport.IConnectionListener;

/**
 *
 * 
 * @author Toni Kalajainen (toni.kalajainen@vtt.fi)
 */
public class ConnectionCollection implements ConnectionMonitor {

	Set<Connection> connections = new HashSet<Connection>(); 
	CopyOnWriteArrayList<ConnectListener> listeners = new CopyOnWriteArrayList<ConnectListener>();
	Object sender;	
	
	public ConnectionCollection(Object sender) {
		this.sender = sender;
	}
		
	@Override
	public void addConnectionListener(ConnectListener l) {
		listeners.add(l);
	}

	@Override
	public void removeConnectionListener(ConnectListener l) {
		listeners.remove(l);
	}
	
	@Override
	public synchronized void getConnections(Collection<Connection> result) {
		result.addAll(connections);
	}
	
	public void addConnection(final Connection c) {
		c.addConnectionListener(new IConnectionListener() {
			@Override
			public void onClosed(ServiceResultException closeError) {
					connections.remove(c);
			}
			@Override
			public void onOpen() {
			}});
		if (!connections.add(c)) return;
		for (ConnectListener cl : listeners)
			cl.onConnect(sender, c);
	}

}
