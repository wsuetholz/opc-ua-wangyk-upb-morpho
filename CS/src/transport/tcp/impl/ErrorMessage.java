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

package transport.tcp.impl;

import builtintypes.StatusCode;
import builtintypes.UnsignedInteger;
import encoding.IEncodeable;

/**
 * ErrorMessage is a message used in TCP Handshake.
 *
 * 
 */
public class ErrorMessage implements IEncodeable {

	UnsignedInteger Error;
	String Reason;
	
	public ErrorMessage() {}
	
	public ErrorMessage(UnsignedInteger error, String reason) {
		this.Error = error;
		this.Reason = reason;
	}
	
	public ErrorMessage(StatusCode code, String reason) {
		this.Error = code.getValue();
		this.Reason = reason;
	}
	
	public UnsignedInteger getError() {
		return Error;
	}
	public void setError(UnsignedInteger error) {
		Error = error;
	}
	public String getReason() {
		return Reason;
	}
	public void setReason(String reason) {
		Reason = reason;
	}		
	
}
