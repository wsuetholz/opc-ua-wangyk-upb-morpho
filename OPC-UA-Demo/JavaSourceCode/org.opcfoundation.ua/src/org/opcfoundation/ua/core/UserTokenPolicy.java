/* ========================================================================
 * Copyright (c) 2005-2010 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/MIT/1.00/
 * ======================================================================*/

package org.opcfoundation.ua.core;

import org.opcfoundation.ua.builtintypes.Structure;
import org.opcfoundation.ua.builtintypes.NodeId;
import org.opcfoundation.ua.core.Identifiers;
import org.opcfoundation.ua.core.UserTokenPolicy;
import org.opcfoundation.ua.transport.security.SecurityPolicy;
import org.opcfoundation.ua.utils.ObjectUtils;
import org.opcfoundation.ua.core.UserTokenType;



public class UserTokenPolicy extends Object implements Structure, Cloneable {
	
	public static final UserTokenPolicy ANONYMOUS = new UserTokenPolicy("anonymous", UserTokenType.Anonymous, null, null, null);
	public static final UserTokenPolicy SECURE_USERNAME_PASSWORD = new UserTokenPolicy("username_basic128", UserTokenType.UserName, null, null, SecurityPolicy.BASIC128RSA15.getPolicyUri());
	public static final UserTokenPolicy SECURE_USERNAME_PASSWORD_BASIC256 = new UserTokenPolicy("username_basic256", UserTokenType.UserName, null, null, SecurityPolicy.BASIC256.getPolicyUri());

	public static final NodeId ID = Identifiers.UserTokenPolicy;
	public static final NodeId BINARY = Identifiers.UserTokenPolicy_Encoding_DefaultBinary;
	public static final NodeId XML = Identifiers.UserTokenPolicy_Encoding_DefaultXml;	
	
    protected String PolicyId;
    protected UserTokenType TokenType;
    protected String IssuedTokenType;
    protected String IssuerEndpointUrl;
    protected String SecurityPolicyUri;
    
    public UserTokenPolicy() {}
    
    public UserTokenPolicy(String PolicyId, UserTokenType TokenType, String IssuedTokenType, String IssuerEndpointUrl, String SecurityPolicyUri)
    {
        this.PolicyId = PolicyId;
        this.TokenType = TokenType;
        this.IssuedTokenType = IssuedTokenType;
        this.IssuerEndpointUrl = IssuerEndpointUrl;
        this.SecurityPolicyUri = SecurityPolicyUri;
    }
    
    public String getPolicyId()
    {
        return PolicyId;
    }
    
    public void setPolicyId(String PolicyId)
    {
        this.PolicyId = PolicyId;
    }
    
    public UserTokenType getTokenType()
    {
        return TokenType;
    }
    
    public void setTokenType(UserTokenType TokenType)
    {
        this.TokenType = TokenType;
    }
    
    public String getIssuedTokenType()
    {
        return IssuedTokenType;
    }
    
    public void setIssuedTokenType(String IssuedTokenType)
    {
        this.IssuedTokenType = IssuedTokenType;
    }
    
    public String getIssuerEndpointUrl()
    {
        return IssuerEndpointUrl;
    }
    
    public void setIssuerEndpointUrl(String IssuerEndpointUrl)
    {
        this.IssuerEndpointUrl = IssuerEndpointUrl;
    }
    
    public String getSecurityPolicyUri()
    {
        return SecurityPolicyUri;
    }
    
    public void setSecurityPolicyUri(String SecurityPolicyUri)
    {
        this.SecurityPolicyUri = SecurityPolicyUri;
    }
    
    /**
      * Deep clone
      *
      * @return cloned UserTokenPolicy
      */
    public UserTokenPolicy clone()
    {
        UserTokenPolicy result = new UserTokenPolicy();
        result.PolicyId = PolicyId;
        result.TokenType = TokenType;
        result.IssuedTokenType = IssuedTokenType;
        result.IssuerEndpointUrl = IssuerEndpointUrl;
        result.SecurityPolicyUri = SecurityPolicyUri;
        return result;
    }
    


	public NodeId getTypeId() {
		return ID;
	}

	public NodeId getXmlEncodeId() {
		return XML;
	}

	public NodeId getBinaryEncodeId() {
		return BINARY;
	}
	
	public String toString() {
		return "UserTokenPolicy: "+ObjectUtils.printFieldsDeep(this);
	}

}