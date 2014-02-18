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
import org.opcfoundation.ua.utils.ObjectUtils;
import org.opcfoundation.ua.builtintypes.UnsignedInteger;
import org.opcfoundation.ua.core.FilterOperand;
import org.opcfoundation.ua.core.RelativePath;



public class AttributeOperand extends FilterOperand implements Structure, Cloneable {
	
	public static final NodeId ID = Identifiers.AttributeOperand;
	public static final NodeId BINARY = Identifiers.AttributeOperand_Encoding_DefaultBinary;
	public static final NodeId XML = Identifiers.AttributeOperand_Encoding_DefaultXml;	
	
    protected NodeId NodeId;
    protected String Alias;
    protected RelativePath BrowsePath;
    protected UnsignedInteger AttributeId;
    protected String IndexRange;
    
    public AttributeOperand() {}
    
    public AttributeOperand(NodeId NodeId, String Alias, RelativePath BrowsePath, UnsignedInteger AttributeId, String IndexRange)
    {
        this.NodeId = NodeId;
        this.Alias = Alias;
        this.BrowsePath = BrowsePath;
        this.AttributeId = AttributeId;
        this.IndexRange = IndexRange;
    }
    
    public NodeId getNodeId()
    {
        return NodeId;
    }
    
    public void setNodeId(NodeId NodeId)
    {
        this.NodeId = NodeId;
    }
    
    public String getAlias()
    {
        return Alias;
    }
    
    public void setAlias(String Alias)
    {
        this.Alias = Alias;
    }
    
    public RelativePath getBrowsePath()
    {
        return BrowsePath;
    }
    
    public void setBrowsePath(RelativePath BrowsePath)
    {
        this.BrowsePath = BrowsePath;
    }
    
    public UnsignedInteger getAttributeId()
    {
        return AttributeId;
    }
    
    public void setAttributeId(UnsignedInteger AttributeId)
    {
        this.AttributeId = AttributeId;
    }
    
    public String getIndexRange()
    {
        return IndexRange;
    }
    
    public void setIndexRange(String IndexRange)
    {
        this.IndexRange = IndexRange;
    }
    
    /**
      * Deep clone
      *
      * @return cloned AttributeOperand
      */
    public AttributeOperand clone()
    {
        AttributeOperand result = new AttributeOperand();
        result.NodeId = NodeId;
        result.Alias = Alias;
        result.BrowsePath = BrowsePath==null ? null : BrowsePath.clone();
        result.AttributeId = AttributeId;
        result.IndexRange = IndexRange;
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
		return "AttributeOperand: "+ObjectUtils.printFieldsDeep(this);
	}

}
