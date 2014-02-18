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
import org.opcfoundation.ua.builtintypes.ExpandedNodeId;
import org.opcfoundation.ua.builtintypes.Variant;



public class QueryDataSet extends Object implements Structure, Cloneable {
	
	public static final NodeId ID = Identifiers.QueryDataSet;
	public static final NodeId BINARY = Identifiers.QueryDataSet_Encoding_DefaultBinary;
	public static final NodeId XML = Identifiers.QueryDataSet_Encoding_DefaultXml;	
	
    protected ExpandedNodeId NodeId;
    protected ExpandedNodeId TypeDefinitionNode;
    protected Variant[] Values;
    
    public QueryDataSet() {}
    
    public QueryDataSet(ExpandedNodeId NodeId, ExpandedNodeId TypeDefinitionNode, Variant[] Values)
    {
        this.NodeId = NodeId;
        this.TypeDefinitionNode = TypeDefinitionNode;
        this.Values = Values;
    }
    
    public ExpandedNodeId getNodeId()
    {
        return NodeId;
    }
    
    public void setNodeId(ExpandedNodeId NodeId)
    {
        this.NodeId = NodeId;
    }
    
    public ExpandedNodeId getTypeDefinitionNode()
    {
        return TypeDefinitionNode;
    }
    
    public void setTypeDefinitionNode(ExpandedNodeId TypeDefinitionNode)
    {
        this.TypeDefinitionNode = TypeDefinitionNode;
    }
    
    public Variant[] getValues()
    {
        return Values;
    }
    
    public void setValues(Variant[] Values)
    {
        this.Values = Values;
    }
    
    /**
      * Deep clone
      *
      * @return cloned QueryDataSet
      */
    public QueryDataSet clone()
    {
        QueryDataSet result = new QueryDataSet();
        result.NodeId = NodeId;
        result.TypeDefinitionNode = TypeDefinitionNode;
        result.Values = Values==null ? null : Values.clone();
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
		return "QueryDataSet: "+ObjectUtils.printFieldsDeep(this);
	}

}
