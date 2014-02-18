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
import org.opcfoundation.ua.core.HistoryEventFieldList;
import org.opcfoundation.ua.core.HistoryUpdateDetails;
import org.opcfoundation.ua.core.HistoryUpdateMode;
import org.opcfoundation.ua.core.SimpleAttributeOperand;



public class InsertReplaceEventDetails extends HistoryUpdateDetails implements Structure, Cloneable {
	
	public static final NodeId ID = Identifiers.InsertReplaceEventDetails;
	public static final NodeId BINARY = Identifiers.InsertReplaceEventDetails_Encoding_DefaultBinary;
	public static final NodeId XML = Identifiers.InsertReplaceEventDetails_Encoding_DefaultXml;	
	
    protected HistoryUpdateMode PerformInsertReplace;
    protected SimpleAttributeOperand[] SelectClause;
    protected HistoryEventFieldList[] EventData;
    
    public InsertReplaceEventDetails() {}
    
    public InsertReplaceEventDetails(NodeId NodeId, HistoryUpdateMode PerformInsertReplace, SimpleAttributeOperand[] SelectClause, HistoryEventFieldList[] EventData)
    {
        super(NodeId);
        this.PerformInsertReplace = PerformInsertReplace;
        this.SelectClause = SelectClause;
        this.EventData = EventData;
    }
    
    public HistoryUpdateMode getPerformInsertReplace()
    {
        return PerformInsertReplace;
    }
    
    public void setPerformInsertReplace(HistoryUpdateMode PerformInsertReplace)
    {
        this.PerformInsertReplace = PerformInsertReplace;
    }
    
    public SimpleAttributeOperand[] getSelectClause()
    {
        return SelectClause;
    }
    
    public void setSelectClause(SimpleAttributeOperand[] SelectClause)
    {
        this.SelectClause = SelectClause;
    }
    
    public HistoryEventFieldList[] getEventData()
    {
        return EventData;
    }
    
    public void setEventData(HistoryEventFieldList[] EventData)
    {
        this.EventData = EventData;
    }
    
    /**
      * Deep clone
      *
      * @return cloned InsertReplaceEventDetails
      */
    public InsertReplaceEventDetails clone()
    {
        InsertReplaceEventDetails result = new InsertReplaceEventDetails();
        result.NodeId = NodeId;
        result.PerformInsertReplace = PerformInsertReplace;
        if (SelectClause!=null) {
            result.SelectClause = new SimpleAttributeOperand[SelectClause.length];
            for (int i=0; i<SelectClause.length; i++)
                result.SelectClause[i] = SelectClause[i].clone();
        }
        if (EventData!=null) {
            result.EventData = new HistoryEventFieldList[EventData.length];
            for (int i=0; i<EventData.length; i++)
                result.EventData[i] = EventData[i].clone();
        }
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
		return "InsertReplaceEventDetails: "+ObjectUtils.printFieldsDeep(this);
	}

}
