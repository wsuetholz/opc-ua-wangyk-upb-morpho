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
import org.opcfoundation.ua.builtintypes.UnsignedByte;



public class AggregateConfiguration extends Object implements Structure, Cloneable {
	
	public static final NodeId ID = Identifiers.AggregateConfiguration;
	public static final NodeId BINARY = Identifiers.AggregateConfiguration_Encoding_DefaultBinary;
	public static final NodeId XML = Identifiers.AggregateConfiguration_Encoding_DefaultXml;	
	
    protected Boolean UseSeverCapabilitiesDefaults;
    protected Boolean TreatUncertainAsBad;
    protected UnsignedByte PercentDataBad;
    protected UnsignedByte PercentDataGood;
    protected Boolean SteppedSlopedExtrapolation;
    
    public AggregateConfiguration() {}
    
    public AggregateConfiguration(Boolean UseSeverCapabilitiesDefaults, Boolean TreatUncertainAsBad, UnsignedByte PercentDataBad, UnsignedByte PercentDataGood, Boolean SteppedSlopedExtrapolation)
    {
        this.UseSeverCapabilitiesDefaults = UseSeverCapabilitiesDefaults;
        this.TreatUncertainAsBad = TreatUncertainAsBad;
        this.PercentDataBad = PercentDataBad;
        this.PercentDataGood = PercentDataGood;
        this.SteppedSlopedExtrapolation = SteppedSlopedExtrapolation;
    }
    
    public Boolean getUseSeverCapabilitiesDefaults()
    {
        return UseSeverCapabilitiesDefaults;
    }
    
    public void setUseSeverCapabilitiesDefaults(Boolean UseSeverCapabilitiesDefaults)
    {
        this.UseSeverCapabilitiesDefaults = UseSeverCapabilitiesDefaults;
    }
    
    public Boolean getTreatUncertainAsBad()
    {
        return TreatUncertainAsBad;
    }
    
    public void setTreatUncertainAsBad(Boolean TreatUncertainAsBad)
    {
        this.TreatUncertainAsBad = TreatUncertainAsBad;
    }
    
    public UnsignedByte getPercentDataBad()
    {
        return PercentDataBad;
    }
    
    public void setPercentDataBad(UnsignedByte PercentDataBad)
    {
        this.PercentDataBad = PercentDataBad;
    }
    
    public UnsignedByte getPercentDataGood()
    {
        return PercentDataGood;
    }
    
    public void setPercentDataGood(UnsignedByte PercentDataGood)
    {
        this.PercentDataGood = PercentDataGood;
    }
    
    public Boolean getSteppedSlopedExtrapolation()
    {
        return SteppedSlopedExtrapolation;
    }
    
    public void setSteppedSlopedExtrapolation(Boolean SteppedSlopedExtrapolation)
    {
        this.SteppedSlopedExtrapolation = SteppedSlopedExtrapolation;
    }
    
    /**
      * Deep clone
      *
      * @return cloned AggregateConfiguration
      */
    public AggregateConfiguration clone()
    {
        AggregateConfiguration result = new AggregateConfiguration();
        result.UseSeverCapabilitiesDefaults = UseSeverCapabilitiesDefaults;
        result.TreatUncertainAsBad = TreatUncertainAsBad;
        result.PercentDataBad = PercentDataBad;
        result.PercentDataGood = PercentDataGood;
        result.SteppedSlopedExtrapolation = SteppedSlopedExtrapolation;
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
		return "AggregateConfiguration: "+ObjectUtils.printFieldsDeep(this);
	}

}
