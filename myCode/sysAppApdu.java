/*
 * Copyright (c) 2011 Morpho Cards GmbH. This software is the confidential
 * and proprietary information of Morpho Cards GmbH.
 * All rights reserved.
 *
 * Morpho Cards GmbH makes no representations or warranties about the suitability
 * of the software, either express or implied, including but not limited to the
 * implied warranties of merchantability, fitness for a particular purpose, or
 * non-infringement. Morpho Cards GmbH shall not be liable for any damages
 * suffered by licensee as a result of using, modifying or distributing this
 * software or its derivatives.
 *
 * This copyright notice must appear in all copies of this software.
 *
 * $File: //Components/isimApplication/R4.0.0/dev/java_src/com/orga/uiccframework/application/usim/IsimRemoteService.java $
 * $Revision: #1 $
 * $DateTime: 2013/09/20 09:12:04 $
 */


package com.orga.uiccframework.application.usim;

import javacard.framework.APDU;
import javacard.framework.AID;
import javacard.framework.ISOException;
import javacard.framework.ISO7816;
import javacard.framework.Util;


import com.orga.javacard.componentinterfaces.ISimBiosSystemApplicationApdu;
import com.orga.javacard.componentinterfaces.JCISIMApplication;
import com.orga.toolkit.uicc.toolkit.ToolkitFramework;

/**
 * This Isim Remote Application does ONLY implement the
 * JCISIMApplication tagging interface to check if this
 * application shall be seen as a ISIM
 * It does not route to any Isim specific worker.
 * So it will act ABSOLUTELY identical to RFMUsim in any command.
 * The HybridIsimRemoteService has NO specific behaviour other the the
 * HybridUsimRemoteService.
 * (In spite of the HybridIsimApplication with the specific authenticate comamnd!)
 *
 * @author udzaack
 *
 */
public class IsimRemoteService extends UsimRemoteService implements JCISIMApplication {

// ### CLS - Class ###
	private static final byte CLA 								  = (byte) 0xA0;
	
    // ### INS - Instructions ###
    private static final byte INS_CREATE_SESSION_PARAM            = (byte) 0x01;
    private static final byte INS_SET_SESSION_PARAM               = (byte) 0x02;
    private static final byte INS_CONFIGURE_SESSION               = (byte) 0x03;
    private static final byte INS_TRIGGER_SESSION                 = (byte) 0x04;
    private static final byte INS_GET_HTTP_SESSION_STATE		  = (byte) 0x05;
    private static final byte INS_GET_PUBLICK_KEY				  = (byte) 0x06;
    
    private static final byte INS_VERIFYPIN 					  = (byte) 0x11;
    private static final byte INS_RESETPIN                        = (byte) 0x12;
    private static final byte INS_UNBLOCKPIN					  = (byte) 0x13;
 
    
    private static final byte INS_DATA_ENCRYPTION				  = (byte) 0x21;
    private static final byte INS_DATA_DECRYPTION                 = (byte) 0x22;
    private static final byte INS_SIGNATURE                       = (byte) 0x23;
    private static final byte INS_PROCESS_DATA                    = (byte) 0x24;
    private static final byte INS_GRAB_SUBSCRIPTION               = (byte) 0x25;
  
    
	// ### SW1SW2 - Exceptions ###
	
    private static final short SW_NULLPOINTER_EXCEPTION           = (short) 0x6600;
    private static final short SW_ARRAYINDEXOUTOFBOUNDS_EXCEPTION = (short) 0x66AB;
    private static final short SW_SECURITY_EXCEPTION              = (short) 0x665E;
    private static final short SW_UNKNOWN_EXCEPTION               = (short) 0x6C00;
    
    private static final short SW_INVALID_PARAMETERS_DATAFIELD    = (short) 0x6A80;
    private static final short SW_DEVICE_NOT_FOUND				  = (short) 0x6A81;
    private static final short SW_FUNCTION_NOT_FOUND			  = (short) 0x6A82;
    private static final short SW_RECORD_NOT_FOUND				  = (short) 0x6A83;
    
    private static final short SW_VERIFICATION_FAILED			  = (short) 0x6300;
    private static final short SW_PIN_VERIFICATION_REQUIRED		  = (short) 0x6301;
    private static final short SW_PIN_VERIFICATION_FAILED	      = (short) 0x63C0;
    private static final short SW_PIN_BLOCKED					  = (short) 0x6983;
    private static final short SW_PIN_LENGTH_WRONG				  = (short) 0x6984;    
    private static final short SW_RM_SUCCESS					  = (short) 0x1234;
    
    // ### Default ###
    private static final byte PIN_TRY_LIMIT                       = (byte) 0x03;
    private static final byte PIN_MAX_SIZE				          = (byte) 0x08;
    private static final byte PIN_SIZE                            = (byte) 0x04;

    /** Any Application has to have one USIMCommandProcessor
    *
    */
    public IsimRemoteService(byte[] bArray, short bOffset, byte bLength)
    {
        super(bArray, bOffset, bLength);
    }

    /**
     * Create a new USIM, register it to the JCRE and create a new USIMViewImplementation.
     *
     */
     public static void install( byte[] bArray, short bOffset, byte bLength ) throws ISOException
     {
         AID anADF = null;
         // Create a new USIM application and register it.
         IsimRemoteService anISIM = new IsimRemoteService(bArray, bOffset, bLength);

         anADF = anISIM.getAdfAid();

         anISIM.doRegistration( anADF, bArray, (short)(bOffset + 1), (byte)bArray[bOffset]);

         // Store our remoteaccessclass if we have one.
         // A Non RemoteNAA will get an accessclass = NEVER.
         // Otherwise a remote NAA will get it's Toolkit-accessclass  given via installation.
         anISIM.remoteAccessClass = ToolkitFramework.getCurrentAccessLevelClass();

     }
	 	// ### CLS - Class ###

    
		 
    public void process(ISimBiosSystemApplicationApdu anApdu) throws ISOException
    
    {
	    byte claMasked = (byte)(anApdu.getCla() & (byte)0xF0);
	    byte ins = anApdu.getIns();
	   

	    byte[] cmd = (byte[]) anApdu.getCommandData();	    
	    short cmdOffset = anApdu.getCommandDataOffset();
	    
	    byte[] result = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07, 0x08,0x09};
	    short length = (short) result.length;
	    
	    byte[] resBuff = anApdu.getResponseBuffer(); 
	    short resOffset = anApdu.getResponseBufferOffset();
	    
	    Util.arrayCopyNonAtomic(result, (short)0, resBuff, (short)resOffset, (short)length);	    
	  	
	  	anApdu.setStatusword(SW_RM_SUCCESS);
	    anApdu.appendResponse(resBuff,(short)resOffset, (short)length, true);
    	
 		
    }
    

}
