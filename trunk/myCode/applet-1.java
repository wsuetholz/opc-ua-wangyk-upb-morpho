package com.morpho;

import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.MultiSelectable;
import javacard.framework.Shareable;
import javacard.framework.Util;
import javacard.framework.OwnerPIN;


import org.globalplatform.GPSystem;
import org.globalplatform.GlobalService;
import org.globalplatform.HTTPAdministration;
import org.globalplatform.HTTPReportListener;

import uicc.toolkit.ToolkitConstants;
import uicc.toolkit.ToolkitException;
import uicc.toolkit.ToolkitInterface;
import uicc.toolkit.ToolkitRegistry;
import uicc.toolkit.ToolkitRegistrySystem;


public class GP extends Applet implements HTTPReportListener, ToolkitInterface, MultiSelectable
{  
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
 
 
    private static final byte INS_GET_PUBLICK_KEY				  = (byte) 0x20;
    private static final byte INS_GET_SUB						  = (byte) 0x21;
    private static final byte INS_SET_SUB		                  = (byte) 0x22;
    private static final byte INS_GET_RECORD                      = (byte) 0x23;
  	private static final byte INS_GET_VALUE		                  = (byte) 0x24;
    
  
    
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
    private static final short SW_FAILD_TO_CLOSE_SEESION     	  = (short) 0x6302;
    private static final short SW_PIN_VERIFICATION_FAILED	      = (short) 0x63C0;
    private static final short SW_PIN_BLOCKED					  = (short) 0x6983;
    private static final short SW_PIN_LENGTH_WRONG				  = (short) 0x6984;
    
    private static final short SW_RM_SUCCESS					  = (short) 0x1234;
    
    
    // ### Default ###
    private static final byte PIN_TRY_LIMIT                       = (byte) 0x03;
    private static final byte PIN_MAX_SIZE				          = (byte) 0x08;
    private static final byte PIN_SIZE                            = (byte) 0x04;
    
    
	private static byte[] data;
	private static short dataOffset;
	private static short dataLength;
	private static boolean useReportListener;
	private static short reportListenerState;
	private static short toolkitExceptionReason;
	
	private OwnerPIN pin;
	
	 // Temporary
	private byte[] pinValue ={ 0x01, 0x02, 0x03, 0x04};
	private byte[] pk1 = {0x00,0x00,0x10,0x00};
	private byte[] pk2 = {0x00,0x00,0x20,0x00};
	private byte[] pk3 = {0x00,0x00,0x30,0x00};	
	
	private TriggerSession trigger;
		
    public static void install( byte[] bArray, short bOffset, byte bLength) throws javacard.framework.ISOException
    {
        new GP();
    }

    public GP()
    {
    	super();
    	
    	pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_MAX_SIZE);
    		
		pin.update(pinValue, (short) 0, PIN_SIZE);
    	
    	register();
    	
    	ToolkitRegistrySystem.getEntry().setEvent(ToolkitConstants.EVENT_UNRECOGNIZED_ENVELOPE);
    }
    
    public void process(APDU apdu) throws ISOException
    {
  
            byte[] apduBuffer = apdu.getBuffer();
            short reason = (short) -1;
            
            try
            {
	            switch(apduBuffer[ISO7816.OFFSET_INS])
	            {
		            // Create Array
	            	case (byte) 0x01:
		            {
	            		// validate P1
	            		short length = (short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF);
	            		
	            		if(length > (short) 0x007F)
	            		{
	            			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
	            		}
	            		
	            		// get requested array length
	            		length = (short) (Util.getShort(apduBuffer, ISO7816.OFFSET_P1) & 0x7FFF);
	            		
	            		if(data != null)
		            	{
	            			if(length > (short) data.length)
	            			{
		            			// delete old
		            			data = null;
			            		JCSystem.requestObjectDeletion();
	            			}
	            			else
	            			{
	            				// update length
	            				length = (short) -1;
	            			}
	            		}
	            		
	            		if(length > (short) -1)
	            		{
		            		// create array with new length
		            		data = new byte[length];
	            		}
		            }
		            break;
		            
		            // Set Data
	            	case (byte) 0x02:
		            {
	            		// validate P1
	            		if(((short) (apduBuffer[ISO7816.OFFSET_P1] & 0x00FF)) > (short) 0x007F)
	            		{
	            			ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
	            		}
	            		
            			// receive data over APDU
            			apdu.setIncomingAndReceive();
            			
            			// get length
            			Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, data, (short) (Util.getShort(apduBuffer, ISO7816.OFFSET_P1) & 0x7FFF), (short) (apduBuffer[ISO7816.OFFSET_LC] & 0x00FF));
		            }
		            break;
		            
		            // Configure Test
	            	case (byte) 0x03:
		            {
	        			// receive data over APDU
	        			apdu.setIncomingAndReceive();
	            		
	            		if(apduBuffer[ISO7816.OFFSET_LC] != (byte) 0x05)
	            		{
	            			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	            		}
	            		
	            		dataOffset = (short) (Util.getShort(apduBuffer, (short) (ISO7816.OFFSET_CDATA)) & 0x7FFF);
	            		dataLength = (short) (Util.getShort(apduBuffer, (short) (ISO7816.OFFSET_CDATA + 2)) & 0x7FFF);
	            		useReportListener = apduBuffer[(short) (ISO7816.OFFSET_CDATA + 4)] == (byte) 0x01;
	            		
	            		// reset report state
	            		reportListenerState = (short) 0;
	    				
	            		// reset reason
	    				toolkitExceptionReason = ISO7816.SW_NO_ERROR;
		            }
		            break;
		            
		            // Run Test
	            	case (byte) 0x04:
	            		//trigger.triggerSession(data, dataOffset, dataLength);
	            		apdu.setOutgoingAndSend((short)90, (short)00);
		            break;
		            
		            // Get Report State
	            	case (byte) 0x05:
		            {
	            		// set state
		            	Util.setShort(apduBuffer, (short) 0, reportListenerState);
		            	
		            	// send state
		            	apdu.setOutgoingAndSend((short) 0, (short) 2);
		            }
		            break;
		            
		            // Get Target Pk
	            	case (byte) 0x06:
		            {
	            		short id = (short) (apduBuffer[ISO7816.OFFSET_P2] & 0x00FF);
	            		switch(id)
	            		{
	            		case 1:
	            			short length = (short) pk1.length;
	            			Util.arrayCopyNonAtomic(pk1, (short)0, apduBuffer, (short)0, (short) length);
	            			apdu.setOutgoingAndSend((short)0, length);
	            		break;
	            		
	            		case 2:
	            				short length2 = (short) pk2.length;
	            			Util.arrayCopyNonAtomic(pk2, (short)0, apduBuffer, (short)0, (short) length2);
	            			apdu.setOutgoingAndSend((short)0, length2);
            			break;
            			
	            		case 3:
	            				short length3 = (short) pk3.length;
	            			Util.arrayCopyNonAtomic(pk3, (short)0, apduBuffer, (short)0, (short) length3);
	            			apdu.setOutgoingAndSend((short)0, length3);
	            		break;
	            		
		            	default:
							ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); //0x6D00
		           	}
		            	
		            }
		            break;
		            // tst send OPT from Andorid
		            case(byte) 0x11:
		            	doVerifyPIN(apdu);
		            break;
		            case(byte) 0x13:
		            	doUnblockPIN();
		            break;
		            case(byte) 0x24:
		            {
		            	apdu.setOutgoingAndSend((short)90, (short)00);
		            }
		            
		            break;
		            
		           // default:
					//	ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); //0x6D00
	            }
    		}
    		catch(NullPointerException e)
    		{
    			reason = SW_NULLPOINTER_EXCEPTION;
			}
    		catch(ArrayIndexOutOfBoundsException e)
    		{
    			reason = SW_ARRAYINDEXOUTOFBOUNDS_EXCEPTION;
    		}
    		catch(SecurityException e)
    		{
    			reason = SW_SECURITY_EXCEPTION;
			}
    		catch(ISOException e)
    		{
    			reason = e.getReason();
			}
    		catch(Exception e)
    		{
    			reason = SW_UNKNOWN_EXCEPTION;
			}
    		
    		// check for errors
    		if(reason != (short) -1)
    		{
    			ISOException.throwIt(reason);
    		}
        }
    
    public Shareable getShareableInterfaceObject(AID aid, byte parameter)
    {
    	if(aid == null)
    	{
    		return (useReportListener && (parameter == GPSystem.FAMILY_HTTP_REPORT)) ? this : null;
    	}
    	
    	return ((aid != null) && (parameter == (byte) 0x01)) ? this : null;
    }
            
    
	public void processToolkit(short event) throws ToolkitException
	{
		if(event == ToolkitConstants.EVENT_UNRECOGNIZED_ENVELOPE)
		{
			try
			{
				trigger.triggerSession(data, dataOffset, dataLength);
    		}
    		catch(NullPointerException e)
    		{
    			toolkitExceptionReason = SW_NULLPOINTER_EXCEPTION;
			}
    		catch(ArrayIndexOutOfBoundsException e)
    		{
    			toolkitExceptionReason = SW_ARRAYINDEXOUTOFBOUNDS_EXCEPTION;
    		}
    		catch(SecurityException e)
    		{
    			toolkitExceptionReason = SW_SECURITY_EXCEPTION;
			}
    		catch(ISOException e)
    		{
    			toolkitExceptionReason = e.getReason();
			}
    		catch(Exception e)
    		{
    			toolkitExceptionReason = SW_UNKNOWN_EXCEPTION;
			}
		}
	}
	
	public void httpAdministationSessionReport(short status)
	{
		reportListenerState = status;
	}
	
	public void deselect(boolean appInstStillActive)
	{
		pin.reset();
	}

	public boolean select(boolean appInstAlreadyActive)
	{
		return true;
	}
	
	private void doVerifyPIN(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
			
		if(pin.getTriesRemaining() == (byte)0) {
			ISOException.throwIt(SW_PIN_BLOCKED);
		}
		
		if((byte)buffer[ISO7816.OFFSET_LC] != PIN_SIZE) {
			ISOException.throwIt(SW_PIN_LENGTH_WRONG);
		}
		
		if (!pin.check(buffer, ISO7816.OFFSET_CDATA, PIN_SIZE)) {
			ISOException.throwIt(SW_PIN_VERIFICATION_FAILED);
		}
	}
	
	private void doResetPIN(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
			
		if ( ! pin.isValidated() ) {
            ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);	
        } else {
        	pin.update(buffer, ISO7816.OFFSET_CDATA, PIN_SIZE);
        }
    }
	
	private void doUnblockPIN() {
		/*
		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		
		if(pin.getTriesRemaining() == (byte)0) {
			ISOException.throwIt(SW_PIN_BLOCKED);
		}
		
		if((byte)buffer[ISO7816.OFFSET_LC] != PIN_SIZE) {
			ISOException.throwIt(SW_PIN_LENGTH_WRONG);
		}
		
		if (!pin.check(buffer, ISO7816.OFFSET_CDATA, PIN_SIZE)) {
			ISOException.throwIt(SW_PIN_VERIFICATION_FAILED);
		} else {
			pin.resetAndUnblock();
		}
		*/
		pin.resetAndUnblock();
	}
}
