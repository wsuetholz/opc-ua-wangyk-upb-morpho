/**
 * Copyright (c) 2008 Sagem Orga GmbH. This software is the
 * confidential and proprietary information of Sagem Orga GmbH.
 * All rights reserved.
 *
 * Sagem Orga GmbH makes no representations or warranties about
 * the suitability of the software, either express or implied, including
 * but not limited to the implied warranties of merchantability, fitness
 * for a particular purpose, or non-infringement. Sagem Orga GmbH
 * shall not be liable for any damages suffered by licensee as a result of
 * using, modifying or distributing this software or its derivatives.
 *
 * This copyright notice must appear in all copies of this software.
 *
 * $File: //Interfaces/iSimBiosSystemApplicationApdu/R1.0.1/dev/java/com/orga/javacard/componentinterfaces/ISimBiosSystemApplicationApdu.java $
 * $DateTime: 2013/09/20 14:07:19 $
 * $Revision: #1 $
 */

package com.orga.javacard.componentinterfaces;

import javacard.framework.APDU;
import javacard.framework.CardRuntimeException;

/**
 * APDU object which gives system applications the possibility to receive and process C-APDUs
 * and generate and send out R-APDUs in a transport protocol independent way.
 */
public interface ISimBiosSystemApplicationApdu
{
    /**
     * Mask and regarding compare values to decide if underlying protocol
     * is OTA (C- and R-APDU are carried by ETSI TS 102.225 messages), terminal-bound or internal.
     * These constants should be applied on return values of getSession().
     */
    public static final int SYSAPP_SESSION_MASK_OTA        = 0xf0000000;
    public static final int SYSAPP_SESSION_VALUE_OTA       = 0xf0000000;
    public static final int SYSAPP_SESSION_MASK_TERMINAL   = 0xff000000;
    public static final int SYSAPP_SESSION_VALUE_TERMINAL  = 0x00000000;
    public static final int SYSAPP_SESSION_MASK_INTERNAL   = 0xff000000;
    public static final int SYSAPP_SESSION_VALUE_INTERNAL  = 0x10000000;

    /*
     * Self-explanatory methods that support APDU header analysis
     */
    byte getCla();
    byte getIns();
    byte getP1();
    byte getP2();

    /**
     * The channel number corresponding to the APDUs class byte.
     * The value may be between 0 and 19.
     *
     * Return values in detail:
     *
     * Case 1.1) ISO 7816-4 first interindustry CLA codings:
     *
     *              Channel number = b2|b1  (values 0..3)
     *
     * Case 1.2) ISO 7816-4 further interindustry CLA codings:
     *
     *              Channel number = b4|b3|b2|b1 + 4 (values 4..19)
     *
     * Case 2) Non-interindustry CLA codings:
     *
     *              Channel number = b2|b1  (values 0..3)
     *
     * @return the channel number
     */
    byte getChannelNumber();

    /**
     * Are the bits in the class byte showing secured messaging set or not.
     *
     * @return  true if and only if
     *              - CLA b7 is unset and b3b4 != 00 or
     *              - CLA b7 is set and b6 != 0
     */
    boolean isSecureMessaging();

    /**
     * Checks if the apdu has been used as an event or a 'normal' apdu.
     * Currently supported are the two values from the Cramp environment.
     * for Tpdu and Event.
     * This is not a coding for the Eventtype but for the messagetype.
     * @return  messagescheme of the apdu (apdu, event, ...)
     *          C_CRAMP_SCHEME_TPDU  = 0x00
     *          C_CRAMP_SCHEME_EVENT = 0x40
     */
    byte getMessageScheme();


    /**
     * Checks if command chaining is requested in the class byte or not.
     *
     * @return  true if and only if CLA b5 is set.
    boolean isCommandChaning();
     */

    /**
     * Get unique session ID which is assigned to current SysApdu object.
     * Each session ID contains information about transport protocol/media type
     * and some additional protocol parameter (e.g. a TAR in case of remote protocol
     * or a logical channel number in case of terminal based SysApdus)
     *
     * Structure of returned 32-bit value if underlying protocol is
     *
     *  a)  OTA (ETSI TS 102.225):
     *
     *      '11110001 ........ ........ ........'       message has compact format (ETSI TS 102.226)
     *      '11110010 ........ ........ ........'       message has expanded format (ETSI TS 102.226)
     *      '1111.... tttttttt uuuuuuuu vvvvvvvv'       message is assigned to the toolkit application
     *                                                      with TAR 'tttttttt uuuuuuuu vvvvvvvv'
     *  b) terminal based:
     *
     *      '00000000 ........ pppppppp ........'       type of underlying transport protocol and media is indicated by 'pppppppp',
     *                                                  where coding is identical with return value of javacard.framework.APDU.getProtocol().
     *      '00000000 ........ ........ ...ccccc'       logical channel nr 'ccccc' is assigned to current SysApdu
     *
     *  c) internal APDU protocol:
     *
     *      '00010000 ........ ........ ........'       underlying protocol is proprietary
     *
     * @return  the internally assigned session ID
     */
    int getSession();

    /**
     * The related javacard.framework.APDU object if available for current protocol.
     *
     * @return APDU or null if not applicable for underlying protocol
     *
     */
    APDU getApdu();

    /**
     * Make command data and its length available for application
     * (via receive process for IO protocol or message parsing in case of OTA).
     *
     * Through invoking this method application signals that current APDU is
     * expected to be case 3 or 4. Otherwise case 1 or 2 is expected.
     *
     * The state of the Apdu is changed to 'incoming direction'.
     *
     * @precondition    receiveCmdData() and getLe() has NOT been invoked yet during processing current SysApdu object
     *
     * @return  length of data received or 0 if data is not available for current APDU.
     *
     * @throws CardRuntimeException     to be defined: e.g. format error in case of OTA APDUs or
     *                                  any IO error for T=0
     */
    short receiveCommandData() throws CardRuntimeException;

    /**
     * Retrieve array containing the command data (a Global JCRE array)
     *
     * Note:?
     *
     * @return          buffer with command data, or null if no data available.
     * @precondition    receiveCmdData() has been invoked
     * @precondition    getLe() has NOT been invoked yet during processing current SysApdu object
     *
     */
    public byte[] getCommandData();

    /**
     * @return  offset to command data, or -1 if no data available.
     *
     * @precondition    receiveCmdData() has been invoked
     * @precondition    getLe() has NOT been invoked yet during processing current SysApdu object
     */
    short getCommandDataOffset();

    /**
     * Return length of received command data, in range 1..255 (same value as Lc if present),
     * or 0 if not available (Lc is missing).
     *
     * Note: returns same value as receiveCmdData().
     *
     * @return  number of received command data bytes
     *
     * @precondition    receiveCmdData() has been invoked
     * @precondition    getLe() has NOT been invoked yet during processing current SysApdu object
     */
    short getCommandDataLength();

    /**
     * Returns the expected length of response data or the negated maximum buffer size.
     *
     * Through invoking this method application signals that current APDU is
     * expected to be case 2 or 4.
     *
     * Sets the state of the apdu to outbound direction. Buffer obtained by getCmdData()
     * is not guaranteed to contain the valid command data anymore.
     *
     * Behaviour for T=0 and OTA compact format protocols:
     *
     *          If no Le was transmitted or Le='00' was transmitted, the negated value of the
     *          maximum response buffer capacity is returned (i.e. 0xFF00 in case of T=0).
     *          Otherwise the transmitted Le value (zero-extended to short value) is returned.
     *
     * Behaviour for T=1 and OTA expanded format protocols:
     *
     *          If no Le is transmitted, 0 is returned (except for the last APDU in the
     *          remote session, where it is supposed that Le='00' was transmitted, see below
     *          and ETSI TS 102.226).
     *          If Le='00' was transmitted, the negated value of the maximum response buffer
     *          capacity is returned.
     *          Otherwise the transmitted Le value (zero-extended to short value) is returned.
     *
     * @precondition    getLe() has NOT been invoked yet during processing current SysApdu object
     *
     * @return      expected length of response data or negated maximum buffer size
     */
    short getLe();

    /*
     * Methods for response APDU generation
     */
    /**
     * Set the current status word of R-APDU.
     *
     * By default SW1SW2 is initialized with '9000' on passing the SysApdu to a SystemApplication.
     *
     * @param sw1Sw2    Status Word to be set
     */
    void  setStatusword(short sw1Sw2);

    /**
     * Returns current Status Word of R-APDU which has been set
     * by processing System Application, otherwise return initialization value '9000'.
     *
     * @return  current Status Word
     */
    short getStatusword();

    /**
     * Get output buffer for direct writing (a Global JCRE array)
     */
    byte[] getResponseBuffer();

    /**
     * Get current write position in output buffer
     */
    short getResponseBufferOffset();

    /**
     * Move the current write position in output buffer forward or backward and
     * returns the number of moved or moveable positions.
     *
     * If feasible, the displacement will be done and the number of moved positions will
     * be returned (return = i16Displacement); otherwise only
     * the number of feasible moved positions will be returned (|return|<|i16Displacement|).
     *
     * @param displacement      positive or negative distance that write position should move
     *
     * @return  the positive or negative number of moved or moveable positions
     */
    short setResponseBufferOffset(short displacement);

    /**
     * Append a segment of given array to end of existing response data,
     * increase write position accordingly.
     *
     * @param respData      the input buffer of data to be appended
     * @param offsRespData  the offset into the input buffer
     * @param lenRespData   the number of bytes to be appended
     *
     * @param truncate  indicates mode of append if data to be appended is too long:
     *                  truncate == false => no bytes of data appended,
     *                  otherwise append only bytes which still fit into buffer.
     *                  In both cases ArrayIndexOutOfBoundsException is thrown.
     *
     * @throws ArrayIndexOutOfBoundsException       available buffer size is insufficient
     *                                              to append specified bytes
     *
     * @return number of appended bytes
     */
    short appendResponse(byte[] respData, short offsRespData, short lenRespData, boolean truncate)
        throws ArrayIndexOutOfBoundsException;

    /**
     * Append a short to output buffer (big-endian), increase write position accordingly
     *
     * @param value     the value to be appended
     * @param truncate  see above
     * @throws ArrayIndexOutOfBoundsException   available buffer size is insufficient
     *                                          to append a short
     *
     * @return number of appended bytes
     */
    short appendResponse(short value, boolean truncate) throws ArrayIndexOutOfBoundsException;

    /**
     * Append a byte to output buffer, increase write position accordingly
     *
     * @param value the value to be appended
     *
     * @throws ArrayIndexOutOfBoundsException   available buffer size is insufficient
     *                                          to append a byte
     *
     * @return number of appended bytes
     */
    short appendResponse(byte value) throws ArrayIndexOutOfBoundsException;

    /**
     * Query length of response data so far written by System Application.
     *
     * @return length of response buffer contents
     */
    short getResponseLength();

    /**
     * Set the mode of sending out the R-APDU.
     * The effecting behavior of this state depends on the underlying protocol.
     *
     * @param is3gMode          switch between 2G or 3G mode
     * @param isWarning         true to set APDU into warning state
     */
    void setMode(boolean is3gMode, boolean isWarning);

    /**
     * Gets number of bytes available in response buffer.
     *  from current write position on
     * @return      number of bytes available in response buffer from current write position on
     *              (Note: can be different from physical array end!)
     */
    short getResponseBufferCapacity();

    /**
     * Checks if the class byte value is proprietary or inderindustry according to ISO 7816-4.
     *
     * @return  true if and only if CLA is coded as ISO interindustry (b8 != 0, first or further)
     */
    public boolean isClaInterindustry();

    /**
     * Updates the APDU's class byte with the given value.
     *
     * @param newCla (in)   new class byte
     *
     */
    void setCla(byte newCla);

    /**
     * Updates the APDU's data length with the given value.
     *
     * @param newLength (in)   new command data length
     *
     */
    void setCommandDataLength(short newLength);
}
