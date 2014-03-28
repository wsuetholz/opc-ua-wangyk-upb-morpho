package core;

import java.util.EnumSet;
import builtintypes.NodeId;
import core.Identifiers;
import builtintypes.Enumeration;

public enum MessageSecurityMode implements Enumeration {
	
	Invaild,
	None,
	Sign,
	SignAndEncrypt;

	public static final NodeId ID = Identifiers.MessageSecurityMode;
	public static EnumSet<MessageSecurityMode> NONE = EnumSet.noneOf(MessageSecurityMode.class);
	public static EnumSet<MessageSecurityMode> ALL = EnumSet.allOf(MessageSecurityMode.class);
	
	@Override
	public int getValue() {
		return ordinal();
	}
	
	public static MessageSecurityMode valueOf(int value)
	{
		if (value <0 || value >= values().length) return null;
		return values()[value];
		
	}
	public boolean hasSigning()
	{
		return this==Sign || this == SignAndEncrypt;
	}
	public boolean hasEncryption()
	{
		return this == SignAndEncrypt;
	}
}
