package core;

import java.util.EnumSet;

import core.Identifiers;
import builtintypes.NodeId;

public enum IdType {
	Numeric;
	
	public static final NodeId ID = Identifiers.IdType;
	public static EnumSet<IdType> NONE = EnumSet.noneOf( IdType.class );
	public static EnumSet<IdType> ALL = EnumSet.allOf( IdType.class );
	

	public int getValue() {
		return ordinal();
	}

	public static IdType valueOf(int value)
	{
		if (value<0 || value>=values().length) return null;
		return values()[value];
	}
	
}
