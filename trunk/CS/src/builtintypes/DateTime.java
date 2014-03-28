package builtintypes;

import java.util.Date;

import core.Identifiers;

public class DateTime {
	protected String dateTime;
	public static final NodeId ID = Identifiers.DateTime;
	
	public String getCurrentDateTime()
	{	
		return this.dateTime;
	}
	public void setDateTime()
	{
		Date currentTime = new Date();
		this.dateTime = currentTime.toString();
	}
}
