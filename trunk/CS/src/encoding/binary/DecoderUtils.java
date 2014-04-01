package encoding.binary;

import core.ResponseHeader;
import builtintypes.DiagnosticInfo;

public class DecoderUtils {
	
	public static void fixResponseHeader(ResponseHeader rh)
	{
		String[] stringTable = rh.getStringTable();
		if (stringTable == null) return;
		DiagnosticInfo di = rh.getServiceDiagnostics();
		if (di==null) return;
		_fixDI(di, stringTable);
	}
	
	private static void _fixDI(DiagnosticInfo di, String[] stringTable)
	{
		di.setStringArray(stringTable);
		if (di.getInnerDiagnosticInfo()!=null)
			_fixDI(di.getInnerDiagnosticInfo(), stringTable);
	}


}
