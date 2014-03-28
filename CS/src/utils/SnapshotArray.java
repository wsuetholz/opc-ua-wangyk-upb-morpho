package utils;

import java.lang.reflect.Array;

public class SnapshotArray<T> {

	private volatile T [] array;
	private final Class<T> componentType;
	
	public SnapshotArray(Class<T> componentType)
	{
		this.componentType = componentType;
		array = createArray(0);
	}
	
	@SuppressWarnings("unchecked")
	private T[] createArray(int size)
	{
		return (T[]) Array.newInstance(componentType, size);
	}
	
	public T[] getArray()
	{
		return array;
	}
	
	public synchronized void add (T item)
	{
		int oldLength = array.length;
		int newLength = oldLength + 1;
		T newArray[] = createArray(newLength);
		System.arraycopy(array, 0, newArray, 0, oldLength);
		newArray[oldLength] = item;
		array = newArray;
	}
	private synchronized int getPos(T listener)
	{
		for (int i=0; i<array.length;i++)
			if (array[i] == listener)
				return i;
		return -1;
	}
	
	public synchronized boolean remove(T item)
	{
		int pos = getPos(item);
		if (pos<0) return false;
		
		int oldLength = array.length;
		int newLength = oldLength - 1;
		T newArray[] = createArray(newLength);
		
		if (pos>0)
			System.arraycopy(array, 0, newArray, 0, pos);
		
		if(pos<newLength)
			System.arraycopy(array, pos+1, newArray, pos, newLength-pos);
		
		array = newArray;
		return true;		
	}
	
	public int size(){
		return array.length;
	}
	
	public boolean isEmpty()
	{
		return array.length == 0;
	}
	
	public void clear()
	{
		array = createArray(0);
	}
	
	
}
