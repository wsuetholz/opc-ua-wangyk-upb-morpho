package utils;

import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public abstract class AbstractState<StateType, ErrorType extends Throwable> implements IStatefulObject<StateType, ErrorType> {
	
	private StateType state = null;
	private StateType errorState = null;
	private ErrorType errorCause;
	
	private SnapshotArray<StateListener<StateType>> listenList = null;
	private SnapshotArray<StateListener<StateType>> notifiableList = null;
	
	public AbstractState(StateType initialState)
	{
		state = initialState;
	}
	
	public AbstractState(StateType initialState, StateType errorState)
	{
		state = initialState;
		this.errorState = errorState;
	}
	
	public synchronized StateType getState()
	{
		return state;
	}
	
	protected StateType attemptSetState(Set<StateType> prerequisiteState, StateType newState)
	{
		if (prerequisiteState == null || newState == null)
			throw new IllegalArgumentException("null arg");
		return setState(newState, null, prerequisiteState);
	}
	
	public synchronized void add
}


	