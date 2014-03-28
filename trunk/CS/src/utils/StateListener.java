package utils;

public interface StateListener<StateType> 
{
	
	void onStateTransition(IStatefulObject<StateType, ?> sender, StateType oldState, StateType newState);

}
