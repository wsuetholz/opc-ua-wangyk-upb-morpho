package utils;

import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public interface IStatefulObject<StateType, ErrorType extends Throwable> {
	
	void addStateNotifiable(StateListener<StateType> notifiable);
	void removeStateNotifiable(StateListener<StateType> notifiable);
	
	void addStateListener(StateListener<StateType> listener);
	void removeStateListener(StateListener<StateType> listener);
	
	StateType getState();
	
	StateType waitForState(Set<StateType> set) throws ErrorType;
	StateType waitForStateUninterruptibly(Set<StateType> set) throws ErrorType;
	StateType waitForState(Set<StateType> set, long timeout, TimeUnit unit) throws ErrorType;
	
	ErrorType getError();
	
}
