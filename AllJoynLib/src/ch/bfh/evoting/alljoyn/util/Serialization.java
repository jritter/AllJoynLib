package ch.bfh.evoting.alljoyn.util;

/**
 * Serialization interface for strategy pattern
 * @author Philémon von Bergen
 *
 */
public interface Serialization {
	
	public String serialize(Object o);
	
	public Object deserialize(String s, Class<?> classType);

}
