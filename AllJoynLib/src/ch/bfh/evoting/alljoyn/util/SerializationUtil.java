package ch.bfh.evoting.alljoyn.util;


/**
 * Context object of strategy pattern for serialization
 * @author Philémon von Bergen
 *
 */
public class SerializationUtil {
	
	private Serialization s;
	
	/**
	 * Construct an object with the given serialization type
	 * @param s concrete serialization
	 */
	public SerializationUtil(Serialization s){
		this.s = s;
	}
	
	/**
	 * Serialize the given object
	 * @param o object to serialize
	 * @return serialized object in form of a string
	 */
	public String serialize(Object o){
		return this.s.serialize(o);
	}
	
	/**
	 * Deserialize the given string
	 * @param string string to deserialize
	 * @param classType the class to inflate
	 * @return the deserialized object
	 */
	public Object deserialize(String string, Class<?> classType){
		return this.s.deserialize(string, classType);
	}
}
