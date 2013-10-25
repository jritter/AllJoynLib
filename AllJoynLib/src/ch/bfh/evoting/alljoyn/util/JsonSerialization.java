package ch.bfh.evoting.alljoyn.util;

import com.google.gson.Gson;



/**
 * Concrete strategy for serialization using Json serialization
 * @author Philémon von Bergen
 *
 */
public class JsonSerialization implements Serialization {
	
	private Gson gson;
	
	public JsonSerialization(){
		this.gson = new Gson();
	}

	/**
	 * Serialize the given object with Json serialization
	 */
	@Override
	public String serialize(Object o) {
		return gson.toJson(o); 
	}

	/**
	 * Deserialize the given string
	 * @param s string of serialized object
	 * @param classType class to inflate
	 */
	@Override
	public Object deserialize(String s, Class<?> classType) {
		Gson gson = new Gson();
		return gson.fromJson(s, classType);
	}

}
