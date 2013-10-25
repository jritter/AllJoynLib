package ch.bfh.evoting.alljoyn.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.io.StreamCorruptedException;


import android.util.Base64;

/**
 * Concrete strategy for serialization using Java serialization
 * @author Philémon von Bergen
 *
 */
public class JavaSerialization implements Serialization {

	/**
	 * Serialize the given object with Java serialization
	 * Return string is base64 encoded
	 */
	@Override
	public String serialize(Object o) {
		if(!(o instanceof Serializable)){
			throw new UnsupportedOperationException();
		}
		
		ByteArrayOutputStream out = null;
        try {
        	out = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(out);
			oos.writeObject(o);
			oos.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
        String string = new String(Base64.encode(out.toByteArray(),Base64.DEFAULT));

        return string;
	}

	/**
	 * Deserialize the given string base64 encoded
	 * @param s encoded serialized object
	 * @param classType not needed for Java serialization
	 */
	@Override
	public Object deserialize(String s, Class<?> classType) {
		Object o = null;
		try {
			InputStream in =new ByteArrayInputStream(Base64.decode(s,Base64.DEFAULT));
			ObjectInputStream ois = new ObjectInputStream(in);
			o = ois.readObject();
			ois.close();
		} catch (StreamCorruptedException e1) {
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}
		return o;
	}

}
