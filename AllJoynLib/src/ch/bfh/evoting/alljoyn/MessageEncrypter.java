package ch.bfh.evoting.alljoyn;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

public class MessageEncrypter {
	
	private static final String TAG = MessageEncrypter.class.getSimpleName();
	private static final String PREFS_NAME = "network_preferences";

	
	private SharedPreferences userDetails;

	
	private SecretKey secretKey;
	private byte[] salt;
	private String password;
	
	private boolean isReady = false;
	private Context context;
	
	
	public MessageEncrypter(Context context){
		this.context = context;
	}
	/**
	 * Method which crypt data using a key
	 * @param key The symetric key
	 * @param data The data which should be encrypted
	 * @return The encrypted bytes, null otherwise
	 * 
	 * Inspired from http://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption
	 */
	public byte[] encrypt(byte[] data) {

		Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			AlgorithmParameters params = cipher.getParameters();

			byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
			byte[] cipherText = cipher.doFinal(data); 

			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			outputStream.write( iv );
			outputStream.write( cipherText );

			return outputStream.toByteArray();
		} catch (NoSuchAlgorithmException e) {
			Log.d(TAG, e.getMessage()+" ");
			e.printStackTrace();
			return null;
		} catch (NoSuchPaddingException e) {
			Log.d(TAG, e.getMessage()+" ");
			e.printStackTrace();
			return null;
		} catch (InvalidKeyException e) {
			Log.d(TAG, e.getMessage()+" ");
			e.printStackTrace();
			return null;
		} catch (InvalidParameterSpecException e) {
			Log.d(TAG, e.getMessage()+" ");
			e.printStackTrace();
			return null;
		} catch (IllegalBlockSizeException e) {
			Log.d(TAG, e.getMessage()+" ");
			e.printStackTrace();
			return null;
		} catch (BadPaddingException e) {
			Log.d(TAG, e.getMessage()+" ");
			e.printStackTrace();
			return null;
		} catch (IOException e) {
			Log.d(TAG, e.getMessage()+" ");
			e.printStackTrace();
			return null;
		}
	}


	/**
	 * 
	 * Method which decrypts data using a key
	 * @param key The symetric key
	 * @param encrypted The data to be decrypted
	 * @return the decrypted string if decryption was successful,
	 *         null otherwise
	 *         
	 * Inspired from http://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption
	 */
	public String decrypt(byte[] ciphertext) {

		//iv is same as block size: for AES => 128 bits = 16 bytes
		byte[] iv = Arrays.copyOfRange(ciphertext, 0, 16);
		byte[] cipherText = Arrays.copyOfRange(ciphertext, 16, ciphertext.length);

		Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

			cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

			return new String(cipher.doFinal(cipherText));

		} catch (NoSuchAlgorithmException e) {
			Log.d(TAG, e.getMessage()+" ");
			e.printStackTrace();
			return null;
		} catch (NoSuchPaddingException e) {
			Log.d(TAG, e.getMessage()+" ");
			e.printStackTrace();
			return null;
		} catch (InvalidKeyException e) {
			Log.d(TAG, e.getMessage()+" ");
			e.printStackTrace();
			return null;
		} catch (InvalidAlgorithmParameterException e) {
			Log.d(TAG, e.getMessage()+" ");
			e.printStackTrace();
			return null;
		} catch (IllegalBlockSizeException e) {
			Log.d(TAG, e.getMessage()+" ");
			e.printStackTrace();
			return null;
		} catch (BadPaddingException e) {
			Log.d(TAG, e.getMessage()+" ");
			e.printStackTrace();
			return null;
		}
	}
	



	/**
	 * Key derivation method from password
	 * @param password password to derive
	 * @param salt salt to take into account to derive the key
	 * @return the symmetric key
	 * Inspired from http://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption
	 */
	private void derivateKey(char[] password) {
				
		SecretKeyFactory factory;
		try {
			factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

			//1000 iteration should be enough since the attack has to be done online and
			//salt changes for each group
			KeySpec spec = new PBEKeySpec(password, this.salt, 1000, 256);
			SecretKey tmp = factory.generateSecret(spec);
			secretKey = new SecretKeySpec(tmp.getEncoded(), "AES");
			this.isReady = true;
		} catch (NoSuchAlgorithmException e) {
			Log.d(TAG, e.getMessage()+" ");
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			Log.d(TAG, e.getMessage()+" ");
			e.printStackTrace();
		}

	}
	
	public void generateSalt(){
		userDetails = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
		this.password = userDetails.getString("group_password", null);
		
		this.salt = SecureRandom.getSeed(8);
		this.derivateKey(password.toCharArray());
		Log.d(TAG,"Salt is "+salt);
	}
	
	public byte[] getSalt(){
		return salt;
	}
	
	public void setSalt(String salt){
		userDetails = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
		this.password = userDetails.getString("group_password", null);
		
		this.salt = Base64.decode(salt, Base64.DEFAULT);
		Log.d(TAG,"Saving salt "+salt);
		this.derivateKey(password.toCharArray());
	}
	
	public void reset(){
		this.isReady=false;
		this.salt = null;
		this.secretKey = null;
	}
	
	public boolean isReady(){
		return isReady;
	}

}
