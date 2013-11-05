package ch.bfh.evoting.alljoyn;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
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

import android.util.Base64;
import android.util.Log;

/**
 * Class used to encrypt and decrypt messages
 * @author Philémon von Bergen
 *
 */
public class MessageEncrypter {
	
	private static final String TAG = MessageEncrypter.class.getSimpleName();
	
	private SecretKey secretKey;
	private byte[] salt;
	private String password;
	
	private boolean isReady = false;

	private Object saltShortDigest;
	
	/**
	 * Method that encrypts data
	 * @param data The data which should be encrypted
	 * @return The encrypted bytes, null if encryption failed
	 * 
	 */
	public byte[] encrypt(byte[] data) {
		//Inspired from http://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption

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
	 * Method that decrypts data
	 * @return the decrypted string if decryption was successful,
	 *         null otherwise
	 *         
	 */
	public String decrypt(byte[] ciphertext) {
		//Inspired from http://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption

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
	 * Key derivation method from the given password
	 * @param password password to derive
	 */
	private void derivateKey(char[] password) {
		//Inspired from http://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption
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
	
	/**
	 * Generate a salt that will be used in the symmetric key derivation
	 */
	public void generateSalt(){
		this.salt = SecureRandom.getSeed(8);
		this.derivateKey(password.toCharArray());
		Log.d(TAG,"Salt is "+salt);
	}
	
	/**
	 * Set the salt
	 * @param salt the Base64 encoded salt
	 */
	public void setSalt(String salt){
		byte[] tempSalt = Base64.decode(salt, Base64.DEFAULT);
		if(this.saltShortDigest.equals(getSaltShortDigest(tempSalt))){
			Log.d(TAG, "received salt digest is "+saltShortDigest+" and computed digest from received salt is "+getSaltShortDigest(tempSalt));
			this.salt = tempSalt;
			Log.d(TAG,"Saving salt "+salt);
			this.derivateKey(password.toCharArray());
		} else {
			Log.e(TAG,"Salt is false!");
		}	
	}
	
	/**
	 * Get the earlier generated or set salt
	 * @return the earlier generated or set salt
	 */
	public byte[] getSalt(){
		return salt;
	}
	
	/**
	 * Compute a truncated digest on the salt
	 * We only take the three first letters (not chars!) of the Base64 encoded digest, because
	 * this truncated digest must be transmitted with the group password (only letters)
	 * @param salt the salt from on we want to compute the digest 
	 * @return the three first letters of the Base64 encoded digest
	 */
	public String getSaltShortDigest(byte[] salt){
		if(salt==null) return "";
		
		//Compute the digest
		MessageDigest md;
		String saltHash;
		Log.d(TAG, "Computing salt digest");
		try {
			md = MessageDigest.getInstance("SHA-1");
			md.update(salt, 0, salt.length);
			saltHash = Base64.encodeToString(md.digest(),Base64.DEFAULT);
		} catch (NoSuchAlgorithmException e) {
			Log.e(TAG, "Digest of salt could not be computed");
			e.printStackTrace();
			return null;
		}
		
		//Truncate the digest
		String shortDigest = "";
		int i=0;
		while(shortDigest.length()<3){
			char c = saltHash.charAt(i);
			if(Character.isLetter(c)){
				shortDigest = shortDigest.concat(String.valueOf(Character.toLowerCase(c)));
			}
			i++;
			if(i>=saltHash.length()){
				break;
			}
		}
		Log.d(TAG, "Short digest is "+shortDigest);

		return shortDigest;
	}
	
	/**
	 * Set the password used to derivate the symmetric key
	 * @param password the password used to derivate the symmetric key
	 */
	public void setPassword(String password){
		this.password = password;
	}
	
	/**
	 * Set the truncated digest of the salt that will be received later
	 * @param saltShortDigest the truncated digest of the salt that will be received later
	 */
	public void setSaltShortDigest(String saltShortDigest){
		this.saltShortDigest = saltShortDigest;
	}
	
	/**
	 * Reset the state of the message encrypter
	 */
	public void reset(){
		this.isReady=false;
		this.salt = null;
		this.secretKey = null;
		this.password = null;
		this.saltShortDigest = null;
	}
	
	/**
	 * Indicate if the symmetric key has been derivated and message encrypter is ready to encrypt/decrypt
	 * @return true is message encrypter is ready to encrypt/decrypt, false otherwise
	 */
	public boolean isReady(){
		return isReady;
	}

}
