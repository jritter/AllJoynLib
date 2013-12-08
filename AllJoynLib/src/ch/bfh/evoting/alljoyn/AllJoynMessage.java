package ch.bfh.evoting.alljoyn;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Class representing a message that is sent over the network
 * @author Philémon von Bergen
 *
 */
public class AllJoynMessage implements Serializable {

	/**
	 * Type of content of a message
	 *
	 */
	public enum Type{
		SALT {
			public String toString() {
				return "SALT";
			}
		},
		IDENTITY {
			public String toString() {
				return "IDENTITY";
			}
		}, 
		NORMAL{
			public String toString() {
				return "NORMAL";
			}
		};
	}
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private String sender;
	private byte[] signature;
	private byte[] message;

	private boolean isEncrypted;
	private MessageEncrypter messageEncrypter;
	private MessageAuthenticater messageAuthenticater;
	private Type type;
	private String decryptedString = null;

	/**
	 * Create a Message object given the class used to encrypt/decrypt the message and the class to sign/verify the message
	 * @param messageEncrypter the class used to encrypt/decrypt the message
	 * @param messageAuthenticater the class to sign/verify the message
	 */
	public AllJoynMessage(MessageEncrypter messageEncrypter, MessageAuthenticater messageAuthenticater) {
		this.messageEncrypter = messageEncrypter;
		this.messageAuthenticater = messageAuthenticater;
	}

	/**
	 * Get the sender of the message
	 * @return the id of the sender of the message
	 */
	public String getSender() {
		return sender;
	}

	/**
	 * Set the sender of the message
	 * @param sender the id of the sender of the message
	 */
	public void setSender(String sender) {
		this.sender = sender;
	}

	/**
	 * Get the content of the message
	 * If the content is encrypted, it decrypts it
	 * @return the decrypted message content
	 */
	public String getMessage() {

		if(this.isEncrypted){
			if(this.decryptedString==null){
				this.decryptedString = this.messageEncrypter.decrypt(this.message);
			}
			return this.decryptedString;
		} else {
			return new String(message);
		}
	}
	
	/**
	 * Get the content of the message
	 * If the content is encrypted, it decrypts it
	 * @return the decrypted message content
	 */
	public String getMessage(PrivateKey privateKey) {

		if(this.isEncrypted){
			if(this.decryptedString==null){
				this.decryptedString = this.messageEncrypter.decrypt(this.message, privateKey);
			}
			return this.decryptedString;
		} else {
			return new String(message);
		}
	}

	/**
	 * Set the content of the message
	 * @param message the content to put into the message
	 * @param encrypt whether the content must be encrypted or not 
	 * @return whether the content was set (and encrypted if needed) correctly
	 */
	public boolean setMessage(String message, boolean encrypt) {
		this.isEncrypted = encrypt;

		//encrypt with password and salt
		if(encrypt){
			this.message = this.messageEncrypter.encrypt(message.getBytes());
			if(this.message==null){
				return false;
			} else {
				return true;
			}
		} else {
			this.message = message.getBytes();
			return true;
		}
	}
	
	public boolean setMessage(String message, boolean encrypt,
			PublicKey publicKey) {
		if (!encrypt){
			return setMessage(message, encrypt);
		}
		
		this.message = this.messageEncrypter.encrypt(message.getBytes(), publicKey);
		if(this.message==null){
			return false;
		} else {
			return true;
		}
	}

	/**
	 * Get the type of the message's content
	 * @return the type of the message's content
	 */
	public Type getType(){
		return this.type;
	}

	/**
	 * Set the type of the message's content
	 * @param type the type of the message's content
	 */
	public void setType(Type type){
		this.type = type;
	}

	/**
	 * Get whether the message's content is encrypted or not
	 * @return true if message's content is encrypted, false otherwise
	 */
	public boolean isEncrypted() {
		return isEncrypted;
	}

	/**
	 * Sign the message
	 * @return whether the signature was successful or not
	 */
	public boolean signMessage(){
		byte[] toSign = prepareSignature();

		if(toSign==null) return false;

		this.signature = messageAuthenticater.sign(toSign);
		if(signature!=null)
			return true;
		else
			return false;
	}

	/**
	 * Verify the signature of the message
	 * @param publicKey public key corresponding to the private key used to generate the signature
	 * @return whether the signature is correct or not
	 */
	public boolean verifyMessage(PublicKey publicKey){
		byte[] toVerify = prepareSignature();
		return messageAuthenticater.verifySignature(publicKey, this.signature, toVerify);
	}

	/**
	 * Method generating the content that must be signed.
	 * The type of the message, the sender, the message's content (encrypted if message is encrypted),
	 * and the flag indicating if the message is encrypted are signed
	 * @return the content that must be signed
	 */
	private byte[] prepareSignature(){
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		try {
			outputStream.write(this.type.toString().getBytes());
			outputStream.write(this.sender.getBytes());
			outputStream.write(this.message);
			byte encrypted = (byte) (isEncrypted ? 1 : 0);
			outputStream.write(encrypted);

			return outputStream.toByteArray( );

		} catch (IOException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Set the class used to sign and verify the message's signature
	 * @param messageAuthenticater the class used to sign and verify the message's signature
	 */
	public void setMessageAuthenticater(MessageAuthenticater messageAuthenticater) {
		this.messageAuthenticater=messageAuthenticater;
	}

	/**
	 * Set the class used to crypt and decrypt the message's content
	 * @param messageEncrypter the class used to crypt and decrypt the message's content
	 */
	public void setMessageEncrypter(MessageEncrypter messageEncrypter) {
		this.messageEncrypter=messageEncrypter;

	}
}
