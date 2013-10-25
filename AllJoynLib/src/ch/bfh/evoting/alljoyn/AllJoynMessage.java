package ch.bfh.evoting.alljoyn;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.PublicKey;

public class AllJoynMessage implements Serializable {

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

	public AllJoynMessage(MessageEncrypter messageEncrypter, MessageAuthenticater messageAuthenticater) {
		this.messageEncrypter = messageEncrypter;
		this.messageAuthenticater = messageAuthenticater;
	}

	public String getSender() {
		return sender;
	}

	public void setSender(String sender) {
		this.sender = sender;
	}

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

	public Type getType(){
		return this.type;
	}

	public void setType(Type type){
		this.type = type;
	}

	public boolean isEncrypted() {
		return isEncrypted;
	}

	public boolean signMessage(){
		byte[] toSign = prepareSignature();

		if(toSign==null) return false;

		this.signature = messageAuthenticater.sign(toSign);
		if(signature!=null)
			return true;
		else
			return false;
	}

	public boolean verifyMessage(PublicKey publicKey){
		byte[] toVerify = prepareSignature();
		return messageAuthenticater.verifySignature(publicKey, this.signature, toVerify);
	}

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

	public void setMessageAuthenticater(MessageAuthenticater messageAuthenticater) {
		this.messageAuthenticater=messageAuthenticater;
	}

	public void setMessageEncrypter(MessageEncrypter messageEncrypter) {
		this.messageEncrypter=messageEncrypter;

	}
}
