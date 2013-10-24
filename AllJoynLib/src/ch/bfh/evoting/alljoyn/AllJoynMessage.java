package ch.bfh.evoting.alljoyn;

import java.io.Serializable;

public class AllJoynMessage implements Serializable {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private String rawMessage;
	private String sender;
	private String signature;
	private String message;
	
	public AllJoynMessage(String sender, String signature, String message) {
		this.sender = sender;
		this.signature = signature;
		this.message = message;
	}
	
	public AllJoynMessage(String rawMessage, String sender) {
		this.rawMessage = rawMessage;
		this.sender = sender;
	}
	
	public String getRawMessage() {
		return rawMessage;
	}
	public void setRawMessage(String rawMessage) {
		this.rawMessage = rawMessage;
	}
	public String getSender() {
		return sender;
	}
	public void setSender(String sender) {
		this.sender = sender;
	}
	public String getSignature() {
		return signature;
	}
	public void setSignature(String signature) {
		this.signature = signature;
	}
	public String getMessage() {
		return message;
	}
	public void setMessage(String message) {
		this.message = message;
	}
	

	
}
