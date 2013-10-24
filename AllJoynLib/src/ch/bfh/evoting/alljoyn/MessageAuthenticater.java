package ch.bfh.evoting.alljoyn;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import android.util.Base64;
import android.util.Log;

public class MessageAuthenticater {

	private static final String TAG = MessageAuthenticater.class.getSimpleName();
	
	private PublicKey publicKey;
	private PrivateKey privateKey;
	
	public void generateKeys(){
		try {
			KeyPairGenerator generator;
			generator = KeyPairGenerator.getInstance("RSA", "BC");
			generator.initialize(512, new SecureRandom());
			KeyPair pair = generator.generateKeyPair();
			publicKey = pair.getPublic();
			privateKey = pair.getPrivate();  

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		}           
	}
	
	public PublicKey decodePublicKey(String encodedKey){
		byte[] sigBytes = Base64.decode(encodedKey, Base64.DEFAULT);

		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(sigBytes);
		KeyFactory keyFact = null;
		PublicKey pubKey = null;
		try {
			keyFact = KeyFactory.getInstance("RSA", "BC");
			pubKey = keyFact.generatePublic(x509KeySpec);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			Log.e(TAG,e.getMessage());
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			Log.e(TAG,e.getMessage());
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
			Log.e(TAG,e.getMessage());
		}
		return pubKey;
	}
	
	public byte[] sign(byte[] valueToSign) {
		//sign message
		Signature instance;
		byte[] signature;
		try {
			instance = Signature.getInstance("SHA1withRSA", "BC");

			instance.initSign(privateKey);
			instance.update(valueToSign);
			signature = instance.sign();
		} catch (NoSuchAlgorithmException e1) {
			Log.e(TAG, "Unable to send message because signature failed");
			e1.printStackTrace();
			return null;
		} catch (InvalidKeyException e) {
			Log.e(TAG, "Unable to send message because signature failed");
			e.printStackTrace();
			return null;
		} catch (SignatureException e) {
			Log.e(TAG, "Unable to send message because signature failed");
			e.printStackTrace();
			return null;
		} catch (NoSuchProviderException e) {
			Log.e(TAG, "Unable to send message because signature failed");
			e.printStackTrace();
			return null;
		}

		return signature;

	}

	public boolean verifySignature(PublicKey publicKey, byte[] signature, byte[] message) {
		Signature instance;

		try {
			instance = Signature.getInstance("SHA1withRSA", "BC");

			instance.initVerify(publicKey);
			instance.update(message);
			return instance.verify(signature);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			Log.e(TAG, e.getStackTrace()+"");
			return false;
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			Log.e(TAG, e.getStackTrace()+"");
			return false;
		} catch (SignatureException e) {
			e.printStackTrace();
			Log.e(TAG, e.getStackTrace()+"");
			return false;
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			Log.e(TAG, e.getStackTrace()+"");
			return false;
		}

	}
	
	public PublicKey getMyPublicKey(){
		return this.publicKey;
	}

}
