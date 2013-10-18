package ch.bfh.evoting.alljoyn;
/******************************************************************************
 * Copyright 2013, Qualcomm Innovation Center, Inc.
 *
 *    All rights reserved.
 *    This file is licensed under the 3-clause BSD license in the NOTICE.txt
 *    file for this project. A copy of the 3-clause BSD license is found at:
 *
 *        http://opensource.org/licenses/BSD-3-Clause.
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the license is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the license for the specific language governing permissions and
 *    limitations under the license.
 *    
 *    Modified by Philémon von Bergen
 ******************************************************************************/

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import java.util.StringTokenizer;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.alljoyn.bus.BusException;
import org.alljoyn.bus.BusObject;
import org.alljoyn.bus.Status;
import org.alljoyn.bus.annotation.BusSignalHandler;

import org.alljoyn.cops.peergroupmanager.PeerGroupManager;
import org.alljoyn.cops.peergroupmanager.BusObjectData;
import org.alljoyn.cops.peergroupmanager.PeerGroupListener;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.os.SystemClock;
import android.support.v4.content.LocalBroadcastManager;
import android.util.Base64;
import android.util.Log;

public class BusHandler extends Handler {

	/*
	 * Constants
	 */
	private static final String TAG = BusHandler.class.getSimpleName();
	private static final String SERVICE_NAME = "ch.bfh.evoting";
	private static final String PREFS_NAME = "network_preferences";

	/*
	 * Security
	 */
	private static String salt_Base64 = null;
	private SecretKey secretKey;
	private KeyPair keyPair;
	private PrivateKey privateKey;

	/*
	 * AllJoyn
	 */
	private SimpleService   mSimpleService = new SimpleService();
	private PeerGroupManager  mGroupManager;

	/*
	 * Message queues
	 */
	private Queue<String> messageQueueToSend = new LinkedList<String>();

	//	private Queue<String> messagesReceivedToEarlyQueue = new LinkedList<String>();

	/*
	 * Identity informations
	 */
	private HashMap<String, Identity> nameMap = new HashMap<String, Identity>();
	private SharedPreferences userDetails;

	/*
	 * Other
	 */
	private Context context;
	private String lastJoinedNetwork;
	private boolean amIAdmin = false;
	private boolean connected = false;
	private String saltMessage;

	/* 
	 * These are the messages sent to the BusHandler from the UI.
	 */
	public static final int INIT = 1;
	public static final int CREATE_GROUP = 2;
	public static final int DESTROY_GROUP = 3;
	public static final int JOIN_GROUP = 4;
	public static final int LEAVE_GROUP = 5;
	public static final int UNLOCK_GROUP = 6;
	public static final int LOCK_GROUP = 7;
	public static final int SET_PORT = 8;
	public static final int JOIN_OR_CREATE = 9;
	public static final int DISCONNECT = 10;
	public static final int PING = 13;

	public BusHandler(Looper looper, Context ctx) {
		super(looper);
		// Connect to an AllJoyn object.
		this.doInit();
		this.context = ctx;
		userDetails = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);

		//		PrivateKey privateKey = (PrivateKey)userDetails.getString("privatekey", null);
		//		try {
		//			keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		//			privateKey = keyPair.getPrivate();
		//		} catch (NoSuchAlgorithmException e) {
		//			// TODO Auto-generated catch block
		//			e.printStackTrace();
		//		}
	}


	@Override
	public void handleMessage(Message msg) {
		Status status =  null;
		switch(msg.what) {
		case INIT: {
			doInit();
			break;
		}
		case CREATE_GROUP: {
			status = doCreateGroup((String) msg.obj);
			Log.d(TAG, "status of group creation "+ status);
			switch(status){
			case OK:
				LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent("NetworkServiceStarted"));
				break;
			case ALLJOYN_JOINSESSION_REPLY_ALREADY_JOINED:
				LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent("NetworkServiceStarted"));
				break;
			case BUS_REPLY_IS_ERROR_MESSAGE:
				LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent("networkConnectionFailed"));
				break;
			default:
				LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent("networkConnectionFailed"));
				break;
			}
			break;
		}
		case DESTROY_GROUP : {
			status = doDestroyGroup((String) msg.obj);
			break;
		}
		case JOIN_GROUP: {
			status = doJoinGroup((String) msg.obj); 
			Log.d(TAG, "status of group join "+ status);
			switch(status){
			case OK:
				LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent("NetworkServiceStarted"));
				break;
			case ALLJOYN_JOINSESSION_REPLY_ALREADY_JOINED:
				LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent("NetworkServiceStarted"));
				break;
			case BUS_REPLY_IS_ERROR_MESSAGE:
				LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent("networkConnectionFailed"));
				break;
			default:
				LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent("networkConnectionFailed"));
				break;
			}
			break;
		}
		case LEAVE_GROUP : {
			status = doLeaveGroup((String) msg.obj);
			break;
		}
		case UNLOCK_GROUP : {
			status = doUnlockGroup((String) msg.obj);
			break;
		}
		case LOCK_GROUP : {
			status = doLockGroup((String) msg.obj);
			break;
		}
		case SET_PORT : {
			doSetPort((Short) msg.obj);
			break;
		}
		case JOIN_OR_CREATE : {
			status = doJoinOrCreate((String) msg.obj);
			break;
		}
		case PING: {
			Bundle data = msg.getData();
			String groupName = data.getString("groupName");
			String pingString = data.getString("pingString");
			boolean encrypted = data.getBoolean("encrypted", true);
			doPing(groupName, pingString, encrypted);
			break;
		}
		case DISCONNECT: {
			doDisconnect();
			break;
		}
		default:
			break;
		}
	}

	/******************************************************************************
	 * 
	 * Network actions
	 *
	 ******************************************************************************/

	private void doInit() {
		PeerGroupListener pgListener = new PeerGroupListener() {
			@Override
			public void foundAdvertisedName(String groupName, short transport) {}

			@Override
			public void lostAdvertisedName(String groupName, short transport) {
				Log.d(TAG, "Group "+groupName+" was destroyed.");
				Intent i = new Intent("groupDestroyed");
				i.putExtra("groupName", groupName);
				LocalBroadcastManager.getInstance(context).sendBroadcast(i);
			}

			@Override
			public void groupLost(String groupName) {
				Log.d(TAG, "peer left");
				LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent("participantStateUpdate"));
			}

			@Override
			public void peerAdded(String busId, String groupName, int numParticipants){
				Log.d(TAG, "peer added");

				final String group = groupName;

				// admin sends the salt to all, but especially for the added peer
				if(amIAdmin){
					Log.e(TAG, "Sending salt");
					Message msg = obtainMessage(BusHandler.PING);
					Bundle data = new Bundle();
					data.putString("groupName", group);
					data.putString("pingString", "salt||"+salt_Base64);
					data.putBoolean("encrypted", false);
					msg.setData(data);
					sendMessage(msg);
				}

				
				//update UI
				LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent("participantStateUpdate"));
				
			}
		};

		ArrayList<BusObjectData> busObjects = new ArrayList<BusObjectData>();
		busObjects.add(new BusObjectData(mSimpleService, "/SimpleService"));
		mGroupManager = new PeerGroupManager(SERVICE_NAME, pgListener, busObjects);
		mGroupManager.registerSignalHandlers(this);
	}

	private void doDisconnect() {
		mGroupManager.cleanup();
		connected = false;
		getLooper().quit();
	}

	private Status doCreateGroup(String groupName) {
		//If group already exists, connection will fail
		//if multicast is not supported on the network, listFoundGroups
		//will be empty, so this it will only be detected during the group creation
		//that this name is already used.
		if(mGroupManager.listFoundGroups().contains(groupName)){
			return Status.FAIL;
		}
		resetSalt();
		
		//Create a salt and derive the key
		salt_Base64 = Base64.encodeToString(SecureRandom.getSeed(8), Base64.DEFAULT);
		secretKey = this.derivateKey(userDetails.getString("password", salt_Base64).toCharArray(), Base64.decode(salt_Base64, Base64.DEFAULT));

		//create the group
		Status status = mGroupManager.createGroup(groupName);
		if(status == Status.OK){
			//save my identity
			String myName = userDetails.getString("identification", "");
			nameMap.put(this.getIdentification(), new Identity(myName, "key"));
			//some flags
			lastJoinedNetwork = groupName;
			amIAdmin = true;
			connected = true;

		}
		return status;
	}

	private Status doDestroyGroup(String groupName) {
		amIAdmin = false;
		resetSalt();
		return mGroupManager.destroyGroup(groupName);
	}

	private Status doJoinGroup(String groupName) {
		resetSalt();
		Status status = mGroupManager.joinGroup(groupName);
		Log.e(TAG, "Satus of join is"+status);
		if(status == Status.OK){
			//save my identity
			String myName = userDetails.getString("identification", "");
			nameMap.put(this.getIdentification(), new Identity(myName, "key"));

			lastJoinedNetwork = groupName;
			connected = true;

			if(saltMessage!=null){
				this.saltReceived(saltMessage);
			}
			saltMessage = null;
		}
		return status;
	}

	private Status doLeaveGroup(String groupName) {
		return mGroupManager.leaveGroup(groupName);
	}

	private Status doUnlockGroup(String groupName) {
		return mGroupManager.unlockGroup(groupName);
	}

	private Status doLockGroup(String groupName) {
		return mGroupManager.lockGroup(groupName);
	}

	private void doSetPort(short sessionPort){
		mGroupManager.setSessionPort(sessionPort);
	}

	private Status doJoinOrCreate(String groupName){
		return mGroupManager.joinOrCreateGroup(groupName).getStatus();
	}

	/******************************************************************************
	 * 
	 * Network informations
	 *
	 ******************************************************************************/

	/**
	 * Get my peer unique id
	 * @return my peer unique id
	 */
	public String getIdentification(){
		return mGroupManager.getMyPeerId();
	}

	/**
	 * Get all participant of the given group
	 * @param groupName
	 * @return list of participant unique id
	 */
	public ArrayList<String> getParticipants(String groupName) {
		return mGroupManager.getPeers(groupName);
	}

	/**
	 * Get the well-known name of the given peer
	 * @param peerId the peer unique identificator
	 * @return the well-known name of the given peer
	 */
	public String getPeerWellKnownName(String peerId){

		if(!nameMap.containsKey(peerId)){
			return null;
		} else {
			return nameMap.get(peerId).getName();
		}
	}
	
	private void resetSalt(){
		salt_Base64 = null;
		secretKey = null;
	}


	/******************************************************************************
	 * 
	 * Message processing
	 *
	 ******************************************************************************/

	/**
	 * Send a message to the given group
	 * @param groupName group to send the message to
	 * @param message message to send
	 * @param encrypted indicate if message must be encrypted or not 
	 */
	private void doPing(String groupName, String message, boolean encrypted) {

		if(this.secretKey==null && encrypted){
			this.messageQueueToSend.add(message);
			return;
		}

		byte[] valueToSign;
		String messageToSend;
		if(encrypted){
			valueToSign = this.encrypt(secretKey, message.getBytes());
			messageToSend = Base64.encodeToString(valueToSign, Base64.DEFAULT);
			if(valueToSign==null){
				//encryption failed
				Log.e(TAG, "Message encryption failed");
				return;
			}
		} else {
			valueToSign = message.getBytes();
			messageToSend = message;
		}

		//TODO deplace in helper method
		//sign message
		//		Signature instance;
		//		byte[] signature;
		//		try {
		//			instance = Signature.getInstance("SHA1withRSA");
		//
		//			instance.initSign(privateKey);
		//			instance.update(finalMessage);
		//			signature = instance.sign();
		//		} catch (NoSuchAlgorithmException e1) {
		//			Log.e(TAG, "Unable to send message because signature failed");
		//			e1.printStackTrace();
		//			return;
		//		} catch (InvalidKeyException e) {
		//			Log.e(TAG, "Unable to send message because signature failed");
		//			e.printStackTrace();
		//			return;
		//		} catch (SignatureException e) {
		//			Log.e(TAG, "Unable to send message because signature failed");
		//			e.printStackTrace();
		//			return;
		//		}
		//
		//		String toSend =  Base64.encodeToString(signature,Base64.DEFAULT) + "||" + Base64.encodeToString(finalMessage,Base64.DEFAULT);

		SimpleInterface simpleInterface = mGroupManager.getSignalInterface(groupName, mSimpleService, SimpleInterface.class);

		try {
			if(simpleInterface != null) {
				Log.e(TAG,"sending message");
				simpleInterface.Ping(messageToSend);
			}
		} catch (BusException e) {
			e.printStackTrace();
		}
	}

	/*
	 * Simple class with the empty Ping signal
	 */
	class SimpleService implements SimpleInterface, BusObject {
		public void Ping(String Str) {}        
	}

	/**
	 * Signal Handler for the Ping signal
	 * This method receives the message from the other peers
	 */
	@BusSignalHandler(iface = "org.alljoyn.bus.samples.simple.SimpleInterface", signal = "Ping")
	public void Ping(String str) {

		if(str==null) return;

		//Check if the message contains the salt
		if(str.startsWith("salt||") && salt_Base64==null){
			//if connection not finished, store the message
			if(!connected){
				saltMessage = str;
			} else {
				this.saltReceived(str);
			}
			return;
		}

		//if I don't have the salt to compute the key to decrypt the messaage, ignore it
		if(secretKey == null){
			return;
		}

		//TODO check signature on str

		//Decrypt the message
		byte[] decrypted = this.decrypt(secretKey, Base64.decode(str.getBytes(), Base64.DEFAULT));
		if(decrypted==null){
			//decryption failed
			Log.d(TAG, "Message decryption failed");
			return;
		}
		String decryptedString = new String(decrypted);

		//Check if message contain an identity
		if(decryptedString.startsWith("identity")){
			//Get the name and its corresponding key key
			StringTokenizer tokenizer = new java.util.StringTokenizer(decryptedString, "||");
			if(tokenizer.countTokens()!=4){
				//malformed string
				Log.d(TAG,"String was not composed of 4 parts");
				return;
			}
			//first come "identity"
			tokenizer.nextElement();
			//then peerId
			String peerId = (String)tokenizer.nextElement();
			//then peerName
			String peerName = (String)tokenizer.nextElement();
			//and finally peerKey
			String peerKey = (String)tokenizer.nextElement();

			Identity newIdentity = new Identity(peerName, peerKey);

			//Check if identity is already known
			if(nameMap.containsKey(peerId)){
				//if yes, check if the same identity as received before
				if(!nameMap.get(peerId).equals(newIdentity)){
					//If not someone is trying to impersonate somebody else
					//TODO
					Log.e(TAG,"Two different data received for peer "+ peerId);	
					return;
				}
			} else {
				//Save the new identity
				Log.e(TAG,"identity received "+newIdentity.getName());
				nameMap.put(peerId, newIdentity);
				this.sendMyIdentity();
				//Update the UI
				LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent("participantStateUpdate"));
			}
			return;
		}

		//Send the message to the app
		Intent i = new Intent("messageArrived");
		i.putExtra("senderId", mGroupManager.getSenderPeerId());
		i.putExtra("senderName", nameMap.get(mGroupManager.getSenderPeerId()).getName());
		i.putExtra("message", decryptedString);
		LocalBroadcastManager.getInstance(context).sendBroadcast(i);
	}

	/******************************************************************************
	 * 
	 * Helper methods
	 *
	 ******************************************************************************/


	/**
	 * Extract the salt and open the queued messages that could not be decrypted before
	 * @param str message containing the salt
	 */
	private void saltReceived(String str){
		Log.d(TAG,"Salt received: "+str);

		StringTokenizer tokenizer = new java.util.StringTokenizer(str, "||");
		if(tokenizer.countTokens()!=2){
			//malformed string
			Log.d(TAG,"Salt string was not composed of 2 parts");
			return;
		}
		//first is "salt" prefix
		tokenizer.nextElement();
		//then comes the salt
		salt_Base64 = (String)tokenizer.nextElement();

		secretKey = this.derivateKey(userDetails.getString("password", salt_Base64).toCharArray(), Base64.decode(salt_Base64, Base64.DEFAULT));
		Log.d(TAG,"Key is "+secretKey);

		//send my identity
		this.sendMyIdentity();

		//treat message queue
		while(!this.messageQueueToSend.isEmpty()){
			this.doPing(lastJoinedNetwork, messageQueueToSend.poll(), true);
		}
	}

	/**
	 * Send my identity to the other peers
	 */
	private void sendMyIdentity(){
		Log.e(TAG,"Send my identity");
		String myName = userDetails.getString("identification", "");

		String myKey = "key";
		String identity = "identity||"+mGroupManager.getMyPeerId()+"||"+myName+"||"+myKey;

		Message msg = obtainMessage(BusHandler.PING);
		Bundle data = new Bundle();
		data.putString("groupName", lastJoinedNetwork);
		data.putString("pingString", identity);
		msg.setData(data);
		sendMessage(msg);
	}


	/******************************************************************************
	 * 
	 * Cryptography
	 *
	 ******************************************************************************/

	/**
	 * Method which crypt data using a key
	 * @param key The symetric key
	 * @param data The data which should be encrypted
	 * @return The encrypted bytes, null otherwise
	 * 
	 * Inspired from http://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption
	 */
	private byte[] encrypt(SecretKey key, byte[] data) {

		Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			AlgorithmParameters params = cipher.getParameters();

			byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
			byte[] cipherText = cipher.doFinal(data); 

			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			outputStream.write( iv );
			outputStream.write( cipherText );

			Log.e(TAG,"message encrypted");
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
	 * @return A byte array of the decrypted data if decryption was successful,
	 *         null otherwise
	 *         
	 * Inspired from http://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption
	 */
	private byte[] decrypt(SecretKey key, byte[] ciphertext) {

		//iv is same as block size: for AES => 128 bits = 16 bytes
		byte[] iv = Arrays.copyOfRange(ciphertext, 0, 16);
		byte[] cipherText = Arrays.copyOfRange(ciphertext, 16, ciphertext.length);

		Cipher cipher;
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

			return cipher.doFinal(cipherText);

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
	private SecretKey derivateKey(char[] password, byte[] salt) {

		SecretKeyFactory factory;
		try {
			factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

			//1000 iteration should be enough since the attack has to be done online and
			//salt changes for each group
			KeySpec spec = new PBEKeySpec(password, salt, 1000, 256);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
			return secret;
		} catch (NoSuchAlgorithmException e) {
			Log.d(TAG, e.getMessage()+" ");
			e.printStackTrace();
			return null;
		} catch (InvalidKeySpecException e) {
			Log.d(TAG, e.getMessage()+" ");
			e.printStackTrace();
			return null;
		}

	}

}
