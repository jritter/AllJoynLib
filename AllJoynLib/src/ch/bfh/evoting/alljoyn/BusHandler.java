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
import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.StringTokenizer;

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
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.support.v4.content.LocalBroadcastManager;
import android.util.Base64;
import android.util.Log;

public class BusHandler extends Handler {
	//org.alljoyn.PeerGroupManagerApp
	private static final String SERVICE_NAME = "ch.bfh.evoting";
	private static final String PREFS_NAME = "network_preferences";

	private SharedPreferences userDetails;


	private SimpleService   mSimpleService = new SimpleService();
	private PeerGroupManager  mGroupManager;

	private Context context;
	private SecretKey secretKey;

	/* These are the messages sent to the BusHandler from the UI. */
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
		/* Connect to an AllJoyn object. */
		this.doInit();
		this.context = ctx;
		userDetails = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
	}

	@Override
	public void handleMessage(Message msg) {
		Status status =  null;
		switch(msg.what) {
		//        case INIT: {
		//            doInit();
		//            break;
		//        }
		//        case CREATE_GROUP: {
		//        	status = doCreateGroup((String) msg.obj);
		//            break;
		//        }
		//        case DESTROY_GROUP : {
		//        	status = doDestroyGroup((String) msg.obj);
		//            break;
		//        }
		//        case JOIN_GROUP: {
		//        	status = doJoinGroup((String) msg.obj);
		//            break;
		//        }
		//        case LEAVE_GROUP : {
		//        	status = doLeaveGroup((String) msg.obj);
		//            break;
		//        }
		//        case UNLOCK_GROUP : {
		//        	status = doUnlockGroup((String) msg.obj);
		//        	break;
		//        }
		//        case LOCK_GROUP : {
		//        	status = doLockGroup((String) msg.obj);
		//        	break;
		//        }
		//        case SET_PORT : {
		//        	doSetPort((Short) msg.obj);
		//        	break;
		//        }
		//        case JOIN_OR_CREATE : {
		//        	status = doJoinOrCreate((String) msg.obj);
		//        	break;
		//        }
		case PING: {
			Bundle data = msg.getData();
			String groupName = data.getString("groupName");
			String pingString = data.getString("pingString");
			doPing(groupName, pingString);
			break;
		}
		//        case DISCONNECT: {
		//            doDisconnect();
		//            break;
		//        }
		default:
			break;
		}
	}

	public void doInit() {
		PeerGroupListener pgListener = new PeerGroupListener() {
			@Override
			public void foundAdvertisedName(String groupName, short transport) {}


			@Override
			public void lostAdvertisedName(String groupName, short transport) {
				Log.d("BusHandler", "Group "+groupName+" was destroyed.");
				Intent i = new Intent("groupDestroyed");
				i.putExtra("groupName", groupName);
				LocalBroadcastManager.getInstance(context).sendBroadcast(i);
			}

			@Override
			public void groupLost(String groupName) {
				Log.d("BusHandler", "peer left");
				LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent("participantStateUpdate"));
			}

			@Override
			public void peerAdded(String busId, String groupName, int numParticipants){
				Log.d("BusHandler", "peer added");

				//send my identity
				//SharedPreferences userDetails = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
				String myName = userDetails.getString("identification", "");

				String myKey = "key";
				String identity = "identity||"+mGroupManager.getMyPeerId()+"||"+myName+"||"+myKey;

				Message msg = obtainMessage(BusHandler.PING);
				Bundle data = new Bundle();
				data.putString("groupName", groupName);
				data.putString("pingString", identity);
				msg.setData(data);
				sendMessage(msg);

				LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent("participantStateUpdate"));
			}
		};

		ArrayList<BusObjectData> busObjects = new ArrayList<BusObjectData>();
		busObjects.add(new BusObjectData(mSimpleService, "/SimpleService"));
		mGroupManager = new PeerGroupManager(SERVICE_NAME, pgListener, busObjects);
		mGroupManager.registerSignalHandlers(this);
	}

	public void doDisconnect() {
		mGroupManager.cleanup();
		getLooper().quit();
	}

	public Status doCreateGroup(String groupName) {
		//SharedPreferences userDetails = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
		String myName = userDetails.getString("identification", "");
		nameMap.put(this.getIdentification(), new Identity(myName, "key"));
		return mGroupManager.createGroup(groupName);
	}

	public Status doDestroyGroup(String groupName) {
		return mGroupManager.destroyGroup(groupName);
	}

	public Status doJoinGroup(String groupName) {
		//SharedPreferences userDetails = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
		String myName = userDetails.getString("identification", "");
		nameMap.put(this.getIdentification(), new Identity(myName, "key"));

		String myKey = "key";
		String identity = "identity||"+mGroupManager.getMyPeerId()+"||"+myName+"||"+myKey;

		Message msg = obtainMessage(BusHandler.PING);
		Bundle data = new Bundle();
		data.putString("groupName", groupName);
		data.putString("pingString", identity);
		msg.setData(data);
		sendMessage(msg);

		return mGroupManager.joinGroup(groupName);
	}

	public Status doLeaveGroup(String groupName) {
		return mGroupManager.leaveGroup(groupName);
	}

	public Status doUnlockGroup(String groupName) {
		return mGroupManager.unlockGroup(groupName);
	}

	public Status doLockGroup(String groupName) {
		return mGroupManager.lockGroup(groupName);
	}

	public void doSetPort(short sessionPort){
		mGroupManager.setSessionPort(sessionPort);
	}

	public Status doJoinOrCreate(String groupName){
		return mGroupManager.joinOrCreateGroup(groupName).getStatus();
	}

	public void doPing(String groupName, String message) {
		// TODO sign message

		if(this.secretKey == null){
			//TODO salt
			try {
				secretKey = this.derivateKey(userDetails.getString("password", null).toCharArray(), "".getBytes());
			} catch (Exception e) {
				secretKey = null;
			}
		}

		byte[] encrypted = this.encrypt(secretKey, message.getBytes());
		if(encrypted==null){
			//encryption failed
			Log.e("BusHandler", "Message encryption failed");
			return;
		}
		String encryptedMessage = new String(Base64.encode(encrypted,Base64.DEFAULT));

		SimpleInterface simpleInterface = mGroupManager.getSignalInterface(groupName, mSimpleService, SimpleInterface.class);

		try {
			if(simpleInterface != null) {
				simpleInterface.Ping(encryptedMessage);
			}
		} catch (BusException e) {
			e.printStackTrace();
		}
	}

	public String getIdentification(){
		return mGroupManager.getMyPeerId();
	}

	public ArrayList<String> getParticipants(String groupName) {
		return mGroupManager.getPeers(groupName);
	}

	/*
	 * Simple class with the empty Ping signal
	 */
	class SimpleService implements SimpleInterface, BusObject {
		public void Ping(String Str) {}        
	}

	/*
	 * Signal Handler for the Ping signal
	 */
	@BusSignalHandler(iface = "org.alljoyn.bus.samples.simple.SimpleInterface", signal = "Ping")
	public void Ping(String str) {
		
		if(this.secretKey == null){
			//TODO salt
			try {
				secretKey = this.derivateKey(userDetails.getString("password", null).toCharArray(), "".getBytes());
			} catch (Exception e) {
				secretKey = null;
			}
		}

		//decrypt message
		byte[] decrypted = this.decrypt(secretKey, Base64.decode(str.getBytes(), Base64.DEFAULT));
		if(decrypted==null){
			//decryption failed
			Log.d("BusHandler", "Message decryption failed");
			return;
		}
		String decryptedString = new String(decrypted);

		if(decryptedString.startsWith("identity")){
			//get identity and key
			StringTokenizer tokenizer = new java.util.StringTokenizer(decryptedString, "||");
			if(tokenizer.countTokens()!=4){
				//malformed string
				Log.d("BusHandler","String was not composed of 4 parts");
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
			if(nameMap.containsKey(peerId)){
				//check if same
				if(!nameMap.get(peerId).equals(newIdentity)){
					Log.e("BusHandler","Two different data received for peer "+ peerId);
					//Not same identity and key
					//Be carefull !!!
					//TODO
				}
			} else {
				nameMap.put(peerId, newIdentity);
				//new name received, so send update
				LocalBroadcastManager.getInstance(context).sendBroadcast(new Intent("participantStateUpdate"));
			}
			//TODO check signature on str

			return;
		}

		//TODO check signature on str

		Intent i = new Intent("messageArrived");
		i.putExtra("senderId", mGroupManager.getSenderPeerId());
		i.putExtra("senderName", nameMap.get(mGroupManager.getSenderPeerId()).getName());
		i.putExtra("message", decryptedString);
		LocalBroadcastManager.getInstance(context).sendBroadcast(i);
	}

	public String getPeerWellKnownName(String peerId){

		if(!nameMap.containsKey(peerId)){
			return null;
		} else {
			return nameMap.get(peerId).getName();
		}
	}

	private HashMap<String, Identity> nameMap = new HashMap<String, Identity>();

	/**
	 * Method which crypt data using a key
	 * 
	 * @param key
	 *            The symetric key as byte array
	 * @param data
	 *            The data which should be encrypted
	 * @return The encrypted bytes
	 */
	private byte[] encrypt(SecretKey key, byte[] data) {
		/*Cipher cipher;
		MessageDigest digest;
		byte[] encrypted = null;
		try {
			// we need a 256 bit key, let's use a SHA-256 hash of the rawSeed
			// for that
			digest = MessageDigest.getInstance("SHA-256");
			digest.reset();

			SecretKeySpec skeySpec = new SecretKeySpec(digest.digest(key),
					"AES");
			cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
			encrypted = cipher.doFinal(data);
		} catch (NoSuchAlgorithmException e) {
			return null;
		} catch (NoSuchPaddingException e) {
			return null;
		} catch (InvalidKeyException e) {
			return null;
		} catch (IllegalBlockSizeException e) {
			return null;
		} catch (BadPaddingException e) {
			return null;
		}

		return encrypted;*/

		/* Encrypt the message. */
//		try{
//			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//			cipher.init(Cipher.ENCRYPT_MODE, key);
//			AlgorithmParameters params = cipher.getParameters();
//			
//			byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
//			byte[] cipherText = cipher.doFinal(data);
//			Log.e("BusHandler", "iv size int "+iv.length);
//			byte[] ivSize = ByteBuffer.allocate(4).putInt(iv.length).array(); 
//			
//			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
//			outputStream.write( ivSize );
//			outputStream.write( iv );
//			outputStream.write( cipherText );
//			
//			return outputStream.toByteArray();
//			
//		} catch (Exception ex){
//			ex.printStackTrace();
//			return null;
//		}
		return data;
	}


	/**
	 * 
	 * Method which decrypts data using a key
	 * 
	 * @param key
	 *            The symetric key as byte array
	 * @param encrypted
	 *            The data to be decrypted
	 * @return A byte array of the decrypted data if decryption was successful,
	 *         null otherwise
	 *         
	 *         http://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption
	 */
	private byte[] decrypt(SecretKey key, byte[] ciphertext) {
		/*Cipher cipher;
		MessageDigest digest;
		byte[] decrypted = null;
		try {
			// we need a 256 bit key, let's use a SHA-256 hash of the rawSeed
			// for that
			digest = MessageDigest.getInstance("SHA-256");
			digest.reset();
			SecretKeySpec skeySpec = new SecretKeySpec(digest.digest(key),
					"AES");
			cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec);
			decrypted = cipher.doFinal(encrypted);
		} catch (NoSuchAlgorithmException e) {
			return null;
		} catch (NoSuchPaddingException e) {
			return null;
		} catch (InvalidKeyException e) {
			return null;
		} catch (IllegalBlockSizeException e) {
			return null;
		} catch (BadPaddingException e) {
			return null;
		}
		return decrypted;*/
		
		/* Decrypt the message, given derived key and initialization vector. */
		
//		byte[] ivSize = Arrays.copyOfRange(ciphertext, 0, 3);
//				
//		int ivSizeInt = ByteBuffer.allocate(4).put(ivSize).getInt(0);
//		Log.e("BusHandler", "iv size int "+ivSizeInt);
//		byte[] iv = Arrays.copyOfRange(ciphertext, 4, ivSizeInt+4);
//		byte[] cipherText = Arrays.copyOfRange(ciphertext, ivSizeInt+5, ciphertext.length);
//		
//		Cipher cipher;
//		try {
//			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
//			
//			return cipher.doFinal(cipherText);
//		} catch (Exception e) {
//			ex.printStackTrace();
//			return null;
//		}	
		return ciphertext;
	}


	private SecretKey derivateKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, InvalidParameterSpecException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException{
		/* Derive the key, given password and salt. */
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
		SecretKey tmp = factory.generateSecret(spec);
		SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

		return secret;

	}

}
