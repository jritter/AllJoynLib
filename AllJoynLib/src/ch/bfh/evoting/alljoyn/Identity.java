package ch.bfh.evoting.alljoyn;

import java.security.PublicKey;

/**
 * Class representing the identity of a peer
 * @author Philémon von Bergen
 *
 */
public class Identity {

	private String name;
	private PublicKey publicKey;

	/**
	 * Create an Identity object
	 * @param name well-known name of the peer
	 * @param publicKey public key corresponding to the private used by this peer to sign its messages
	 */
	public Identity(String name, PublicKey publicKey){
		this.name = name;
		this.publicKey = publicKey;
	}

	/**
	 * Get the well-known name of the peer
	 * @return the well-known name of the peer
	 */
	public String getName() {
		return name;
	}

	/**
	 * Set the well-known name of the peer
	 * @param name the well-known name of the peer
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * Get the public key corresponding to the private used by this peer to sign its messages
	 * @return the public key corresponding to the private used by this peer to sign its messages
	 */
	public PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Set the public key corresponding to the private used by this peer to sign its messages
	 * @param publicKey the public key corresponding to the private used by this peer to sign its messages
	 */
	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		result = prime * result
				+ ((publicKey == null) ? 0 : publicKey.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Identity other = (Identity) obj;
		if (name == null) {
			if (other.name != null)
				return false;
		} else if (!name.equals(other.name))
			return false;
		if (publicKey == null) {
			if (other.publicKey != null)
				return false;
		} else if (!publicKey.equals(other.publicKey))
			return false;
		return true;
	}

}
