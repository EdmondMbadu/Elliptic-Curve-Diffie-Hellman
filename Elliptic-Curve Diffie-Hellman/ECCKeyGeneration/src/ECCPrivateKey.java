import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;

import javax.crypto.KeyAgreement;

/**
 * This code is the implementation of the Elliptic Curve Diffie Hellman key
 * exchange. To implement it we use the java library crypto , and the curve secp
 * 192r1
 * 
 * @author Edmond Mbadu
 *
 */
public class ECCPrivateKey {

	public static void main(String[] args)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException {
		KeyPairGenerator keyPairGen;
		// Specify that we are using the elliptic curve implementation
		// of the Diffie Hellman protocol
		long start= System.nanoTime();
		keyPairGen = KeyPairGenerator.getInstance("EC", "SunEC");
		// Initialize the parameter class
		ECGenParameterSpec Escp;
		// Get the parameters of the particular curve secp192r1
		Escp = new ECGenParameterSpec("secp192k1");
		// Initialize the curve
		keyPairGen.initialize(Escp);

		// from Step 1 of the Diffie Hellman Protocol
		// Generate the private key for Alice

		// But first generate the Key pair:
		// It contains both the private and the public key for Alice

		KeyPair kpAlice = keyPairGen.generateKeyPair();

		// Now generate first the private key for ALice
		PrivateKey privKeyAlice = kpAlice.getPrivate();
		// Get the public key for Alice
		PublicKey pubKeyAlice = kpAlice.getPublic();
		System.out.println("Alice: " + privKeyAlice.toString());
		System.out.println("Alice: " + pubKeyAlice.toString());

		// Repeat the same steps for Bob
		KeyPair kpBob = keyPairGen.generateKeyPair();

		// Now generate first the private key for Bob
		PrivateKey privKeyBob = kpBob.getPrivate();
		// Get the public key for Bob
		PublicKey pubKeyBob = kpBob.getPublic();
		System.out.println("Bob: " + privKeyBob.toString());
		System.out.println("Bob: " + pubKeyBob.toString());
		
		
		// This is step 4 of the protocol 
		KeyAgreement ecdhAlice=KeyAgreement.getInstance("ECDH");
		// Initialize the private key of Alice 
		ecdhAlice.init(privKeyAlice);
		// Pass the value computed by Bob which is public 
		ecdhAlice.doPhase(pubKeyBob, true);
		
		// Do the same thing with Bob 
		KeyAgreement ecdhBob=KeyAgreement.getInstance("ECDH");
		ecdhBob.init(privKeyBob);
		ecdhBob.doPhase(pubKeyAlice, true);
		
		// The result( the key, which is converted to hex )  is the same for both Alice and Bob 
		System.out.println("Secret key computed by Alice: 0x"+
							(new BigInteger(1,ecdhAlice.generateSecret()).toString(16).toUpperCase()));
		
		System.out.println("Secret key computed by Bob  : 0x"+
				(new BigInteger(1,ecdhBob.generateSecret()).toString(16).toUpperCase()));
		
		System.out.println("Time in milli seconds"
				+ ": "+(System.nanoTime()-start)/1000000);
		


	}

}
