package asymmetric;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import util.CryptoTools;

public class ECDH_decrypt {
	public static void main(String[] args) throws Exception{
		/*KeyPairGenerator alice_kpg = KeyPairGenerator.getInstance("EC");
		alice_kpg.initialize(256);
		KeyPair alic_kp = alice_kpg.generateKeyPair();
		PublicKey alice_public_key = alic_kp.getPublic();
		PrivateKey alic_private_key = alic_kp.getPrivate();*/
		
		byte[] alice_public_key = CryptoTools.hexToBytes("3059301306072A8648CE3D020106082A8648CE3D0301070342000450C35C2FB11926C2C91E089CFC743F9D942EE14B8D42E25AE6588C4F93DDFF6ACDF520F74AF3E2500EF2A5E2C346D4DA7E92C1F89AD9FD4F3ED1B97DC3F39DC8");
		byte[] alic_private_key = CryptoTools.hexToBytes("3041020100301306072A8648CE3D020106082A8648CE3D0301070427302502010104200FE89D3070EECF985F971851B088EC97605A08D037F3CF3463FED25BCE0037B5");
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(alice_public_key);
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		PublicKey alice_public = keyFactory.generatePublic(keySpec);
		
		byte[] bob_public_key = CryptoTools.hexToBytes("3059301306072A8648CE3D020106082A8648CE3D03010703420004678DF0E72D7FC86006174E506B1729081E5D1201936EBA8A39E8741E4F713F8C29AE2E62038D95B36A585E2A87FEA73BE482611115457A3D3823EA5D79E31154");
		byte[] bob_private_key = CryptoTools.hexToBytes("3041020100301306072A8648CE3D020106082A8648CE3D030107042730250201010420090145EB296FD96158EDF5E59D20EBB8E7332BBE150784D91900DB2006980127");
		PKCS8EncodedKeySpec keySpec2 = new PKCS8EncodedKeySpec(bob_private_key);
		PrivateKey bob_private = keyFactory.generatePrivate(keySpec2);
		
		byte[] ct = CryptoTools.hexToBytes("B1803ED24B595CCB11AA39473DC7B10B");
		byte[] iv = CryptoTools.hexToBytes("4000000001000000000C00000001000C");
		
		KeyAgreement ka = KeyAgreement.getInstance("ECDH");
		ka.init(bob_private);
		ka.doPhase(alice_public, true);
		byte[] shared_secret = ka.generateSecret();
		
		SecretKeySpec secret = new SecretKeySpec(shared_secret, "AES");
		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		
		AlgorithmParameterSpec aps = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, secret, aps);
		
		byte[] pt = cipher.doFinal(ct);
		for (int i = 0; i < pt.length; i++) {
			System.out.print(Character.toString((char)pt[i]));
		}
	}

}
