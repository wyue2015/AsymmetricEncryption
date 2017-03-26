package dh;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

public class DH {
	/**
	 * 获取UserA的密钥对，并存放于Map中
	 * @return
	 * @throws Exception
	 */
	public static Map<String,Object> initKeyOfUserA() throws Exception{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
		keyPairGenerator.initialize(512);//指定DH算法的密钥对的长度
		KeyPair keyPair = keyPairGenerator.generateKeyPair();//生成密钥对
		
		//取出密钥对并放入Map集合中存放
		DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();//
		DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();
		Map<String,Object> keyMap = new HashMap<String,Object>();
		keyMap.put("publicKey", publicKey);
		keyMap.put("privateKey", privateKey);
		
		return keyMap;
	}
	
	/**
	 * 获得UserB的密钥，并存放在Map中
	 * @param publicKeyOfUserB
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> initKeyOfUserB(byte[] publicKeyOfUserA) throws Exception{
		//解析UserA提供的公钥
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyOfUserA);
		KeyFactory  keyFactory = KeyFactory.getInstance("DH");
		DHPublicKey pubKey = (DHPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);
		DHParameterSpec dhParameterSpec = pubKey.getParams();
		
		//构造UserB的密钥对
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
		keyPairGenerator.initialize(dhParameterSpec);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
//		KeyPair keyPair = keyPairGenerator.genKeyPair();//生成密钥对
		
		//取出密钥对并放入Map集合中存放
		DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();
		DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();
		Map<String, Object> keyMap = new HashMap<String, Object>();
		keyMap.put("publicKey", publicKey);
		keyMap.put("privateKey", privateKey);
		
		return keyMap;
	}
	
	/**
	 * 根据UserA的私钥+UserB的公钥 或 UserB的私钥+UserA的公钥 生成本地密钥，用于加密数据
	 * @param publicKey
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] getLocalSecretKey(byte[] publicKey, byte[] privateKey) throws Exception{
		//解析公钥，根据标准生成新的公钥
		KeyFactory keyFactory = KeyFactory.getInstance("DH");
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
		PublicKey pubKey = keyFactory.generatePublic(x509EncodedKeySpec);
		
		//解析私钥，根据标准生成新的私钥
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
		PrivateKey privKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		
		//根据新的公钥、私钥生成本地密钥
		KeyAgreement keyAgreement = KeyAgreement.getInstance(keyFactory.getAlgorithm());
		keyAgreement.init(privKey);
		keyAgreement.doPhase(pubKey, true);
		SecretKey secretKey = keyAgreement.generateSecret("AES");//可以获取DES、DESede、AES算法的本地密钥
		
		return secretKey.getEncoded();
	}
	
	
	/**
	 * 根据本地密钥+对称加密算法实现非对称加密数据
	 * @param unencrypted_data
	 * @param local_key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encrypt(byte[] unencrypted_data, byte[] local_key) throws Exception{
		SecretKey secretKey = new SecretKeySpec(local_key, "AES");//可以使用DES、DESede、AES算法结合DH加密数据
		Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] encrypted_data = cipher.doFinal(unencrypted_data);
		return encrypted_data;
	}
	
	
	/**
	 * 根据本地密钥+对称加密算法实现非对称解密数据
	 * @param encrypted_data
	 * @param local_key
	 * @return
	 * @throws Exception
	 */
	public static byte[] decrypt(byte[] encrypted_data, byte[] local_key) throws Exception{
		SecretKey secretKey = new SecretKeySpec(local_key, "AES");//可以使用DES、DESede算法结合DH加密数据
		Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] decrypted_data = cipher.doFinal(encrypted_data);
		
		return decrypted_data;
	}
	
	
	/**
	 * 从Map存放的密钥对中获取公钥
	 * @param keyMap
	 * @return
	 */
	public static byte[] getPublicKey(Map<String, Object> keyMap){
		PublicKey publicKey = (PublicKey) keyMap.get("publicKey");
		
		return publicKey.getEncoded();
	}
	
	/**
	 * 从Map存放的密钥对中获取私钥
	 * @param keyMap
	 * @return
	 */
	public static byte[] getPrivateKey(Map<String, Object> keyMap){
		PrivateKey privateKey = (PrivateKey) keyMap.get("privateKey");
		
		return privateKey.getEncoded();
	}
	
	//测试
	public static void main(String[] args) throws Exception {
		
		String unecryption_data = "hello 你好";
		
		//UserA的公钥私钥
		Map<String, Object> keyMapOfUserA = DH.initKeyOfUserA();
		byte[] publicKeyOfUserA = DH.getPublicKey(keyMapOfUserA);
		byte[] privateKeyOfUserA = DH.getPrivateKey(keyMapOfUserA);
		
		//UserB的公钥私钥
		Map<String, Object> keyMapOfUserB = DH.initKeyOfUserB(publicKeyOfUserA);
		byte[] publicKeyOfUserB = DH.getPublicKey(keyMapOfUserB);
		byte[] privateKeyOfUserB = DH.getPrivateKey(keyMapOfUserB);
		
		//生成本地密钥
		byte[] local_keyOfUserA = DH.getLocalSecretKey(publicKeyOfUserB, privateKeyOfUserA);//UserA的本地密钥
		byte[] local_keyOfUserB = DH.getLocalSecretKey(publicKeyOfUserA, privateKeyOfUserB);//UserB的本地密码
		
		//UserA加密，UserB加密数据
		byte[] encrypted_dataOfUserA = DH.encrypt(unecryption_data.getBytes(), local_keyOfUserA);//UserA加密数据
		byte[] decrypted_dataOfUserB = DH.decrypt(encrypted_dataOfUserA, local_keyOfUserB);//UserB解密数据
		System.out.println(Hex.encodeHexString(encrypted_dataOfUserA));
		System.out.println(new String(decrypted_dataOfUserB));

		//UserB加密，UserA解密数据
		byte[] encrypted_dataOfUserB = DH.encrypt(unecryption_data.getBytes(), local_keyOfUserB);
		byte[] decrypted_dataOfUserA = DH.decrypt(encrypted_dataOfUserB, local_keyOfUserA);
		System.out.println(Hex.encodeHexString(encrypted_dataOfUserB));
		System.out.println(new String(decrypted_dataOfUserA));
		
	}
	

}
