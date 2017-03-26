package rsa;

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

import org.apache.commons.codec.binary.Hex;


public class RSA {
	
	/**
	 * 生成密钥对，并存放于Map中
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> initKey() throws Exception{
		//获取密钥
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");//获取密钥对生成器
		keyPairGenerator.initialize(512);//初始化密钥生成器
		KeyPair keyPair = keyPairGenerator.generateKeyPair();//产生密钥对
		PublicKey publicKey = keyPair.getPublic();//从密钥对中获取公钥
		PrivateKey privateKey = keyPair.getPrivate();//从密钥对中获取私钥
		
		//将生成的密钥对放入Map中存放
		Map<String, Object> keyMap = new HashMap<String, Object>();
		keyMap.put("publicKey", publicKey);
		keyMap.put("privateKey", privateKey);
		
		return keyMap;
	}
	
	
	/**
	 * 根据私钥，对数据进行加密操作；使用PKCS8EncodedKeySpec，注意与公钥加密的区别
	 * @param unencryptionData
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptionByPrivateKey(byte[] unencryptionData, byte[] privateKey) throws Exception{
		//根据私钥字节获取新的私钥
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		
		//加密数据
		Cipher cipher = Cipher.getInstance(privKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, privKey);
		byte[] encryption_data = cipher.doFinal(unencryptionData);
		
		return encryption_data;
	}
	
	
	/**
	 * 根据公钥，对数据进行加密操作；使用X509EncodedKeySpec，注意与私钥加密的区别
	 * @param unencryptionData
	 * @param publicKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptionByPublicKey(byte[] unencryptionData, byte[] publicKey) throws Exception{
		//根据公钥字节获取新的公钥
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
		PublicKey pubKey = keyFactory.generatePublic(x509EncodedKeySpec);
		
		//加密数据
		Cipher cipher = Cipher.getInstance(pubKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		byte[] encryption_data = cipher.doFinal(unencryptionData);
		
		return encryption_data;
	}
	
	/**
	 * 根据私钥，对数据进行解密操作；使用PKCS8EncodedKeySpec，注意与公钥解密的区别
	 * @param encryptionData
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] decrypitonByPrivateKey(byte[] encryptionData, byte[] privateKey) throws Exception{
		//根据公钥字节获取新的公钥
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		
		//解密数据
		Cipher cipher = Cipher.getInstance(privKey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privKey);
		byte[] decryption_data = cipher.doFinal(encryptionData);
		
		return decryption_data;
	}
	
	
	/**
	 * 根据公钥，对数据进行解密操作；使用X509EncodedKeySpec，注意与私钥解密的区别
	 * @param encryptionData
	 * @param publicKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptionByPublicKey(byte[] encryptionData, byte[] publicKey) throws Exception{
		//根据公钥字节获取新的公钥
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
		PublicKey pubKey = keyFactory.generatePublic(x509EncodedKeySpec);
		
		//解密数据
		Cipher cipher = Cipher.getInstance(pubKey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, pubKey);
		byte[] decryption_data = cipher.doFinal(encryptionData);
		
		return decryption_data;
	}
	
	/**
	 * 从Map中获取私钥
	 * @param keyMap
	 * @return
	 */
	public static byte[] getPrivateKey(Map<String, Object> keyMap){
		PrivateKey privateKey = (PrivateKey) keyMap.get("privateKey");
		
		return privateKey.getEncoded();
	}
	
	/**
	 * 从Map中获取公钥
	 * @param keyMap
	 * @return
	 */
	public static byte[] getPublicKey(Map<String, Object> keyMap){
		PublicKey publicKey = (PublicKey) keyMap.get("publicKey");
		
		return publicKey.getEncoded();
	}
	
	//测试
	public static void main(String[] args) throws Exception {
		String unencryption_data = "hello 你好";
		
		//从Map中获取公钥私钥
		Map<String, Object> keyMap = RSA.initKey();
		byte[] privateKey = RSA.getPrivateKey(keyMap);
		byte[] publicKey = RSA.getPublicKey(keyMap);
		
		//对于私钥拥有着，使用私钥加密，其他人使用公钥解密
		byte[] encryption_data = RSA.encryptionByPrivateKey(unencryption_data.getBytes(), privateKey);
		System.out.println(Hex.encodeHex(encryption_data));
		byte[] decryption_data = RSA.decryptionByPublicKey(encryption_data, publicKey);
		System.out.println(new String(decryption_data));
		
		//对于非私钥拥有着，使用公钥加密，私钥拥有着使用私钥解密
		byte[] encryption_data2 = RSA.encryptionByPublicKey(unencryption_data.getBytes(), publicKey);
		System.out.println(Hex.encodeHex(encryption_data2));
		byte[] decryption_data2 = RSA.decrypitonByPrivateKey(encryption_data2, privateKey);
		System.out.println(new String(decryption_data2));
		
		
		
	}
	

}
