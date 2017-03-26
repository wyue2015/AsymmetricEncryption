package elgamal;

import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;


public class ElGamal {
	
	/**
	 * 初始化ElGamal算法的密钥对，获取密钥对，并存放于Map中
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> initKey() throws Exception{
		//由BC方式获取ElGamal算法的密钥对生成器
		Security.addProvider(new BouncyCastleProvider());//加入对BC的支持
		AlgorithmParameterGenerator algorithmParameterGenerator = AlgorithmParameterGenerator.getInstance("ElGamal");
		algorithmParameterGenerator.init(256);//初始化算法参数生成器
		AlgorithmParameters algorithmParameters = algorithmParameterGenerator.generateParameters();//生成算法参数
		DHParameterSpec dhParameterSpec = (DHParameterSpec) algorithmParameters.getParameterSpec(DHParameterSpec.class);//构建参数材料
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ElGamal");//实例化密钥对生成器
		keyPairGenerator.initialize(dhParameterSpec, new SecureRandom());//初始化密钥对生成器
		
		//从密钥对中获取公钥、私钥，并存放于Map中
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		Map<String, Object> keyMap = new HashMap<String, Object>();
		keyMap.put("publicKey", publicKey);
		keyMap.put("privateKey", privateKey);
		
		return keyMap;
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
		Security.addProvider(new BouncyCastleProvider());
		KeyFactory keyFactory = KeyFactory.getInstance("ElGamal");
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
		KeyFactory keyFactory = KeyFactory.getInstance("ElGamal");
		PrivateKey privKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		
		//解密数据
		Cipher cipher = Cipher.getInstance(privKey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privKey);
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
	
	
	public static void main(String[] args) throws Exception {
		String unencryption_data = "Hello 你好";//待加密数据
		
		Map<String, Object> keyMap = ElGamal.initKey();
		byte[] publicKey = ElGamal.getPublicKey(keyMap);
		byte[] privateKey = ElGamal.getPrivateKey(keyMap);
		
		//公钥加密，私钥解密
		byte[] encryption_data = ElGamal.encryptionByPublicKey(unencryption_data.getBytes(), publicKey);
		byte[] decryption_data = ElGamal.decrypitonByPrivateKey(encryption_data, privateKey);
		
		System.out.println(Hex.toHexString(encryption_data));
		System.out.println(new String(decryption_data));
	}
	
	
}
