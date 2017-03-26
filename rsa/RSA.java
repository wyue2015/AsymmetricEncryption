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
	 * ������Կ�ԣ��������Map��
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> initKey() throws Exception{
		//��ȡ��Կ
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");//��ȡ��Կ��������
		keyPairGenerator.initialize(512);//��ʼ����Կ������
		KeyPair keyPair = keyPairGenerator.generateKeyPair();//������Կ��
		PublicKey publicKey = keyPair.getPublic();//����Կ���л�ȡ��Կ
		PrivateKey privateKey = keyPair.getPrivate();//����Կ���л�ȡ˽Կ
		
		//�����ɵ���Կ�Է���Map�д��
		Map<String, Object> keyMap = new HashMap<String, Object>();
		keyMap.put("publicKey", publicKey);
		keyMap.put("privateKey", privateKey);
		
		return keyMap;
	}
	
	
	/**
	 * ����˽Կ�������ݽ��м��ܲ�����ʹ��PKCS8EncodedKeySpec��ע���빫Կ���ܵ�����
	 * @param unencryptionData
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptionByPrivateKey(byte[] unencryptionData, byte[] privateKey) throws Exception{
		//����˽Կ�ֽڻ�ȡ�µ�˽Կ
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		
		//��������
		Cipher cipher = Cipher.getInstance(privKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, privKey);
		byte[] encryption_data = cipher.doFinal(unencryptionData);
		
		return encryption_data;
	}
	
	
	/**
	 * ���ݹ�Կ�������ݽ��м��ܲ�����ʹ��X509EncodedKeySpec��ע����˽Կ���ܵ�����
	 * @param unencryptionData
	 * @param publicKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptionByPublicKey(byte[] unencryptionData, byte[] publicKey) throws Exception{
		//���ݹ�Կ�ֽڻ�ȡ�µĹ�Կ
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
		PublicKey pubKey = keyFactory.generatePublic(x509EncodedKeySpec);
		
		//��������
		Cipher cipher = Cipher.getInstance(pubKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		byte[] encryption_data = cipher.doFinal(unencryptionData);
		
		return encryption_data;
	}
	
	/**
	 * ����˽Կ�������ݽ��н��ܲ�����ʹ��PKCS8EncodedKeySpec��ע���빫Կ���ܵ�����
	 * @param encryptionData
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] decrypitonByPrivateKey(byte[] encryptionData, byte[] privateKey) throws Exception{
		//���ݹ�Կ�ֽڻ�ȡ�µĹ�Կ
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		
		//��������
		Cipher cipher = Cipher.getInstance(privKey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privKey);
		byte[] decryption_data = cipher.doFinal(encryptionData);
		
		return decryption_data;
	}
	
	
	/**
	 * ���ݹ�Կ�������ݽ��н��ܲ�����ʹ��X509EncodedKeySpec��ע����˽Կ���ܵ�����
	 * @param encryptionData
	 * @param publicKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptionByPublicKey(byte[] encryptionData, byte[] publicKey) throws Exception{
		//���ݹ�Կ�ֽڻ�ȡ�µĹ�Կ
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
		PublicKey pubKey = keyFactory.generatePublic(x509EncodedKeySpec);
		
		//��������
		Cipher cipher = Cipher.getInstance(pubKey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, pubKey);
		byte[] decryption_data = cipher.doFinal(encryptionData);
		
		return decryption_data;
	}
	
	/**
	 * ��Map�л�ȡ˽Կ
	 * @param keyMap
	 * @return
	 */
	public static byte[] getPrivateKey(Map<String, Object> keyMap){
		PrivateKey privateKey = (PrivateKey) keyMap.get("privateKey");
		
		return privateKey.getEncoded();
	}
	
	/**
	 * ��Map�л�ȡ��Կ
	 * @param keyMap
	 * @return
	 */
	public static byte[] getPublicKey(Map<String, Object> keyMap){
		PublicKey publicKey = (PublicKey) keyMap.get("publicKey");
		
		return publicKey.getEncoded();
	}
	
	//����
	public static void main(String[] args) throws Exception {
		String unencryption_data = "hello ���";
		
		//��Map�л�ȡ��Կ˽Կ
		Map<String, Object> keyMap = RSA.initKey();
		byte[] privateKey = RSA.getPrivateKey(keyMap);
		byte[] publicKey = RSA.getPublicKey(keyMap);
		
		//����˽Կӵ���ţ�ʹ��˽Կ���ܣ�������ʹ�ù�Կ����
		byte[] encryption_data = RSA.encryptionByPrivateKey(unencryption_data.getBytes(), privateKey);
		System.out.println(Hex.encodeHex(encryption_data));
		byte[] decryption_data = RSA.decryptionByPublicKey(encryption_data, publicKey);
		System.out.println(new String(decryption_data));
		
		//���ڷ�˽Կӵ���ţ�ʹ�ù�Կ���ܣ�˽Կӵ����ʹ��˽Կ����
		byte[] encryption_data2 = RSA.encryptionByPublicKey(unencryption_data.getBytes(), publicKey);
		System.out.println(Hex.encodeHex(encryption_data2));
		byte[] decryption_data2 = RSA.decrypitonByPrivateKey(encryption_data2, privateKey);
		System.out.println(new String(decryption_data2));
		
		
		
	}
	

}
