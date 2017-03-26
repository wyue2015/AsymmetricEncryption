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
	 * ��ȡUserA����Կ�ԣ��������Map��
	 * @return
	 * @throws Exception
	 */
	public static Map<String,Object> initKeyOfUserA() throws Exception{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
		keyPairGenerator.initialize(512);//ָ��DH�㷨����Կ�Եĳ���
		KeyPair keyPair = keyPairGenerator.generateKeyPair();//������Կ��
		
		//ȡ����Կ�Բ�����Map�����д��
		DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();//
		DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();
		Map<String,Object> keyMap = new HashMap<String,Object>();
		keyMap.put("publicKey", publicKey);
		keyMap.put("privateKey", privateKey);
		
		return keyMap;
	}
	
	/**
	 * ���UserB����Կ���������Map��
	 * @param publicKeyOfUserB
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> initKeyOfUserB(byte[] publicKeyOfUserA) throws Exception{
		//����UserA�ṩ�Ĺ�Կ
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyOfUserA);
		KeyFactory  keyFactory = KeyFactory.getInstance("DH");
		DHPublicKey pubKey = (DHPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);
		DHParameterSpec dhParameterSpec = pubKey.getParams();
		
		//����UserB����Կ��
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
		keyPairGenerator.initialize(dhParameterSpec);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
//		KeyPair keyPair = keyPairGenerator.genKeyPair();//������Կ��
		
		//ȡ����Կ�Բ�����Map�����д��
		DHPublicKey publicKey = (DHPublicKey) keyPair.getPublic();
		DHPrivateKey privateKey = (DHPrivateKey) keyPair.getPrivate();
		Map<String, Object> keyMap = new HashMap<String, Object>();
		keyMap.put("publicKey", publicKey);
		keyMap.put("privateKey", privateKey);
		
		return keyMap;
	}
	
	/**
	 * ����UserA��˽Կ+UserB�Ĺ�Կ �� UserB��˽Կ+UserA�Ĺ�Կ ���ɱ�����Կ�����ڼ�������
	 * @param publicKey
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] getLocalSecretKey(byte[] publicKey, byte[] privateKey) throws Exception{
		//������Կ�����ݱ�׼�����µĹ�Կ
		KeyFactory keyFactory = KeyFactory.getInstance("DH");
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey);
		PublicKey pubKey = keyFactory.generatePublic(x509EncodedKeySpec);
		
		//����˽Կ�����ݱ�׼�����µ�˽Կ
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);
		PrivateKey privKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		
		//�����µĹ�Կ��˽Կ���ɱ�����Կ
		KeyAgreement keyAgreement = KeyAgreement.getInstance(keyFactory.getAlgorithm());
		keyAgreement.init(privKey);
		keyAgreement.doPhase(pubKey, true);
		SecretKey secretKey = keyAgreement.generateSecret("AES");//���Ի�ȡDES��DESede��AES�㷨�ı�����Կ
		
		return secretKey.getEncoded();
	}
	
	
	/**
	 * ���ݱ�����Կ+�ԳƼ����㷨ʵ�ַǶԳƼ�������
	 * @param unencrypted_data
	 * @param local_key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encrypt(byte[] unencrypted_data, byte[] local_key) throws Exception{
		SecretKey secretKey = new SecretKeySpec(local_key, "AES");//����ʹ��DES��DESede��AES�㷨���DH��������
		Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		byte[] encrypted_data = cipher.doFinal(unencrypted_data);
		return encrypted_data;
	}
	
	
	/**
	 * ���ݱ�����Կ+�ԳƼ����㷨ʵ�ַǶԳƽ�������
	 * @param encrypted_data
	 * @param local_key
	 * @return
	 * @throws Exception
	 */
	public static byte[] decrypt(byte[] encrypted_data, byte[] local_key) throws Exception{
		SecretKey secretKey = new SecretKeySpec(local_key, "AES");//����ʹ��DES��DESede�㷨���DH��������
		Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		byte[] decrypted_data = cipher.doFinal(encrypted_data);
		
		return decrypted_data;
	}
	
	
	/**
	 * ��Map��ŵ���Կ���л�ȡ��Կ
	 * @param keyMap
	 * @return
	 */
	public static byte[] getPublicKey(Map<String, Object> keyMap){
		PublicKey publicKey = (PublicKey) keyMap.get("publicKey");
		
		return publicKey.getEncoded();
	}
	
	/**
	 * ��Map��ŵ���Կ���л�ȡ˽Կ
	 * @param keyMap
	 * @return
	 */
	public static byte[] getPrivateKey(Map<String, Object> keyMap){
		PrivateKey privateKey = (PrivateKey) keyMap.get("privateKey");
		
		return privateKey.getEncoded();
	}
	
	//����
	public static void main(String[] args) throws Exception {
		
		String unecryption_data = "hello ���";
		
		//UserA�Ĺ�Կ˽Կ
		Map<String, Object> keyMapOfUserA = DH.initKeyOfUserA();
		byte[] publicKeyOfUserA = DH.getPublicKey(keyMapOfUserA);
		byte[] privateKeyOfUserA = DH.getPrivateKey(keyMapOfUserA);
		
		//UserB�Ĺ�Կ˽Կ
		Map<String, Object> keyMapOfUserB = DH.initKeyOfUserB(publicKeyOfUserA);
		byte[] publicKeyOfUserB = DH.getPublicKey(keyMapOfUserB);
		byte[] privateKeyOfUserB = DH.getPrivateKey(keyMapOfUserB);
		
		//���ɱ�����Կ
		byte[] local_keyOfUserA = DH.getLocalSecretKey(publicKeyOfUserB, privateKeyOfUserA);//UserA�ı�����Կ
		byte[] local_keyOfUserB = DH.getLocalSecretKey(publicKeyOfUserA, privateKeyOfUserB);//UserB�ı�������
		
		//UserA���ܣ�UserB��������
		byte[] encrypted_dataOfUserA = DH.encrypt(unecryption_data.getBytes(), local_keyOfUserA);//UserA��������
		byte[] decrypted_dataOfUserB = DH.decrypt(encrypted_dataOfUserA, local_keyOfUserB);//UserB��������
		System.out.println(Hex.encodeHexString(encrypted_dataOfUserA));
		System.out.println(new String(decrypted_dataOfUserB));

		//UserB���ܣ�UserA��������
		byte[] encrypted_dataOfUserB = DH.encrypt(unecryption_data.getBytes(), local_keyOfUserB);
		byte[] decrypted_dataOfUserA = DH.decrypt(encrypted_dataOfUserB, local_keyOfUserA);
		System.out.println(Hex.encodeHexString(encrypted_dataOfUserB));
		System.out.println(new String(decrypted_dataOfUserA));
		
	}
	

}
