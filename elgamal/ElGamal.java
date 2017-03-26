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
	 * ��ʼ��ElGamal�㷨����Կ�ԣ���ȡ��Կ�ԣ��������Map��
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> initKey() throws Exception{
		//��BC��ʽ��ȡElGamal�㷨����Կ��������
		Security.addProvider(new BouncyCastleProvider());//�����BC��֧��
		AlgorithmParameterGenerator algorithmParameterGenerator = AlgorithmParameterGenerator.getInstance("ElGamal");
		algorithmParameterGenerator.init(256);//��ʼ���㷨����������
		AlgorithmParameters algorithmParameters = algorithmParameterGenerator.generateParameters();//�����㷨����
		DHParameterSpec dhParameterSpec = (DHParameterSpec) algorithmParameters.getParameterSpec(DHParameterSpec.class);//������������
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ElGamal");//ʵ������Կ��������
		keyPairGenerator.initialize(dhParameterSpec, new SecureRandom());//��ʼ����Կ��������
		
		//����Կ���л�ȡ��Կ��˽Կ���������Map��
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		Map<String, Object> keyMap = new HashMap<String, Object>();
		keyMap.put("publicKey", publicKey);
		keyMap.put("privateKey", privateKey);
		
		return keyMap;
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
		Security.addProvider(new BouncyCastleProvider());
		KeyFactory keyFactory = KeyFactory.getInstance("ElGamal");
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
		KeyFactory keyFactory = KeyFactory.getInstance("ElGamal");
		PrivateKey privKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
		
		//��������
		Cipher cipher = Cipher.getInstance(privKey.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, privKey);
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
	
	
	public static void main(String[] args) throws Exception {
		String unencryption_data = "Hello ���";//����������
		
		Map<String, Object> keyMap = ElGamal.initKey();
		byte[] publicKey = ElGamal.getPublicKey(keyMap);
		byte[] privateKey = ElGamal.getPrivateKey(keyMap);
		
		//��Կ���ܣ�˽Կ����
		byte[] encryption_data = ElGamal.encryptionByPublicKey(unencryption_data.getBytes(), publicKey);
		byte[] decryption_data = ElGamal.decrypitonByPrivateKey(encryption_data, privateKey);
		
		System.out.println(Hex.toHexString(encryption_data));
		System.out.println(new String(decryption_data));
	}
	
	
}
