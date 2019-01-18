/*
 * PBE AES256
 * This sample shows the use of PBE (password-based encryption) with the AES256 algorithm.
 * With this implementation, only the password (passphrase) and the salt value need to be kept secret
 * for the purpose of (encrypted) data exchange.
 * In certain cases, e.g. password hashing (not exactly the case in this code sample), 
 * the salt value should a secure random and unique for each plaintext.
 * The decipher relies on the unique value of IV (initialization vector) generated from each cipher execution.
 * Because every IV and every cipher text are unique, it is safe to transmit them across the unprotected network,
 * until the algorithm is deemed unsafe.
 * 
 * NOTES: To use an algorithm, such as AES256, that exceeds the import control restriction (currently 128 bit),
 * obtain the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files from Oracle,
 * and save the .jar files in the %JAVA_HOME%\lib\security. Overwrite existing files if necessary. 
 * 
 * 11/25/2015
 * Author: limecov
 */

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class PBECipher {
	
	/*
	 * These constant values can be stored elsewhere for ease of maintenance.
	 * Only the password (passphrase) and the salt value need to be kept secret.
	 * The passphrase and salt need to be complex to prevent brute force attack.
	 * The salt needs to be random to prevent dictionary attack.
	 */
	
	private final String PASSPHRASE = "ThisIsThePassword";
	private final byte[] SALT = new String("SALTsaltSALT").getBytes();
	
	private final String SECRET_KEY_FACTORY_ALGORITHM = "PBKDF2WithHmacSHA256";
	private final String SECRET_KEY_ALGORITHM = "AES";
	private final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS5Padding";
	private final int ITERATION_COUNT = 65536;
	private final int KEY_LENGTH = 256;
	private final int IV_LENGTH = 16;
	
	public String getPlainText(byte[] cipherText) {
		String plainText = null;
		try {
			// Set up the cipher
			SecretKeyFactory factory = SecretKeyFactory.getInstance(this.SECRET_KEY_FACTORY_ALGORITHM);
			KeySpec spec = new PBEKeySpec(this.PASSPHRASE.toCharArray(), this.SALT, this.ITERATION_COUNT, this.KEY_LENGTH);
			SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), this.SECRET_KEY_ALGORITHM);
			Cipher cipher = Cipher.getInstance(this.CIPHER_TRANSFORMATION);
			
			// Separate the IV and the cipher text
			byte[] iv = Arrays.copyOfRange(cipherText, 0, this.IV_LENGTH);
			byte[] finalCipherText = Arrays.copyOfRange(cipherText, this.IV_LENGTH, cipherText.length);
			
			// Use the IV in the cipher
			cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
			
			// Get the plain text
			plainText = new String(cipher.doFinal(finalCipherText), StandardCharsets.UTF_8);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		return plainText;
	}
	
	public byte[] getCipherText(String plainText) {
		byte[] cipherText = null;
		try {
			// Set up the cipher
			SecretKeyFactory factory = SecretKeyFactory.getInstance(this.SECRET_KEY_FACTORY_ALGORITHM);
			KeySpec spec = new PBEKeySpec(this.PASSPHRASE.toCharArray(), this.SALT, this.ITERATION_COUNT, this.KEY_LENGTH);
			SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), this.SECRET_KEY_ALGORITHM);
			Cipher cipher = Cipher.getInstance(this.CIPHER_TRANSFORMATION);
			cipher.init(Cipher.ENCRYPT_MODE, secret);
			
			// Get the IV and the cipher text
			byte[] iv = cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
			byte[] tempCipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
			
			// Combine the IV and the cipher text
			cipherText = new byte[iv.length + tempCipherText.length];
			System.arraycopy(iv, 0, cipherText, 0, iv.length);
			System.arraycopy(tempCipherText, 0, cipherText, iv.length, tempCipherText.length);
			
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidParameterSpecException e) {
			e.printStackTrace();
		}
		return cipherText;
	}

	public static void main(String args[]) {
		PBECipher encryptor = new PBECipher();
		PBECipher decryptor = new PBECipher();
		String plainText = "SSN123456789";
		byte[] cipherText = null;
		String cipherTextInHex = new String();
		// Multiple execution of the same plain text to show that each execution produces a different cipher text
		for (int i = 0; i < 3; i++) {
			cipherText = encryptor.getCipherText(plainText);
			cipherTextInHex = DatatypeConverter.printHexBinary(cipherText);
			System.out.println(cipherTextInHex);
			System.out.println(decryptor.getPlainText(DatatypeConverter.parseHexBinary(cipherTextInHex)));
			System.out.println();
		}
	}
}
