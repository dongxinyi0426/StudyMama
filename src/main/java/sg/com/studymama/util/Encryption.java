package sg.com.studymama.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Encryption {

	private static final Logger LOG = LoggerFactory.getLogger(Encryption.class);
	public static String generateHashValue(String password){
			String rtnValue=password;
		try{
			MessageDigest hashv = MessageDigest.getInstance("SHA-256");
			hashv.reset();
			hashv.update(getStaticSalt());
			byte raw[] = hashv.digest(password.getBytes("UTF-8"));
			String hash = byteToHex(raw);
			
		    return hash;
		}
		catch(Exception ex){
		}
		return rtnValue;
	}
	
	private static byte[] getStaticSalt(){
	String salt= "845CA75AA22187141415C6890881E1A428E3B16D57C484BFB4C8771A9869DE15";
		return hexToBytes(salt.toCharArray());
	}

	private static byte[] hexToBytes(char[] hex) {
        int length = hex.length / 2;
        byte[] raw = new byte[length];
        for (int i = 0; i < length; i++) {
          int high = Character.digit(hex[i * 2], 16);
          int low = Character.digit(hex[i * 2 + 1], 16);
          int value = (high << 4) | low;
          if (value > 127)
            value -= 256;
          raw[i] = (byte) value;
        }
        return raw;
      }

	private static String byteToHex(byte[] data) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
            int halfbyte = (data[i] >>> 4) & 0x0F;
            int two_halfs = 0;
            do {
                if ((0 <= halfbyte) && (halfbyte <= 9))
                    buf.append((char) ('0' + halfbyte));
                else
                    buf.append((char) ('a' + (halfbyte - 10)));
                halfbyte = data[i] & 0x0F;
            } while(two_halfs++ < 1);
        }
        return buf.toString();
    }
	
	public static String randomGenerator(String SALTCHARS, int maxLength) {
        StringBuilder salt = new StringBuilder();
        SecureRandom rnd;
        
		try {
			rnd = SecureRandom.getInstance("SHA1PRNG");
	        while (salt.length() < maxLength) { // length of the random string.
	            int index = (int) (rnd.nextFloat() * SALTCHARS.length());
	            salt.append(SALTCHARS.charAt(index));
	        }
		} catch (NoSuchAlgorithmException e) {
			LOG.error("Error in initializing SecureRandom class ", e);
		}
        
        return salt.toString();
		
	}
}

