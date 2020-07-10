package n64;

import ghidra.program.flatapi.FlatProgramAPI;

public class Utils {

    public static String bytesToHex(byte[] bytes) {
        final char[] hexArray = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int b = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[b >>> 4];
            hexChars[j * 2 + 1] = hexArray[b & 0x0F];
        }
        return new String(hexChars);
    }
    

    public static String readString(FlatProgramAPI api, long addr) {

        String str = "";
        try {
            char c = 0;
            do {
                c = (char) api.getCurrentProgram().getMemory().getByte(api.toAddr(addr));
                if (c != 0)
                    str += c;
                addr++;
            } while (c != 0);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return str;
    }
    

    public static boolean memcmp(byte[] arr1, int off1, byte[] arr2, int off2, int length)
    {   
        for (int i = 0; i < length; i++) {
            if (arr1[off1 + i] != arr2[off2+i]) {
                return false;
            }
        }
        
        return true;
    }
}
