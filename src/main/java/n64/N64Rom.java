package n64;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.python.jline.internal.Log;

public class N64Rom {

    public byte[] mRawRom;
    public int mCic;

    public int getClockRate() {
        return ByteBuffer.wrap(mRawRom).getInt(0x4) & 0xFFFFFFF0;
    }

    public int getEntryPoint() {
        return ByteBuffer.wrap(mRawRom).getInt(8);
    }

    public int getReleaseAddress() {
        return ByteBuffer.wrap(mRawRom).getInt(0xC);
    }

    public int getCRC1() {
        return ByteBuffer.wrap(mRawRom).getInt(0x10);
    }

    public int getCRC2() {
        return ByteBuffer.wrap(mRawRom).getInt(0x14);
    }

    public String getName() {
        byte[] name = new byte[0x14];
        ByteBuffer buff = ByteBuffer.wrap(mRawRom);
        buff.position(0x20);
        buff.get(name, 0, name.length);
        try {
            return new String(name, "UTF8").replaceAll("\\s+$", "");
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            return "**ERROR**";
        }
    }

    public String getDeveloper() {
        return new String(new byte[] { mRawRom[0x3B] });
    }

    public String getCartID() {
        return new String(new byte[] { mRawRom[0x3C], mRawRom[0x3D] });
    }

    public String getCountryCode() {
        return new String(new byte[] { mRawRom[0x3E] });
    }

    public String getGameCode() {
        return getDeveloper() + getCartID() + getCountryCode();
    }

    public byte getVersion() {
        return mRawRom[0x3F];
    }

    public char getLibultraVersion() {
        return (char) mRawRom[0xF];
    }
    
    public long getFixedEntrypoint()
    {
        long entrypoint = (getEntryPoint() & 0xFFFFFFFFl);
        if (mCic == 6103)
            entrypoint -= 0x100000;

        if (mCic == 6105)
            entrypoint -= 0x200000;
        
        return entrypoint;
    }

    public byte[] getBootStrap() {
        ByteBuffer buff = ByteBuffer.wrap(mRawRom);
        buff.position(0x40);
        byte[] bootCode = new byte[0xFC0];
        buff.get(bootCode);
        return bootCode;
    }

    private String getBootStrapMd5() {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("MD5");
            md.update(getBootStrap());
            byte[] digest = md.digest();
            return Utils.bytesToHex(digest);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    private void findCic() {
        String md5 = getBootStrapMd5();
        if (md5.equals("900B4A5B68EDB71F4C7ED52ACD814FC5")) {
            mCic = 6101;
            return;
        } else if (md5.equals("E24DD796B2FA16511521139D28C8356B")) {
            mCic = 6102;
            return;
        } else if (md5.equals("319038097346E12C26C3C21B56F86F23")) {
            mCic = 6103;
            return;
        } else if (md5.equals("FF22A296E55D34AB0A077DC2BA5F5796")) {
            mCic = 6105;
            return;
        } else if (md5.equals("6460387749AC0BD925AA5430BC7864FE")) {
            mCic = 6106;
            return;
        }

        mCic = 0;
    }

    public N64Rom(byte[] data) throws Exception {
        if (data.length < 0x1000 || data.length % 4 != 0)
            throw new Exception("Invalid ROM Size");

        // check for endian swap
        if (data[0] != (byte) 0x80 && data[1] == (byte) 0x80) {
            mRawRom = new byte[data.length];
            for (int i = 0; i < data.length; i += 2) {
                mRawRom[i + 0] = data[i + 1];
                mRawRom[i + 1] = data[i + 0];
            }
        } else
            mRawRom = data;

        findCic();
        if (mCic == 0)
            Log.info("Unknown CIC chip");
        else
            Log.info("Detected CIC-NUS-", mCic);
    }
}