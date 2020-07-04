package n64;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.python.jline.internal.Log;

public class N64Rom {

    public byte[] mRawRom;
    public N64Cic mCic;

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
        if (mCic == N64Cic.CIC_NUS_6103)
            entrypoint -= 0x100000;

        if (mCic == N64Cic.CIC_NUS_6106)
            entrypoint -= 0x200000;
        
        if (mCic == N64Cic.LylatWars)
            entrypoint = 0x80000480;
        
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


        mCic = N64Cic.FromMd5(getBootStrapMd5());
        if (mCic == N64Cic.Unknown)
            Log.info("Unknown CIC chip");
        else
            Log.info("Detected ", mCic.mName);
    }
}