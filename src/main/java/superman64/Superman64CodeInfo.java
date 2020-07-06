package superman64;

import java.util.HashMap;
import java.util.Map;

public class Superman64CodeInfo {
    public long mBootData;
    public long mBootRodata;
    public long mBootBssStart;
    public long mBootBssEnd;
    public long mCodeRom;
    public long mCodeRam;
    public int mCodeSize;

    public Superman64CodeInfo(long bootData, long bootRodata, long bootBssStart, long bootBssEnd, long codeRom, long codeRam, int codeSize) {
        this.mBootData = bootData & 0xFFFFFFFFl;
        this.mBootRodata = bootRodata & 0xFFFFFFFFl;
        this.mBootBssStart = bootBssStart & 0xFFFFFFFFl;
        this.mBootBssEnd = bootBssEnd & 0xFFFFFFFFl;
        this.mCodeRom = codeRom & 0xFFFFFFFFl;
        this.mCodeRam = codeRam & 0xFFFFFFFFl;
        this.mCodeSize = codeSize;
    }

    public static final Map<Superman64Version, Superman64CodeInfo> TABLE = new HashMap<Superman64Version, Superman64CodeInfo>() {
        {
            put(Superman64Version.USA, new Superman64CodeInfo(0x800d60d0, 0x800db350, 0x800e09f0, 0x80147F10, 0xE15f0, 0x80147F10, 0x12E50));
        }
    };
}
