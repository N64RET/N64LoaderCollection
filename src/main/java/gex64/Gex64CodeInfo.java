package gex64;

import java.util.HashMap;
import java.util.Map;

public class Gex64CodeInfo {
    public long mBootData;
    public long mBootRodata;
    public long mBootBssStart;
    public long mBootBssEnd;
    public long mOvlTableInfos;
    public long mUnkBlockRam;
    public long mUnkBlockRomStart;
    public long mUnkBlockRomEnd;

    public Gex64CodeInfo(long bootData, long bootRodata, long bootBssStart, long bootBssEnd) {
        this.mBootData = bootData & 0xFFFFFFFFl;
        this.mBootRodata = bootRodata & 0xFFFFFFFFl;
        this.mBootBssStart = bootBssStart & 0xFFFFFFFFl;
        this.mBootBssEnd = bootBssEnd & 0xFFFFFFFFl;
    }

    public static final Map<Gex64Version, Gex64CodeInfo> TABLE = new HashMap<Gex64Version, Gex64CodeInfo>() {
        {
            put(Gex64Version.USA, new Gex64CodeInfo(0x8006aaf0, 0x800739f0, 0x8007f340, 0x80159720));
        }
    };
}
