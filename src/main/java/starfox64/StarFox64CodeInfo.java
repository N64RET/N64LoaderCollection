package starfox64;

import java.util.HashMap;
import java.util.Map;

public class StarFox64CodeInfo {
    public long mBootData;
    public long mBootRodata;
    public long mBootBssStart;
    public long mBootBssEnd;
    public long mOvlTableInfos;
    public long mUnkBlockRam;
    public long mUnkBlockRomStart;
    public long mUnkBlockRomEnd;

    public StarFox64CodeInfo(long bootData, long bootRodata, long bootBssStart, long bootBssEnd) {
        this.mBootData = bootData & 0xFFFFFFFFl;
        this.mBootRodata = bootRodata & 0xFFFFFFFFl;
        this.mBootBssStart = bootBssStart & 0xFFFFFFFFl;
        this.mBootBssEnd = bootBssEnd & 0xFFFFFFFFl;
    }

    public static final Map<StarFox64Version, StarFox64CodeInfo> TABLE = new HashMap<StarFox64Version, StarFox64CodeInfo>() {
        {
            put(StarFox64Version.Europe, new StarFox64CodeInfo(0x800c3e70, 0x800c54d0, 0x800df9f0, 0x8017ABE0));
            put(StarFox64Version.U11, new StarFox64CodeInfo(0x800c3660, 0x800c48d0, 0x800dd880, 0x80178A70));
            put(StarFox64Version.Japan, new StarFox64CodeInfo(0x800c07b0, 0x800c1a20, 0x800e87c0, 0x8017E210));
        }
    };
}
