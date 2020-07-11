package hal;

import java.util.HashMap;
import java.util.Map;

public class HalCodeInfo {
    public long mBootData;
    public long mBootRodata;
    public long mBootBssStart;
    public long mBootBssEnd;

    public HalCodeInfo(long bootData, long bootRodata, long bootBssStart, long bootBssEnd) {
        this.mBootData = bootData & 0xFFFFFFFFl;
        this.mBootRodata = bootRodata & 0xFFFFFFFFl;
        this.mBootBssStart = bootBssStart & 0xFFFFFFFFl;
        this.mBootBssEnd = bootBssEnd & 0xFFFFFFFFl;
    }

    public static final Map<HalVersion, HalCodeInfo> TABLE = new HashMap<HalVersion, HalCodeInfo>() {
        {
            put(HalVersion.SnapUSA, new HalCodeInfo(0x80040CC0, 0x80042FA0, 0x80045670, 0x8009A8C0));
            put(HalVersion.SmashUSA, new HalCodeInfo(0x8003b6b0, 0x8003d650, 0x8003fad0, 0x800A1970));
        }
    };
}
