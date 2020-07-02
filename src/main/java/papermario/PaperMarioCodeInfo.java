package papermario;

import java.util.HashMap;
import java.util.Map;

public class PaperMarioCodeInfo {
    public long mBootData;
    public long mBootRodata;
    public long mBootBssStart;
    public long mBootBssEnd;
    public long mOvlTableInfos;
    public long mUnkBlockRam;
    public long mUnkBlockRomStart;
    public long mUnkBlockRomEnd;

    public PaperMarioCodeInfo(long bootData, long bootRodata, long bootBssStart, long bootBssEnd, long ovlTableInfos,
            long unkBlockRam, long unkBlockRomStart, long unkBlockRomEnd) {
        this.mBootData = bootData & 0xFFFFFFFFl;
        this.mBootRodata = bootRodata & 0xFFFFFFFFl;
        this.mBootBssStart = bootBssStart & 0xFFFFFFFFl;
        this.mBootBssEnd = bootBssEnd & 0xFFFFFFFFl;
        this.mOvlTableInfos = ovlTableInfos & 0xFFFFFFFFl;
        this.mUnkBlockRam = unkBlockRam & 0xFFFFFFFFl;
        this.mUnkBlockRomStart = unkBlockRomStart & 0xFFFFFFFFl;
        this.mUnkBlockRomEnd = unkBlockRomEnd & 0xFFFFFFFFl;
    }

    public static final Map<PaperMarioVersion, PaperMarioCodeInfo> TABLE = new HashMap<PaperMarioVersion, PaperMarioCodeInfo>() {
        {
            put(PaperMarioVersion.USA, new PaperMarioCodeInfo(0x80095820, 0x80097D30, 0x8009A5b0, 0x800DC500,
                    0x800934f0, 0x80280000, 0x7e0e80, 0x7e73a0));
        }
    };
}
