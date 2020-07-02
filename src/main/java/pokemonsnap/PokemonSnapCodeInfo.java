package pokemonsnap;

import java.util.HashMap;
import java.util.Map;

public class PokemonSnapCodeInfo {
    public long mBootData;
    public long mBootRodata;
    public long mBootBssStart;
    public long mBootBssEnd;
    public long mOvlTableInfos;
    public long mUnkBlockRam;
    public long mUnkBlockRomStart;
    public long mUnkBlockRomEnd;

    public PokemonSnapCodeInfo(long bootData, long bootRodata, long bootBssStart, long bootBssEnd, long ovlTableInfos) {
        this.mBootData = bootData & 0xFFFFFFFFl;
        this.mBootRodata = bootRodata & 0xFFFFFFFFl;
        this.mBootBssStart = bootBssStart & 0xFFFFFFFFl;
        this.mBootBssEnd = bootBssEnd & 0xFFFFFFFFl;
        this.mOvlTableInfos = ovlTableInfos & 0xFFFFFFFFl;
    }

    public static final Map<PokemonSnapVersion, PokemonSnapCodeInfo> TABLE = new HashMap<PokemonSnapVersion, PokemonSnapCodeInfo>() {
        {
            put(PokemonSnapVersion.USA, new PokemonSnapCodeInfo(0x80040CC0, 0x80042FA0, 0x80045670, 0x8009A8C0, -1));
        }
    };
}
