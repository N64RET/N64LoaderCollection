package pokemonstadium;

import java.util.HashMap;
import java.util.Map;

public class PokemonStadiumCodeInfo {
    public long mBootData;
    public long mBootRodata;
    public long mBootBssStart;
    public long mBootBssEnd;

    public PokemonStadiumCodeInfo(long bootData, long bootRodata, long bootBssStart, long bootBssEnd) {
        this.mBootData = bootData & 0xFFFFFFFFl;
        this.mBootRodata = bootRodata & 0xFFFFFFFFl;
        this.mBootBssStart = bootBssStart & 0xFFFFFFFFl;
        this.mBootBssEnd = bootBssEnd & 0xFFFFFFFFl;
    }

    public static final Map<PokemonStadiumVersion, PokemonStadiumCodeInfo> TABLE = new HashMap<PokemonStadiumVersion, PokemonStadiumCodeInfo>() {
        {
            put(PokemonStadiumVersion.E11, new PokemonStadiumCodeInfo(0x80068d70, 0x8006f9e0, 0x8007ef80, 0x80104DB0));
        }
    };
}
