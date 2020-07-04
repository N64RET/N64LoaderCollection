package starfox64;

import n64.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.LoadSpec;

public class StarFox64Loader extends N64Loader {

    private StarFox64Version mVersion;

    @Override
    public String getName() {
        return "StarFox 64 Loader";
    }
        
    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        try {
            mRom = new N64Rom(provider.getInputStream(0).readAllBytes());
            identifyVersion();
            if (mVersion != StarFox64Version.Invalid)
                loadSpecs.add(getLoadSpec());
        } catch (Exception e) {

        }

        return loadSpecs;
    }

    private void identifyVersion() {
        mVersion = StarFox64Version.Invalid;
        
        if (mRom.getName().equals("STARFOX64"))
        {
            if (mRom.getGameCode().equals("NFXP") && mRom.getVersion() == 0) {
                mVersion = StarFox64Version.Europe;
            } else if (mRom.getGameCode().equals("NFXJ") && mRom.getVersion() == 0) {
                mVersion = StarFox64Version.Japan;
            } else if (mRom.getGameCode().equals("NFXE") && mRom.getVersion() == 1) {
                mVersion = StarFox64Version.U11;
            }
        }
    }


    @Override
    protected void loadGame() {
        identifyVersion();

        long entrypoint = mRom.getFixedEntrypoint();

        ByteBuffer buff = ByteBuffer.wrap(mRom.mRawRom);
        buff.position(0x1000);

        var codeInfo = StarFox64CodeInfo.TABLE.get(mVersion);
        byte[] section = new byte[(int) (codeInfo.mBootData - entrypoint)];
        buff.get(section);
        createSegment("boot.text", entrypoint, section, new MemPerm("R-X"), false);

        section = new byte[(int) (codeInfo.mBootRodata - codeInfo.mBootData)];
        buff.get(section);
        createSegment("boot.data", codeInfo.mBootData, section, new MemPerm("RW-"), false);

        section = new byte[(int) (codeInfo.mBootBssStart - codeInfo.mBootRodata)];
        buff.get(section);
        createSegment("boot.rodata", codeInfo.mBootRodata, section, new MemPerm("R--"), false);
        createEmptySegment("boot.bss", codeInfo.mBootBssStart, codeInfo.mBootBssEnd - 1, new MemPerm("RW-"), false);
    }

}
