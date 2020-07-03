package starfox64;

import n64.*;
import java.nio.ByteBuffer;

public class StarFox64Loader extends N64Loader {

    private StarFox64Version mVersion;

    @Override
    public String getName() {
        return "StarFox 64 Loader";
    }

    private void identifyVersion() {
        if (mRom.getGameCode().equals("NFXP")) {
            mVersion = StarFox64Version.Europe;
        } else if (mRom.getGameCode().equals("NFXJ")) {
            mVersion = StarFox64Version.Japan;
        } else if (mRom.getGameCode().equals("NFXE")) {
            mVersion = StarFox64Version.USA;
        } else {
            mVersion = StarFox64Version.Invalid;
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
