package superman64;

import n64.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.LoadSpec;

public class Superman64Loader extends N64Loader {

    Superman64Version mVersion;
    
    @Override
    public String getName() {
        return "Superman 64 Loader";
    }
    
    void identifyVersion()
    {
        mVersion = Superman64Version.Invalid;
        if (mRom.getName().equals("SUPERMAN"))
        {
            if (mRom.getGameCode().equals("NSPE") && mRom.getVersion() == 0)
                mVersion = Superman64Version.USA;
        }
    }
    
    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        try {
            mRom = new N64Rom(provider.getInputStream(0).readAllBytes());
            identifyVersion();
            if (mVersion != Superman64Version.Invalid)
                loadSpecs.add(getLoadSpec());
        } catch (Exception e) {

        }

        return loadSpecs;
    }

    @Override
    protected void loadGame() {
        identifyVersion();
        
        long entrypoint = mRom.getFixedEntrypoint();

        ByteBuffer buff = ByteBuffer.wrap(mRom.mRawRom);
        buff.position(0x1000);

        var codeInfo = Superman64CodeInfo.TABLE.get(mVersion);
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
        
        section = new byte[codeInfo.mCodeSize];
        buff.get(section);
        //buff.position((int)codeInfo.mCodeRom);
        createSegment("code", codeInfo.mCodeRam, section, new MemPerm("RWX"), false);
    }

}
