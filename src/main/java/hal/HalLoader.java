package hal;

import n64.*;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.python.jline.internal.Log;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.mem.MemoryAccessException;


public class HalLoader extends N64Loader {
    HalVersion mVersion;
    
    @Override
    public String getName() {
        return "HAL Loader";
    }
    
    void identifyVersion()
    {
        mVersion = HalVersion.Invalid;
        if (mRom.getName().equals("POKEMON SNAP"))
        {
            if (mRom.getGameCode().equals("NPFE") && mRom.getVersion() == 0)
                mVersion = HalVersion.SnapUSA;
        }
        else if (mRom.getName().equals("SMASH BROTHERS"))
        {
            if (mRom.getGameCode().equals("NALE") && mRom.getVersion() == 0)
                mVersion = HalVersion.SmashUSA;
        }
    }
    
    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        try {
            mRom = new N64Rom(provider.getInputStream(0).readAllBytes());
            identifyVersion();
            if (mVersion != HalVersion.Invalid)
                loadSpecs.add(getLoadSpec());
        } catch (Exception e) {

        }

        return loadSpecs;
    }
    
    @Override
    protected void loadGame()
    {
        identifyVersion();
        long entrypoint = mRom.getFixedEntrypoint();
        
        ByteBuffer buff = ByteBuffer.wrap(mRom.mRawRom);
        buff.position(0x1000);

        var codeInfo = HalCodeInfo.TABLE.get(mVersion);
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
        
        LoadCodeOvl("code", codeInfo.mBootData, false);
        
        try {
            // pointer to code.data in the code overlay struct
            long ovlTable = mApi.getCurrentProgram().getMemory().getInt(mApi.toAddr(codeInfo.mBootData+0x14)) & 0xFFFFFFFFl;
            
            int count = 0;
            switch (mVersion)
            {
            case SnapUSA:
                count = 30;
                break;
            case SmashUSA:
                count = 65;
                break;
            default:
                count = 0;
                break;
            }
            
            for (int i = 0; i < count; i++)
                LoadCodeOvl("block_" + i, ovlTable + i*0x24, true);
        } catch (MemoryAccessException e1) {
            e1.printStackTrace();
        }
    }
    
    private void LoadCodeOvl(String name, long addr, boolean overlay)
    {
        var buff = ByteBuffer.wrap(mRom.mRawRom);
        byte[] data = new byte[0x24];
        try {
            mApi.getCurrentProgram().getMemory().getBytes(mApi.toAddr(addr), data);
            var ovlBuff = ByteBuffer.wrap(data);
            long romStart = ovlBuff.getInt() & 0xFFFFFFFFl;
            long romEnd = ovlBuff.getInt() & 0xFFFFFFFFl;
            long ram = ovlBuff.getInt() & 0xFFFFFFFFl;
            long textStart = ovlBuff.getInt() & 0xFFFFFFFFl;
            long textEnd = ovlBuff.getInt() & 0xFFFFFFFFl;
            long dataStart = ovlBuff.getInt() & 0xFFFFFFFFl;
            long rodataEnd = ovlBuff.getInt() & 0xFFFFFFFFl;
            long bssStart = ovlBuff.getInt() & 0xFFFFFFFFl;
            long bssEnd = ovlBuff.getInt() & 0xFFFFFFFFl;
            
            Log.info(String.format("Loading Overlay 0x%08X; rom=%08X-%08X; .text=%08X-%08X; .data/.rodata=%08X-%08X; .bss=%08X-%08X", addr, romStart, romEnd, textStart, textEnd, dataStart, rodataEnd, bssStart, bssEnd));
            
            byte[] block = new byte[(int)(textEnd-textStart)];
            buff.position((int)romStart);
            buff.get(block);
            createSegment(name + ".text", textStart, block, new MemPerm("R-X"), overlay);
            
            // .data and .rodata are merged together
            block = new byte[(int)(rodataEnd-dataStart)];
            buff.get(block);
            createSegment(name + ".data", dataStart, block, new MemPerm("RX-"), overlay);
            createEmptySegment(name + ".bss", bssStart, bssEnd-1, new MemPerm("RW-"), overlay);
            
            
        } catch (MemoryAccessException e) {
            e.printStackTrace();
        }
    }
}
