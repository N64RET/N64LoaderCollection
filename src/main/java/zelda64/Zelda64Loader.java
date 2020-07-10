package zelda64;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;

import org.python.jline.internal.Log;
import n64.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.StringDataType;

public class Zelda64Loader extends N64Loader {
    Zelda64Game mGame;

    @Override
    public String getName() {
        return "Zelda 64 Loader";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        try {
            var game = new Zelda64Game(provider.getInputStream(0).readAllBytes(), false, null);
            if (game.isKnown())
                loadSpecs.add(getLoadSpec());
        } catch (Exception e) {

        }

        return loadSpecs;
    }

    @Override
    protected void loadGame() throws CancelledException {

        mGame = new Zelda64Game(this, true);
        if (!mGame.isKnown()) {
            throw new CancelledException("Unknown ROM");
        }

        // set the default charset to EUC-JP
        try {
            var dt =  mApi.getCurrentProgram().getDataTypeManager().resolve(new StringDataType(), null);
            var settings = dt.getDefaultSettings();
            settings.setString("charset", "EUC-JP");
            settings.clearSetting("encoding");
            settings.clearSetting("language");

        } catch (Exception e) {
            e.printStackTrace();
        }

        var codeInfo = Zelda64CodeInfo.TABLE.get(mGame.mVersion);
        long entrypoint = mRom.getFixedEntrypoint();

        // boot
        var bootFile = mGame.getFile(0x00001060);
        byte[] boot = new byte[bootFile.mData.length+0x60];
        ByteBuffer buff = ByteBuffer.wrap(mRom.mRawRom);
        buff.position(0x1000);

        byte[] segment = new byte[(int) (codeInfo.mBootData - entrypoint)];
        buff.get(segment);
        createSegment("boot.text", entrypoint, segment, new MemPerm("R-X"), false);

        segment = new byte[(int) (codeInfo.mBootRodata - codeInfo.mBootData)];
        buff.get(segment);
        createSegment("boot.data", codeInfo.mBootData, segment, new MemPerm("RW-"), false);

        segment = new byte[(int) (entrypoint + boot.length - codeInfo.mBootRodata)];
        buff.get(segment);
        createSegment("boot.rodata", codeInfo.mBootRodata, segment, new MemPerm("R--"), false);

        // code
        int codeVrom = (int) codeInfo.mCodeVrom;
        if (codeVrom != -1) {
            createEmptySegment("boot.bss", entrypoint + boot.length, codeInfo.mCodeText - 1, new MemPerm("RW-"), false);

            byte[] code = mGame.getFile(codeVrom).mData;
            buff = ByteBuffer.wrap(code);
            buff.position(0);

            segment = new byte[(int) (codeInfo.mCodeData - codeInfo.mCodeText)];
            buff.get(segment);
            createSegment("code.text", codeInfo.mCodeText, segment, new MemPerm("R-X"), false);

            segment = new byte[(int) (codeInfo.mCodeRodata - codeInfo.mCodeData)];
            buff.get(segment);
            createSegment("code.data", codeInfo.mCodeData, segment, new MemPerm("RW-"), false);

            segment = new byte[(int) (codeInfo.mCodeText + code.length - codeInfo.mCodeRodata)];
            buff.get(segment);
            createSegment("code.rodata", codeInfo.mCodeRodata, segment, new MemPerm("R--"), false);

            createEmptySegment("code.bss", codeInfo.mCodeText + code.length, 0x807FFFFFl, new MemPerm("RW-"), false);
            
            // GameStates
            int count = mGame.isOot() ? 6 : mGame.isMm() ? 7 : mGame.isAc() ? 10 : 0;
            loadOvlTable(codeInfo.mGameStateOvlTable, count, 0x30, 4, 0xC, -1, "GameState");

            // KaleidoMgr
            loadOvlTable(codeInfo.mKaleidoMgrOvlTable, 2, 0x1C, 4, 0xC, 0x18, "KaleidoMgrOvl");

            // map_mark_data
            if (mGame.isOot())
                loadOvlTable(codeInfo.mMapMarkDataOvlInfo, 1, 0x18, 4, 0xC, -1, "map_mark_data");

            // FBDemo
            if (mGame.isMm())
                loadOvlTable(codeInfo.mFbDemoOvlTable, 7, 0x1C, 0xC, 4, -1, "FbDemo");

            // Actors
            count = mGame.isOot() ? 471 : mGame.isMm() ? 690 : mGame.isAc() ? 180 : 0;
            loadOvlTable(codeInfo.mActorOvlTable, count, 0x20, 0, 8, 0x18, "Actor");

            // EffectSS2
            count = mGame.isOot() ? 37 : mGame.isMm() ? 39 : 0;
            loadOvlTable(codeInfo.mEffectSS2OvlTable, count, 0x1C, 0, 8, -1, "EffectSS2");
            
            // AC specific overlays (hardcoded because there is only one version of AC)
            if (mGame.isAc())
            {
                int idx = 0;
                
                loadOvl("unkOvl_" + idx++, 0x80ab07c0, 0x970920);
                loadOvl("unkOvl_" + idx++, 0x80930960, 0x827de0);
                loadOvl("unkOvl_" + idx++, 0x80a94ac0, 0x954d30);
                loadOvl("unkOvl_" + idx++, 0x809259e0, 0x81d9d0);
                loadOvl("unkOvl_" + idx++, 0x80922800, 0x81aa60);

                
                loadOvlTable(0x8085e4d0, 24, 0x20, 0, 8, -1, "ovlTable1_");
                loadOvlTable(0x80947638, 947, 0x10, 0, 8, -1, "ovlTable2_");
                loadOvlTable(0x80947638, 947, 0x10, 0, 8, -1, "ovlTable3_");
                loadOvl("unkOvl_" + idx++, 0x80aae880, 0x96e9f0);
                loadOvl("unkOvl_" + idx++, 0x8092cd00, 0x824500);
                loadOvlTable(0x80947638, 1, 0x14, 0, 8, -1, "ovlTable4_");
                loadOvlTable(0x809582d0, 2, 0x14, 0, 8, -1, "ovlTable5_");
                loadOvlTable(0x80a11a38, 8, 0x14, 0, 8, -1, "ovlTable6_");
                loadOvlTable(0x80a19b90, 111, 0x14, 0, 8, -1, "ovlTable7_");
                loadOvlTable(0x80a22c40, 5, 0x14, 0, 8, -1, "ovlTable8_");
                loadOvlTable(0x80a5c8bc, 2, 0x14, 0, 8, -1, "ovlTable9_");
            }
        }
    }

    private void loadOvlTable(long addr, int entryCount, int entrySize, int vromOff, int vramOff, int nameOff,
            String defaultName) {
        if (addr == -1 || entryCount == 0)
            return;
        
        byte[] data = new byte[entryCount * entrySize];
        try {
            mApi.getCurrentProgram().getMemory().getBytes(mApi.toAddr(addr), data);
            var br = ByteBuffer.wrap(data);

            for (int i = 0; i < entryCount; i++) {

                if (mApi.getMonitor().isCancelled())
                    return;

                br.position(i * entrySize + vromOff);
                int vrom = br.getInt();
                br.position(i * entrySize + vramOff);
                long vram = br.getInt() & 0xFFFFFFFFl;
                
                String name = (entryCount > 1) ? defaultName + "_" + i : defaultName;
                if (nameOff != -1) {
                    br.position(i * entrySize + nameOff);
                    long namePtr = br.getInt() & 0xFFFFFFFFl;
                    if (namePtr != 0)
                        name = Utils.readString(mApi, namePtr);
                }
                
                
                if (vram != 0)
                    loadOvl(name, vram, vrom);
            }

        } catch (MemoryAccessException e) {
            e.printStackTrace();
            Msg.error(this, e.getMessage());
        }
    }
    

    
    private void loadOvl(String name, long vram, int vrom)
    {
        vram &= 0xFFFFFFFFl;
        
        byte[] ovl = mGame.getFile(vrom).mData;
        byte[] reloc = mGame.isAc()
                ? mGame.getFile(vrom+ovl.length).mData
                : null;

        loadOvl(name, vram, vram, new Zelda64Overlay(ovl, reloc));
    }

    private void loadOvl(String name, long ram, long vram, Zelda64Overlay ovl) {
        Log.info(String.format("creating %s", name));

        // isn't really required since in our case ram == vram but whatever
        ovl.PerformRelocation(mApi, ram, vram);
        
        long relocAddr = -1;
        

        if (ovl.mTextSize != 0)
            createSegment(name + ".text", ram, ovl.GetText(), new MemPerm("R-X"), false);
        ram += ovl.mTextSize;
        
        if (ovl.mDataSize != 0)
            createSegment(name + ".data", ram, ovl.GetData(), new MemPerm("RW-"), false);
        ram += ovl.mDataSize;
        
        if (ovl.mRodataSize != 0)
            createSegment(name + ".rodata", ram, ovl.GetRodata(), new MemPerm("R--"),
                    false);
        ram += ovl.mRodataSize;
        
        // .reloc is directly after .rodata in oot and mm
        if (mGame.isOot() || mGame.isMm())
        {
            relocAddr = ram;
            ram += ovl.mRelocData.length;
        }
        
        if (ovl.mBssSize != 0)
            createEmptySegment(name + ".bss", ram, ram + ovl.mBssSize - 1,
                    new MemPerm("RW-"), false);
        ram += ovl.mBssSize;
        
        // in ac the reloc section isn't really loaded in memory with the ovl (it gets allocated separately).
        // however it does get accounted in the vram addresses so I'm going to load it after .bss
        if (mGame.isAc())
            relocAddr = ram;
        
        try {
            createSegment(name + ".reloc", relocAddr, ovl.GetRelocData(),
                        new MemPerm("R--"), false);

            mApi.createData(mApi.toAddr(relocAddr), new Zelda64OvlRelaInfo().toDataType());
            if (ovl.mEntries.length > 0)
                mApi.createData(mApi.toAddr(relocAddr).add(0x14), new ArrayDataType(StructConverter.DWORD, ovl.mEntries.length, 4));

        } catch (Exception e) {
            e.printStackTrace();
            Msg.error(this, e.getMessage());
        }
    }

    @Override
    protected void addHeaderInfo() {
        super.addHeaderInfo();

        var props = mApi.getCurrentProgram().getOptions(Program.PROGRAM_INFO);
        props.setString("Zelda 64 Build",
                String.format("%s (%s)", mGame.getVersionLongName(), mGame.mVersion.GetBuildName()));
    }

}
