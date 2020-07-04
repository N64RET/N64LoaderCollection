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
            if (game.IsKnown())
                loadSpecs.add(getLoadSpec());
        } catch (Exception e) {

        }

        return loadSpecs;
    }

    @Override
    protected void loadGame() throws CancelledException {

        try {
            mGame = new Zelda64Game(mRom, true, mApi.getMonitor());
        } catch (Exception e) {
            e.printStackTrace();
            mGame = null;
            throw new CancelledException(e.getMessage());
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

        if (!mGame.IsKnown()) {
            throw new CancelledException("Unknown ROM");
        }

        var codeInfo = Zelda64CodeInfo.TABLE.get(mGame.mVersion);
        long entrypoint = mRom.getFixedEntrypoint();

        // boot
        var bootFile = mGame.GetFile(0x00001060);
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

            byte[] code = mGame.GetFile(codeVrom).mData;
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
            int count = mGame.IsOot() ? 6 : mGame.IsMm() ? 7 : 0;
            LoadOvlTable(codeInfo.mGameStateOvlTable, count, 0x30, 4, 0xC, -1, "GameState");

            // KaleidoMgr
            LoadOvlTable(codeInfo.mKaleidoMgrOvlTable, 2, 0x1C, 4, 0xC, 0x18, "KaleidoMgrOvl");

            // map_mark_data
            if (mGame.IsOot())
                LoadOvlTable(codeInfo.mMapMarkDataOvlInfo, 1, 0x18, 4, 0xC, -1, "map_mark_data");

            // FBDemo
            if (mGame.IsMm())
                LoadOvlTable(codeInfo.mFbDemoOvlTable, 7, 0x1C, 0xC, 4, -1, "FbDemo");

            // Actors
            count = mGame.IsOot() ? 471 : mGame.IsMm() ? 690 : 0;
            LoadOvlTable(codeInfo.mActorOvlTable, count, 0x20, 0, 8, 0x18, "Actor");

            // EffectSS2
            count = mGame.IsOot() ? 37 : mGame.IsMm() ? 39 : 0;
            LoadOvlTable(codeInfo.mEffectSS2OvlTable, count, 0x1C, 0, 8, -1, "EffectSS2");
        }
    }

    private String readString(long addr) {

        String str = "";
        try {
            char c = 0;
            do {
                c = (char) mApi.getCurrentProgram().getMemory().getByte(mApi.toAddr(addr));
                if (c != 0)
                    str += c;
                addr++;
            } while (c != 0);
        } catch (Exception e) {
            e.printStackTrace();
            Msg.error(this, e.getMessage());
        }
        return str;
    }

    private void LoadOvlTable(long addr, int entryCount, int entrySize, int vromOff, int vramOff, int nameOff,
            String defaultName) {
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
                        name = readString(namePtr);
                }
                if (vram != 0)
                    LoadOvl(name, vram, vram, new Zelda64Overlay(mGame.GetFile(vrom).mData));
            }

        } catch (MemoryAccessException e) {
            e.printStackTrace();
            Msg.error(this, e.getMessage());
        }
    }

    private void LoadOvl(String name, long dst, long virtStart, Zelda64Overlay ovl) {
        Log.info(String.format("creating %s", name));

        // isn't really required since in our case dst == virtStart but whatever
        ovl.PerformRelocation(mApi, dst, virtStart);

        if (ovl.mTextSize != 0)
            createSegment(name + ".text", dst, ovl.GetText(), new MemPerm("R-X"), false);
        if (ovl.mDataSize != 0)
            createSegment(name + ".data", dst + ovl.mTextSize, ovl.GetData(), new MemPerm("RW-"), false);
        if (ovl.mRodataSize != 0)
            createSegment(name + ".rodata", dst + ovl.mTextSize + ovl.mDataSize, ovl.GetRodata(), new MemPerm("R--"),
                    false);
        if (ovl.mRelocSize != 0)
            createSegment(name + ".reloc", dst + ovl.mTextSize + ovl.mDataSize + ovl.mRodataSize, ovl.GetRelocData(),
                    new MemPerm("RW-"), false);
        if (ovl.mBssSize != 0)
            createEmptySegment(name + ".bss", dst + ovl.mRawData.length, dst + ovl.mRawData.length + ovl.mBssSize - 1,
                    new MemPerm("RW-"), false);
        var addr = mApi.toAddr(dst);
        try {

            mApi.createData(addr.add(ovl.mRelaInfoOff), new Zelda64OvlRelaInfo().toDataType());
            mApi.createData(addr.add(ovl.mRelaInfoOff).add(0x14),
                    new ArrayDataType(StructConverter.DWORD, ovl.mEntries.length, 4));
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
                String.format("%s (%s)", mGame.GetVersionLongName(), mGame.mVersion.GetBuildName()));
    }

}
