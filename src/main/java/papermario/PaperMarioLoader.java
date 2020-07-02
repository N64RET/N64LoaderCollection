package papermario;

import n64.*;
import java.nio.ByteBuffer;
import org.python.jline.internal.Log;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;

public class PaperMarioLoader extends N64Loader {
    @Override
    public String getName() {
        return "PaperMario 64 Loader";
    }
    
    @Override
    protected void loadGame()
    {
        var codeInfo = PaperMarioCodeInfo.TABLE.get(PaperMarioVersion.USA);
        long entrypoint = mRom.getFixedEntrypoint();
        
        ByteBuffer buff = ByteBuffer.wrap(mRom.mRawRom);
        buff.position(0x1000);
        
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

        ProcessOvlTableInfos(codeInfo.mOvlTableInfos);
        int idx = 0;
        LoadBlock(idx++, 0x80280000, 0x7e0e80, 0x7e73a0);

        LoadBlock(idx++, 0x8023e000, 0x16c8e0, 0x1cc310);

        // LoadBlock(idx++, 0x800a0910, 0x1fe1b0, 0x2191b0);

        LoadBlock(idx++, 0x800dc500, 0x759b0, 0xa5dd0);
        LoadBlock(idx++, 0x8010f6d0, 0xa5dd0, 0xe79b0);
        LoadBlock(idx++, 0x802c3000, 0xe79b0, 0xfee30);
        LoadBlock(idx++, 0x802dbd40, 0xfee30, 0x102610);
        LoadBlock(idx++, 0x802e0d90, 0x102610, 0x10cc10);
        LoadBlock(idx++, 0x802eb3d0, 0x10cc10, 0x10f1b0);
    }

    private void LoadBlock(int idx, long ram, long romStart, long romEnd) {
        ByteBuffer buff = ByteBuffer.wrap(mRom.mRawRom);
        buff.position((int) romStart);
        byte[] block = new byte[(int) (romEnd - romStart)];
        buff.get(block);
        createSegment("block_" + idx, ram, block, new MemPerm("RWX"), true);
    }

    public void ProcessOvlTableInfos(long addr) {
        byte[] entry = new byte[0x10];

        for (int i = 0;; i++) {
            try {

                if (mApi.getMonitor().isCancelled())
                    return;

                mApi.getCurrentProgram().getMemory().getBytes(mApi.toAddr(addr + i * 0x10), entry);
                var br = ByteBuffer.wrap(entry);

                int count = br.getInt();
                long table = br.getInt() & 0xFFFFFFFFl;
                String name = readString(br.getInt() & 0xFFFFFFFFl, "ovlTable", i);
                long unkInfo = br.getInt() & 0xFFFFFFFFl;

                if (table == 0)
                    break;

                Log.info(
                        String.format("Loading Overlay Table: name=\"%s\"; addr=0x%X; count=0x%X", name, table, count));
                ProcessOvlTable(name, table, count);

            } catch (MemoryAccessException e) {
                e.printStackTrace();
                Msg.error(this, e.getMessage());
            }

        }
    }

    private void ProcessOvlTable(String tableName, long tableAddr, int count) throws MemoryAccessException {
        byte[] data = new byte[count * 0x20];

        mApi.getCurrentProgram().getMemory().getBytes(mApi.toAddr(tableAddr), data);
        var br = ByteBuffer.wrap(data);

        for (int i = 0; i < count; i++) {
            String name = readString(br.getInt() & 0xFFFFFFFFl, tableName, i);
            long unk1 = br.getInt() & 0xFFFFFFFFl;
            long romStart = br.getInt() & 0xFFFFFFFFl;
            long romEnd = br.getInt() & 0xFFFFFFFFl;
            long vram = br.getInt() & 0xFFFFFFFFl;
            String bgName = readString(br.getInt() & 0xFFFFFFFFl, tableName + "_bg", i);
            int unk2 = br.getInt();
            int unk3 = br.getInt();

            Log.info(String.format("Loading Overlay: name=\"%s\"; bgName=\"%s\"; vram=0x%X; rom=0x%X-0x%X;", name,
                    bgName, vram, romStart, romEnd));

            byte[] ovl = new byte[(int) (romEnd - romStart)];
            var romBr = ByteBuffer.wrap(mRom.mRawRom);
            romBr.position((int) romStart);
            romBr.get(ovl);
            createSegment(name, vram, ovl, new MemPerm("RWX"), true);

        }

    }

    private String readString(long addr, String prefix, int idx) {
        return addr == 0 ? (prefix + "_" + idx) : readStringImpl(addr);
    }

    private String readStringImpl(long addr) {

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
}
