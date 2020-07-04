package n64;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.OptionUtils;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.StructConverter;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.lang.Register;

public class N64Loader extends AbstractLibrarySupportLoader {

    protected static final String PIF_ROM_PATH_NAME = "PIF ROM path";
    protected static final String LIBULTRA_OS_SYMS_NAME = "Add Libultra OS Symbols";
    protected static final String LOAD_BOOT_SEGMENT_NAME = "Find and load the boot segment only";

    protected FlatProgramAPI mApi;
    protected N64Rom mRom;
    private boolean mFindBootSegment;

    @Override
    public String getName() {
        return "N64 Loader";
    }

    public final LoadSpec getLoadSpec() {
        return new LoadSpec(this, 0, new LanguageCompilerSpecPair("MIPS:BE:64:64-32addr", "o32"), true);
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        try {
            N64Rom rom = new N64Rom(provider.getInputStream(0).readAllBytes());
            loadSpecs.add(getLoadSpec());
        } catch (Exception e) {

        }

        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
            TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
        byte[] data = provider.getInputStream(0).readAllBytes();

        try {
            mRom = new N64Rom(data);
        } catch (Exception e) {
            e.printStackTrace();
            mRom = null;
            throw new CancelledException(e.getMessage());
        }

        mApi = new FlatProgramAPI(program, monitor);

        // create the n64 memory map / add hardware registers
        try {
            createN64Memory(mRom, OptionUtils.getOption(PIF_ROM_PATH_NAME, options, ""));
        } catch (Exception e) {
            e.printStackTrace();
            throw new CancelledException(e.getMessage());
        }

        mFindBootSegment = OptionUtils.getBooleanOptionValue(LOAD_BOOT_SEGMENT_NAME, options, false);

        loadGame();
        addHeaderInfo();

        if (OptionUtils.getBooleanOptionValue(LIBULTRA_OS_SYMS_NAME, options, true))
            addLibultraOSSymbols();

        try {
            mApi.addEntryPoint(mApi.toAddr(mRom.getFixedEntrypoint()));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
    
    private boolean FindBoot()
    {
        long entrypoint = mRom.getFixedEntrypoint();
        
        ByteBuffer buff = ByteBuffer.wrap(mRom.mRawRom);
        buff.position(0x1000);
        MemoryBlock block = null;
        
        /* The entrypoint code which clears bss is usually the same and looks like this:
         * 
         * u32* bssStart = BSS_START;
         * u32 bssSize = BSS_SIZE;
         * 
         * while (bssSize > 0)
         * {
         *     *bssStart = 0;
         *     *(bssStart+1) = 0;
         *     bssStart += 2;
         *     bssSize -= 8;
         * }
         * 
         * sp = SP_BASE;
         * game_entrypoint();
         */
        try {

            // 0x40 is probably enough
            byte[] entry = new byte[0x60];
            buff.get(entry);

            block = mApi.createMemoryBlock("temp", mApi.toAddr(entrypoint), entry, false);
            block.setPermissions(true, false, true);

            long bssStart = -1;
            long bssSize = -1;


            SimpleEmu emu = new SimpleEmu();
            Address addr = mApi.toAddr(entrypoint);
            mApi.disassemble(addr);
            while (addr.compareTo(mApi.toAddr(entrypoint + entry.length)) < 0) {
                Instruction ins = mApi.getInstructionAt(addr);

                switch (ins.getMnemonicString().replace("_", "")) {
                // check for a sw zero, 0x0(reg containing bssStart)
                case "sw": {
                    var src = (Register) ins.getOpObjects(0)[0];
                    var off = (Scalar) ins.getOpObjects(1)[0];
                    var dst = (Register) ins.getOpObjects(1)[1];

                    if (emu.GetReg(src).isZero && off.getValue() == 0) {
                        if (!emu.GetReg(dst).isConst || bssStart != -1)
                            throw new Exception();

                        bssStart = emu.GetReg(dst).value;
                    }
                    break;
                }
                // the bss size get decreased each iteration
                case "addi": {
                    var dst = (Register) ins.getOpObjects(0)[0];
                    var src = (Register) ins.getOpObjects(1)[0];
                    var imm = (Scalar) ins.getOpObjects(2)[0];

                    if (imm.getSignedValue() < 0)
                    {
                        if (bssSize != -1)
                            throw new Exception();
                        
                        bssSize = emu.GetReg(src).value;
                    }
                    break;
                }
                }

                emu.Execute(ins);
                
                if (bssSize != -1 && bssStart != -1)
                    break;

                addr = addr.add(4);
            }

            if (bssStart == -1 || bssSize == -1)
                throw new Exception();

            mApi.removeMemoryBlock(block);
            
            byte[] code = new byte[(int)(bssStart - entrypoint)];
            buff.position(0x1000);
            buff.get(code);
            
            createSegment("boot", entrypoint, code, new MemPerm("RWX"), false);
            createEmptySegment("boot.bss", bssStart, bssStart+bssSize-1, new MemPerm("RW-"), false);
            return true;

        } catch (Exception e) {

            try
            {
                if (block != null)
                mApi.removeMemoryBlock(block);
            }
            catch (Exception e2) {}
            e.printStackTrace();
            return false;
        }
    }

    protected void loadGame() throws CancelledException {

        long entrypoint = mRom.getFixedEntrypoint();


        if (!mFindBootSegment || !FindBoot()) {

            ByteBuffer buff = ByteBuffer.wrap(mRom.mRawRom);
            buff.position(0x1000);
            byte[] code = new byte[mRom.mRawRom.length - 0x1000];
            buff.get(code);
            createSegment("boot", entrypoint, code, new MemPerm("RWX"), false);
            createEmptySegment("boot.bss", entrypoint + code.length, 0x87FFFFFFl, new MemPerm("RW-"), false);
        }
    }

    private void addLibultraOSSymbols() {
        try {
            mApi.createLabel(mApi.toAddr(0x80000300), "osTvType", true, SourceType.ANALYSIS);
            mApi.createLabel(mApi.toAddr(0x80000308), "osRomBase", true, SourceType.ANALYSIS);
            mApi.createLabel(mApi.toAddr(0x8000030C), "osResetType", true, SourceType.ANALYSIS);
            mApi.createLabel(mApi.toAddr(0x80000318), "osMemSize", true, SourceType.ANALYSIS);
            mApi.createLabel(mApi.toAddr(0x8000031C), "osAppNmiBuffer", true, SourceType.ANALYSIS);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void createN64Memory(N64Rom rom, String pifRomPath) throws Exception {
        createEmptySegment(".ivt", 0x80000000, 0x800003FF, new MemPerm("RWX"), false);
        createEmptySegment(".rdreg", 0xA3F00000, 0xA3F00027, new MemPerm("RW-"), false);
        // CreateEmptySegment(".sp.dmem", 0xA4000000, 0xA4000FFF, new MemPerm("RW-"),
        // false);

        mApi.addEntryPoint(mApi.toAddr(0xA4000040));
        createSegment(".sp.dmem", 0xA4000040, rom.getBootStrap(), new MemPerm("RWX"), false);
        createEmptySegment(".sp.imem", 0xA4001000, 0xA4001FFF, new MemPerm("RW-"), false);
        createEmptySegment(".spreg", 0xA4040000, 0xA4080007, new MemPerm("RW-"), false);
        createEmptySegment(".dpcreg", 0xA4100000, 0xA410001F, new MemPerm("RW-"), false);
        createEmptySegment(".dpsreg", 0xA4200000, 0xA420000F, new MemPerm("RW-"), false);
        createEmptySegment(".mireg", 0xA4300000, 0xA430000F, new MemPerm("RW-"), false);
        createEmptySegment(".vireg", 0xA4400000, 0xA4400037, new MemPerm("RW-"), false);
        createEmptySegment(".aireg", 0xA4500000, 0xA4500017, new MemPerm("RW-"), false);
        createEmptySegment(".pireg", 0xA4600000, 0xA4600033, new MemPerm("RW-"), false);
        createEmptySegment(".rireg", 0xA4700000, 0xA470001F, new MemPerm("RW-"), false);
        createEmptySegment(".sireg", 0xA4800000, 0xA480001B, new MemPerm("RW-"), false);
        createEmptySegment(".cartdom2addr1", 0xA5000000, 0xA5FFFFFF, new MemPerm("RW-"), false);
        createEmptySegment(".cartdom1addr1", 0xA6000000, 0xA7FFFFFF, new MemPerm("RW-"), false);
        createEmptySegment(".cartdom2addr2", 0xA8000000, 0xAFFFFFFF, new MemPerm("RW-"), false);
        createSegment(".cartdom1addr2", 0xB0000000, rom.mRawRom, new MemPerm("RW-"), false);

        if (pifRomPath == null || pifRomPath.isEmpty()) {
            createEmptySegment(".pifrom", 0xBFC00000, 0xBFC007BF, new MemPerm("RW-"), false);
        } else {
            File f = new File(pifRomPath);
            byte[] data = Files.readAllBytes(f.toPath());
            byte[] pifRom = new byte[0x7C0];
            System.arraycopy(data, 0, pifRom, 0, pifRom.length);

            createSegment(".pifrom", 0xBFC00000, pifRom, new MemPerm("RWX"), false);
        }
        mApi.addEntryPoint(mApi.toAddr(0xBFC00000));
        createEmptySegment(".pifram", 0xBFC007C0, 0xBFC007FF, new MemPerm("RW-"), false);

        mApi.createData(mApi.toAddr(0xB0000000), new N64Header().toDataType());

        createData("RDRAM_CONFIG_REG", 0xA3F00000, StructConverter.DWORD);
        createData("RDRAM_DEVICE_ID_REG", 0xA3F00004, StructConverter.DWORD);
        createData("RDRAM_DELAY_REG", 0xA3F00008, StructConverter.DWORD);
        createData("RDRAM_MODE_REG", 0xA3F0000C, StructConverter.DWORD);
        createData("RDRAM_REF_INTERVAL_REG", 0xA3F00010, StructConverter.DWORD);
        createData("RDRAM_REF_ROW_REG", 0xA3F00014, StructConverter.DWORD);
        createData("RDRAM_RAS_INTERVAL_REG", 0xA3F00018, StructConverter.DWORD);
        createData("RDRAM_MIN_INTERVAL_REG", 0xA3F0001C, StructConverter.DWORD);
        createData("RDRAM_ADDR_SELECT_REG", 0xA3F00020, StructConverter.DWORD);
        createData("RDRAM_DEVICE_MANUF_REG", 0xA3F00024, StructConverter.DWORD);

        createData("SP_MEM_ADDR_REG", 0xA4040000, StructConverter.DWORD);
        createData("SP_DRAM_ADDR_REG", 0xA4040004, StructConverter.DWORD);
        createData("SP_RD_LEN_REG", 0xA4040008, StructConverter.DWORD);
        createData("SP_WR_LEN_REG", 0xA404000C, StructConverter.DWORD);
        createData("SP_STATUS_REG", 0xA4040010, StructConverter.DWORD);
        createData("SP_DMA_FULL_REG", 0xA4040014, StructConverter.DWORD);
        createData("SP_DMA_BUSY_REG", 0xA4040018, StructConverter.DWORD);
        createData("SP_SEMAPHORE_REG", 0xA404001C, StructConverter.DWORD);
        createData("SP_PC_REG", 0xA4080000, StructConverter.DWORD);
        createData("SP_IBIST_REG", 0xA4080004, StructConverter.DWORD);

        createData("DPC_START_REG", 0xA4100000, StructConverter.DWORD);
        createData("DPC_END_REG", 0xA4100004, StructConverter.DWORD);
        createData("DPC_CURRENT_REG", 0xA4100008, StructConverter.DWORD);
        createData("DPC_STATUS_REG", 0xA410000C, StructConverter.DWORD);
        createData("DPC_CLOCK_REG", 0xA4100010, StructConverter.DWORD);
        createData("DPC_BUFBUSY_REG", 0xA4100014, StructConverter.DWORD);
        createData("DPC_PIPEBUSY_REG", 0xA4100018, StructConverter.DWORD);
        createData("DPC_TMEM_REG", 0xA410001C, StructConverter.DWORD);

        createData("DPS_TBIST_REG", 0xA4200000, StructConverter.DWORD);
        createData("DPS_TEST_MODE_REG", 0xA4200004, StructConverter.DWORD);
        createData("DPS_BUFTEST_ADDR_REG", 0xA4200008, StructConverter.DWORD);
        createData("DPS_BUFTEST_DATA_REG", 0xA420000C, StructConverter.DWORD);

        createData("MI_INIT_MODE_REG", 0xA4300000, StructConverter.DWORD);
        createData("MI_VERSION_REG", 0xA4300004, StructConverter.DWORD);
        createData("MI_INTR_REG", 0xA4300008, StructConverter.DWORD);
        createData("MI_INTR_MASK_REG", 0xA430000C, StructConverter.DWORD);

        createData("VI_STATUS_REG", 0xA4400000, StructConverter.DWORD);
        createData("VI_ORIGIN_REG", 0xA4400004, StructConverter.DWORD);
        createData("VI_WIDTH_REG", 0xA4400008, StructConverter.DWORD);
        createData("VI_INTR_REG", 0xA440000C, StructConverter.DWORD);
        createData("VI_CURRENT_REG", 0xA4400010, StructConverter.DWORD);
        createData("VI_BURST_REG", 0xA4400014, StructConverter.DWORD);
        createData("VI_V_SYNC_REG", 0xA4400018, StructConverter.DWORD);
        createData("VI_H_SYNC_REG", 0xA440001C, StructConverter.DWORD);
        createData("VI_LEAP_REG", 0xA4400020, StructConverter.DWORD);
        createData("VI_H_START_REG", 0xA4400024, StructConverter.DWORD);
        createData("VI_V_START_REG", 0xA4400028, StructConverter.DWORD);
        createData("VI_V_BURST_REG", 0xA440002C, StructConverter.DWORD);
        createData("VI_X_SCALE_REG", 0xA4400030, StructConverter.DWORD);
        createData("VI_Y_SCALE_REG", 0xA4400034, StructConverter.DWORD);

        createData("AI_DRAM_ADDR_REG", 0xA4500000, StructConverter.DWORD);
        createData("AI_LEN_REG", 0xA4500004, StructConverter.DWORD);
        createData("AI_CONTROL_REG", 0xA4500008, StructConverter.DWORD);
        createData("AI_STATUS_REG", 0xA450000C, StructConverter.DWORD);
        createData("AI_DACRATE_REG", 0xA4500010, StructConverter.DWORD);
        createData("AI_BITRATE_REG", 0xA4500014, StructConverter.DWORD);

        createData("PI_DRAM_ADDR_REG", 0xA4600000, StructConverter.DWORD);
        createData("PI_CART_ADDR_REG", 0xA4600004, StructConverter.DWORD);
        createData("PI_RD_LEN_REG", 0xA4600008, StructConverter.DWORD);
        createData("PI_WR_LEN_REG", 0xA460000C, StructConverter.DWORD);
        createData("PI_STATUS_REG", 0xA4600010, StructConverter.DWORD);
        createData("PI_BSD_DOM1_LAT_REG", 0xA4600014, StructConverter.DWORD);
        createData("PI_BSD_DOM1_PWD_REG", 0xA4600018, StructConverter.DWORD);
        createData("PI_BSD_DOM1_PGS_REG", 0xA460001C, StructConverter.DWORD);
        createData("PI_BSD_DOM1_RLS_REG", 0xA4600020, StructConverter.DWORD);
        createData("PI_BSD_DOM2_LAT_REG", 0xA4600024, StructConverter.DWORD);
        createData("PI_BSD_DOM2_PWD_REG", 0xA4600028, StructConverter.DWORD);
        createData("PI_BSD_DOM2_PGS_REG", 0xA460002C, StructConverter.DWORD);
        createData("PI_BSD_DOM2_RLS_REG", 0xA4600030, StructConverter.DWORD);

        createData("RI_MODE_REG", 0xA4700000, StructConverter.DWORD);
        createData("RI_CONFIG_REG", 0xA4700004, StructConverter.DWORD);
        createData("RI_CURRENT_LOAD_REG", 0xA4700008, StructConverter.DWORD);
        createData("RI_SELECT_REG", 0xA470000C, StructConverter.DWORD);
        createData("RI_REFRESH_REG", 0xA4700010, StructConverter.DWORD);
        createData("RI_LATENCY_REG", 0xA4700014, StructConverter.DWORD);
        createData("RI_RERROR_REG", 0xA4700018, StructConverter.DWORD);
        createData("RI_WERROR_REG", 0xA470001C, StructConverter.DWORD);

        createData("SI_DRAM_ADDR_REG", 0xA4800000, StructConverter.DWORD);
        createData("SI_PIF_ADDR_RD64B_REG", 0xA4800004, StructConverter.DWORD);
        createData("SI_PIF_ADDR_WR64B_REG", 0xA4800010, StructConverter.DWORD);
        createData("SI_STATUS_REG", 0xA4800018, StructConverter.DWORD);
    }

    protected void createData(String name, long addr, DataType type) throws Exception {
        mApi.createData(mApi.toAddr(addr), type);
        mApi.createLabel(mApi.toAddr(addr), name, true, SourceType.ANALYSIS);
    }

    protected void createSegment(String name, long start, byte[] data, MemPerm perm, boolean overlay) {
        try {
            MemoryBlock block = mApi.createMemoryBlock(name, mApi.toAddr(start), data, overlay);
            block.setPermissions(perm.R, perm.W, perm.X);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void createEmptySegment(String name, long start, long end, MemPerm perm, boolean overlay) {
        try {
            MemoryBlock block = mApi.getCurrentProgram().getMemory().createUninitializedBlock(name, mApi.toAddr(start),
                    (end + 1 - start), overlay);
            block.setPermissions(perm.R, perm.W, perm.X);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    protected void addHeaderInfo() {
        var props = mApi.getCurrentProgram().getOptions(Program.PROGRAM_INFO);
        N64CheckSum sum = new N64CheckSum(mRom.mRawRom, mRom.mCic);
        props.setString("N64 ClockRate",
                ((mRom.getClockRate() == 0) ? "Default" : String.format("%dHz", mRom.getClockRate())));
        props.setString("N64 EntryPoint", String.format("%08X", mRom.getEntryPoint()));
        props.setString("N64 Release Address", String.format("%08X", mRom.getReleaseAddress()));
        props.setString("N64 CRC1", String.format("%08X", mRom.getCRC1())
                + ((mRom.mCic == N64Cic.Unknown) ? "" : (sum.getCRC1() == mRom.getCRC1() ? " (VALID)" : " (INVALID)")));
        props.setString("N64 CRC2", String.format("%08X", mRom.getCRC2())
                + ((mRom.mCic == N64Cic.Unknown) ? "" : (sum.getCRC2() == mRom.getCRC2() ? " (VALID)" : " (INVALID)")));
        props.setString("N64 Name", mRom.getName());
        props.setString("N64 Game Code", mRom.getGameCode());
        props.setString("N64 Mask ROM Version", String.format("%02X", mRom.getVersion()));
        props.setString("N64 Libultra Version", String.format("OS2.0%c", mRom.getLibultraVersion()));
        props.setString("N64 CIC chip", mRom.mCic.mName);
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec, DomainObject domainObject,
            boolean isLoadIntoProgram) {
        List<Option> list = super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);
        list.add(new Option(PIF_ROM_PATH_NAME, String.class));
        list.add(new Option(LIBULTRA_OS_SYMS_NAME, true));
        if (this.getName().equals("N64 Loader"))
            list.add(new Option(LOAD_BOOT_SEGMENT_NAME, false));
        return list;
    }

    @Override
    public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {
        for (Option option : options) {
            if (option.getName().equals(PIF_ROM_PATH_NAME)) {
                String str = (String) option.getValue();
                if (str != null && !str.isEmpty()) {
                    File f = new File(str);
                    if (!f.exists() || f.isDirectory())
                        return "Could not find PIF rom";
                    if (f.length() < 0x7C0)
                        return "Invalid PIF rom size";
                }
            }
        }

        return super.validateOptions(provider, loadSpec, options, program);
    }

    @Override
    protected void postLoadProgramFixups(List<Program> loadedPrograms, DomainFolder folder, List<Option> options,
            MessageLog messageLog, TaskMonitor monitor) throws CancelledException, IOException {
        super.postLoadProgramFixups(loadedPrograms, folder, options, messageLog, monitor);
    }
}
