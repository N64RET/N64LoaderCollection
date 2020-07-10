package zelda64;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import n64.*;

import ghidra.util.task.TaskMonitor;

public class Zelda64Game {
    public N64Rom mRom;
    public Zelda64Version mVersion;
    public int mDmaDataOff;
    public List<Zelda64File> mFiles;

    
    public Zelda64Game(N64Loader loader, boolean loadFs)
    {
        this.mRom = loader.mRom;
        identifyVersion(loader);
        mFiles = null;
        if (loadFs && isKnown())
            mFiles = getFs(loader.mApi.getMonitor());
    }
    
    public Zelda64Game(N64Rom rom, boolean loadFs, TaskMonitor monitor) {
        this.mRom = rom;
        identifyVersion(null);
        mFiles = null;
        if (loadFs && isKnown())
            mFiles = getFs(monitor);
    }

    public Zelda64Game(byte[] data, boolean loadFs, TaskMonitor monitor) throws Exception {
        this(new N64Rom(data), loadFs, monitor);
    }

    private void identifyVersion(N64Loader loader) {
        
        int endSearch = loader != null
                ? (int)(loader.mBootBssStart - mRom.getFixedEntrypoint() + 0x1000)
                :0x100000;
                
        switch (mRom.getName())
        {
        case "THE LEGEND OF ZELDA":
        case "ZELDA MAJORA'S MASK":
        case "THE MASK OF MUJURA":
        case "MAJORA'S MASK":
        case "DOUBUTSUNOMORI":
            break;
        default:
            mVersion = Zelda64Version.Invalid;
            return;
        }
                
        // avoid duplicates for better performances
        List<String> teams = new ArrayList<String>();
        List<String> dates = new ArrayList<String>();
        for (var version : Zelda64Version.values())
        {
            if (version == Zelda64Version.Invalid)
                continue;
            if (!teams.contains(version.mTeam))
                teams.add(version.mTeam);
            if (!dates.contains(version.mDate))
                dates.add(version.mDate);
        }
        
        for (int i = 0x1000; i < endSearch; i++) {
            for (var team : teams)
            {
                // split build team and build date

                int off = i;
                if (compareString(off, team))
                {
                    // build date match
                    off = (off+team.length()+1) + 3 & ~3;
                    
                    for (var date : dates)
                    {
                        if (compareString(off, date))
                        {
                            // make option
                            off = (off+date.length()+1) + 3 & ~3;
                            
                            // segment padding
                            off = off + 1 + 0xF & ~0xF;
                            mDmaDataOff = off;
                            mVersion = Zelda64Version.FromString(team, date);
                            return;
                        }
                    }
                    break;
                }
                
            }
        }
        mVersion = Zelda64Version.Invalid;
    }

    public boolean isOot() {
        switch (mVersion) {
        case OotEurope10:
        case OotEurope11:
        case OotEuropeGC:
        case OotEuropeGCMq:
        case OotEuropeGCMqDbg:
        case OotEuropeGCDbg:
        case OotJPUS10:
        case OotJPUS11:
        case OotJPUS12:
        case OotJapanGC:
        case OotJapanGcZeldaCollection:
        case OotJapanGCMq:
        case OotUSAGC:
        case OotUSAGCMq:
            return true;
        default:
            return false;

        }
    }

    public boolean isMm() {
        switch (mVersion) {
        case MmEurope10:
        case MmEurope11:
        case MmEurope11Debug:
        case MmJapan10:
        case MmJapan11:
        case MmUSA10:
        case MmUSADebug:
        case MmUSADemo:
            return true;
        default:
            return false;
        }
    }
    
    public boolean isAc()
    {
        return (mVersion == Zelda64Version.Ac);
    }

    public boolean isKnown() {
        return isOot() || isMm() || isAc();
    }

    public String getVersionLongName() {
        String gameName = isOot() ? "Ocarina Of Time" : isMm() ? "Majora's Mask" : "???";

        switch (mVersion) {
        case Invalid:
            return gameName + " Invalid";
        case MmEurope10:
            return gameName + " Europe 1.0";
        case MmEurope11:
            return gameName + " Europe 1.1";
        case MmEurope11Debug:
            return gameName + " Europe 1.1 Debug";
        case MmJapan10:
            return gameName + " Japan 1.0";
        case MmJapan11:
            return gameName + " Japan 1.1";
        case MmUSA10:
            return gameName + " USA 1.0";
        case MmUSADebug:
            return gameName + " USA Debug";
        case MmUSADemo:
            return gameName + " USA Kiosk Demo";
        case OotEurope10:
            return gameName + " Europe 1.0";
        case OotEurope11:
            return gameName + " Europe 1.1";
        case OotEuropeGC:
            return gameName + " Europe GameCube";
        case OotEuropeGCMq:
            return gameName + " Europe Master Quest";
        case OotEuropeGCMqDbg:
            return gameName + " Europe Master Quest Debug";
        case OotEuropeGCDbg:
            return gameName + " Europe GameCube Debug";
        case OotJPUS10:
            return gameName + " JP/US 1.0";
        case OotJPUS11:
            return gameName + " JP/US 1.1";
        case OotJPUS12:
            return gameName + " JP/US 1.2";
        case OotJapanGC:
            return gameName + " Japan GameCube";
        case OotJapanGcZeldaCollection:
            return gameName + " Japan GameCube Zelda Collection";
        case OotJapanGCMq:
            return gameName + " Japan Master Quest";
        case OotUSAGC:
            return gameName + " USA GameCube";
        case OotUSAGCMq:
            return gameName + " USA Master Quest";
        case Ac:
            return "Doubutsu no Mori";
        default:
            return "Invalid or unknown version";
        }

    }
    
    private boolean compareString(int romOff, String str)
    {
        /*
        byte[] bytes = str.getBytes(StandardCharsets.US_ASCII);
        return Utils.memcmp(mRom.mRawRom, romOff, bytes, 0, bytes.length);
        */

        for (int i = 0; i < str.length(); i++) {
            if (mRom.mRawRom[romOff + i] != (byte)str.charAt(i)) {
                return false;
            }
        }
        
        return true;
    }

    public List<Zelda64File> getFs(TaskMonitor monitor) {
        List<Zelda64File> ret = new ArrayList<Zelda64File>();
        int filecount = 3; // dmadata file

        ByteBuffer buff = ByteBuffer.wrap(mRom.mRawRom);
        buff.position(mDmaDataOff);

        for (int i = 0; i < filecount; i++) {
            if (monitor != null) {
                if (monitor.isCancelled())
                    break;
                if (i > 2)
                    monitor.setProgress(i);
            }

            DmaDataEntry entry = new DmaDataEntry(buff);
            Zelda64File file = entry.toFile(this);
            ret.add(file);
            if (entry.valid() && entry.exist()) {
                if (i == 2) // dmadata
                {
                    filecount = file.mData.length / 0x10;
                    if (monitor != null)
                        monitor.initialize(filecount);
                }
            }
        }

        return ret;
    }

    public Zelda64File getFile(int vrom) {
        if (mFiles == null)
            return null;
        for (Zelda64File file : mFiles) {
            if (file.mVromStart == vrom)
                return file;
        }
        return null;
    }

    public static class DmaDataEntry {
        private int VRomStart;
        private int VRomEnd;
        private int RomStart;
        private int RomEnd;

        public boolean valid() {
            return (VRomStart != 0 || VRomEnd != 0 || RomStart != 0 || RomEnd != 0);
        }

        public boolean exist() {
            return RomStart != -1 && RomEnd != -1;
        }

        public boolean compressed() {
            return RomEnd != 0;
        }

        public DmaDataEntry(ByteBuffer buff) {
            VRomStart = buff.getInt();
            VRomEnd = buff.getInt();
            RomStart = buff.getInt();
            RomEnd = buff.getInt();
        }

        public int getSize() {
            if (!valid() || !exist())
                return 0;
            return compressed() ? RomEnd - RomStart : VRomEnd - VRomStart;
        }

        public Zelda64File toFile(Zelda64Game mm64) {
            if (!valid())
                return new Zelda64File(null, -1, -1, false, 0);

            if (!exist())
                return Zelda64File.DeletedFile(VRomStart, RomStart, VRomEnd - VRomStart);

            int len = getSize();

            ByteBuffer buff = ByteBuffer.wrap(mm64.mRom.mRawRom);
            buff.position(RomStart);
            byte[] data = new byte[len];
            buff.get(data);

            if (compressed())
                data = Yaz0.DecodeBuffer(data);

            return new Zelda64File(data, VRomStart, RomStart, compressed(), len);
        }
    }
}
