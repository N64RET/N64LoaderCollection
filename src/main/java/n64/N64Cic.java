package n64;

public enum N64Cic {
    Unknown(null, "Unknown CIC"),
    CIC_NUS_6101("900B4A5B68EDB71F4C7ED52ACD814FC5", "CIC-NUS-6101/7102"),
    CIC_NUS_6102("E24DD796B2FA16511521139D28C8356B", "CIC-NUS-6102/7101"),
    CIC_NUS_6103("319038097346E12C26C3C21B56F86F23", "CIC-NUS-6103/7103"),
    CIC_NUS_6105("FF22A296E55D34AB0A077DC2BA5F5796", "CIC-NUS-6105/7105"),
    CIC_NUS_6106("6460387749AC0BD925AA5430BC7864FE", "CIC-NUS-6106/7106"),
    
    LylatWars("955894C2E40A698BF98A67B78A4E28FA", "CIC-NUS-6101/7102 (Mod)"); // derivation of 6101
    
    public String mMd5;
    public String mName;
    
    private N64Cic(String md5, String name) {
        mMd5 = md5;
        mName = name;
    }
    
    public static N64Cic FromMd5(String md5) {
        var values = N64Cic.values();
        for (int i = 0; i < values.length; i++)
        {
            if (md5.equals(values[i].mMd5))
                return values[i];
        }
        return N64Cic.Unknown;
    }
}
