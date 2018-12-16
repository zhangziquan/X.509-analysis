import java.io.File;
import java.io.FileInputStream;
import java.util.HashMap;
import java.util.Map;

public class CertReader {
    public final static byte tag_Boolean = 0x01;
    public final static byte tag_Integer = 0x02;
    public final static byte tag_BitString = 0x03;
    public final static byte tag_OctetString = 0x04;
    public final static byte tag_Null = 0x05;
    public final static byte tag_ObjectId = 0x06;
    public final static byte tag_Enumerated = 0x0A;
    public final static byte tag_UTF8String = 0x0C;
    public final static byte tag_PrintableString = 0x13;
    public final static byte tag_T61String = 0x14;
    public final static byte tag_IA5String = 0x16;
    public final static byte tag_UtcTime = 0x17;
    public final static byte tag_GeneralizedTime = 0x18;
    public final static byte tag_GeneralString = 0x1B;
    public final static byte tag_UniversalString = 0x1C;
    public final static byte tag_BMPString = 0x1E;
    public final static byte tag_Sequence = 0x30;
    public final static byte tag_SequenceOf = 0x30;
    public final static byte tag_Set = 0x31;
    public final static byte tag_SetOf = 0x31;

    Map<String, String> map;

    public byte[] cer = null;
    private String output = "";
    private int count = 0;

    public int readpoint = 0;

    public static void main(String[] args) {
        CertReader certReader = new CertReader();
        certReader.init();
        certReader.readData("ca.cer");
        certReader.TLV();
    }

    public void init() {
        map = new HashMap<String, String>();
        map.put("2.5.4.6", "Country");
        map.put("2.5.4.7", "Locality ");
        map.put("2.5.4.8", "Sate or province name ");
        map.put("2.5.4.10", "Organization name ");
        map.put("2.5.4.11", "Organizational Unit name ");
        map.put("2.5.4.3", "Common Name ");
        
        map.put("2.5.29.19", "Basic Constraints");
        map.put("2.5.29.15", "Key Usage");
        map.put("2.5.29.14", "Subject Key Identifier");
        map.put("2.5.29.31", "CRL Distribution Points");
        map.put("1.3.6.1.4.1.311.21.1", "Windows");

        map.put("1.2.840.10040.4.1", "DSA");
        map.put("1.2.840.10040.4.3", "sha1DSA");
        map.put("1.2.840.113549.1.1.1", "RSA");
        map.put("1.2.840.113549.1.1.2", "md2RSA");
        map.put("1.2.840.113549.1.1.3", "md4RSA");
        map.put("1.2.840.113549.1.1.4", "md5RSA");
        map.put("1.2.840.113549.1.1.5", "sha1RSA");
    }

    public void readData(String filename) {
        File file = new File(filename);

        try {
            FileInputStream in = new FileInputStream(file);
            cer = new byte[2000];
            byte[] buffer = new byte[1];
            int bytenum = in.read(buffer);

            while (bytenum != -1) {
                cer[count++] = buffer[0];
                bytenum = in.read(buffer);
            }
            in.close();
            System.out.println(count);

        } catch (Exception e) {
            // TODO: handle exception
            System.out.print(e);
        }
    }

    public int TLV() {
        if (readpoint > count) {
            return 65536;
        }
        char type = (char) cer[readpoint++];
        char len0 = (char) cer[readpoint++];
        int len = (0x000000FF & len0);
        //System.out.println("TAG: " + (0x000000FF & type) + " len : " + len);
        output = "";
        if (type < 0xa0) {
            if (type == tag_Boolean) {
                char vc = (char) cer[readpoint++];
                if (vc == 0) {
                    output = "FALSE";
                } else {
                    output = "TRUE";
                }
            } else if (type == tag_Integer) {
                if (len0 > 0x80) {
                    int tn2 = len0 - 0x80;
                    char next;
                    len = 0;
                    for (int j = 0; j < (0x000000FF & tn2); j++) {
                        next = (char) cer[readpoint++];
                        len *= 256;
                        len += next;
                    }
                }
                bitfill((0x000000FF & len));
            } else if (type == tag_BitString) {
                if (len0 > 0x80) {
                    int tn2 = len0 - 0x80;
                    char next;
                    len = 0;
                    for (int j = 0; j < (0x000000FF & tn2); j++) {
                        next = (char) cer[readpoint++];
                        len *= 256;
                        len += next;
                    }
                }
                bitfill((len));
            } else if (type == tag_OctetString) {
                if (len0 > 0x80) {
                    int tn2 = len0 - 0x80;
                    char next;
                    len = 0;
                    for (int j = 0; j < tn2; j++) {
                        next = (char) cer[readpoint++];
                        len *= 256;
                        len += next;
                    }
                }
                bitStringfill((0x000000FF & len));
            } else if (type == tag_Null) {
                output = "NULL";
            } else if (type == tag_ObjectId) {
                output = "";
                int lend = (0x000000FF & len0);
                char next = (char) cer[readpoint++];
                int d = next / 40;
                String out;
                out = String.format("%d", d);
                output += out;
                output += ".";
                d = next - d * 40;
                out = String.format("%d", d);
                output += out;
                for (int i = 1; i < lend; i++) {
                    output += ".";
                    i--;
                    int t = 0;
                    while (true) {
                        next = (char) cer[readpoint++];
                        i++;
                        boolean b2 = false;
                        if ((next & 0x80) == 0x80) {
                            b2 = true;
                        }
                        if (b2) {
                            next &= 0x7f;
                        }
                        t *= 128;
                        t += (0x000000FF & next);
                        if (!b2) {
                            break;
                        }
                    }
                    out = String.format("%d", t);
                    output += out;
                }
            } else if (type == tag_PrintableString) {
                int d = (0x000000FF & len0);
                for (int i = 0; i < d; i++) {
                    char s = (char) cer[readpoint++];
                    output += s;
                }
                output += "\0";
            } else if (type == tag_UtcTime) {
                int d = (0x000000FF & len0);
                for (int i = 0; i < d; i++) {
                    char s = (char) cer[readpoint++];
                    int t = (0x000000FF & s) - 48;
                    String ss = String.format("%d", t);
                    output += ss;
                }
                output += "\0";

            } else if (type == tag_GeneralizedTime) {
                int d = (0x000000FF & len0);
                for (int i = 0; i < d; i++) {
                    char s = (char) cer[readpoint++];
                    output += s;
                }
                output += "\0";
            } else if (type == tag_Sequence || type == tag_Set) {
                if (len0 > 0x80) {
                    len = 0;
                    len0 -= 0x80;
                    char next;
                    for (int i = 0; i < (0x000000FF & len0); i++) {
                        next = (char) cer[readpoint++];
                        len *= 256;
                        len += next;
                    }
                }
                int dlen = len;
                while (dlen > 0) {
                    dlen -= TLV();
                }
            } else {

            }
        } else {
            if (len0 > 0x80) {
                int tn2 = len0 - 0x80;
                char next;
                len = 0;

                for (int i = 0; i < (0x000000FF & tn2); i++) {
                    next = (char) cer[readpoint++];
                    len *= 256;
                    len += next;
                }
            }
            TLV();
        }
        if (output != "") {
            if (map.containsKey(output)) {
                output = (String) map.get(output);
            }
            System.out.println(output);
            output = "";
        }
        return len;
    }

    public void bitfill(int len) {
        output = "";
        for (int i = 0; i < len; i++) {
            char next = (char) cer[readpoint++];
            int d = (0x000000FF & next);
            String out;
            out = String.format("%02x", d);
            output += out;
        }
    }

    public void bitStringfill(int len) {
        output = "";
        for (int i = 0; i < len; i++) {
            char next = (char) cer[readpoint++];
            output += next;
        }
    }
}