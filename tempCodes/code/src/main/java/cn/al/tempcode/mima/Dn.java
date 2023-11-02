package cn.al.tempcode.mima;

import java.util.Arrays;

public class Dn {
    private String c;
    private String st;
    private String l;
    private String o;
    private String[] ou;
    private String cn;
    private String email;

    public Dn(String c, String st, String l, String o, String[] ou, String cn, String email) {
        this.c = c;
        this.st = st;
        this.l = l;
        this.o = o;
        this.ou = ou;
        this.cn = cn;
        this.email = email;
    }

    @Override
    public String toString() {
        return "Dn{" +
                "c='" + c + '\'' +
                ", st='" + st + '\'' +
                ", l='" + l + '\'' +
                ", o='" + o + '\'' +
                ", ou=" + Arrays.toString(ou) +
                ", cn='" + cn + '\'' +
                ", email='" + email + '\'' +
                '}';
    }

    public String getC() {
        return c;
    }

    public void setC(String c) {
        this.c = c;
    }

    public String getSt() {
        return st;
    }

    public void setSt(String st) {
        this.st = st;
    }

    public String getL() {
        return l;
    }

    public void setL(String l) {
        this.l = l;
    }

    public String getO() {
        return o;
    }

    public void setO(String o) {
        this.o = o;
    }

    public String[] getOu() {
        return ou;
    }

    public void setOu(String[] ou) {
        this.ou = ou;
    }

    public String getCn() {
        return cn;
    }

    public void setCn(String cn) {
        this.cn = cn;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Dn() {
    }
}
