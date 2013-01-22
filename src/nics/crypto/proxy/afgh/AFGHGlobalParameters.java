/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package nics.crypto.proxy.afgh;

import it.unisa.dia.gas.jpbc.CurveGenerator;
import it.unisa.dia.gas.jpbc.CurveParameters;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.field.curve.CurveField;
import it.unisa.dia.gas.plaf.jpbc.pairing.DefaultCurveParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeAPairing;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author david
 */
public class AFGHGlobalParameters {

    private int rBits, qBits;
    private Pairing e;
    private Field G1, G2, Zq;
    private Element g, Z;
    private ElementPowPreProcessing g_ppp, Z_ppp;

    private CurveParameters curveParams;
    private Random random;

    public AFGHGlobalParameters(DefaultCurveParameters curveParameters){
        initialize(curveParameters);
    }

    public AFGHGlobalParameters(int r, int q) {
        rBits = r;
        qBits = q;
        

        random = new Random(0);
        boolean generateCurveFieldGen = false;
        
        // Init the generator...
        CurveGenerator curveGenerator = new TypeACurveGenerator(random, rBits, qBits, generateCurveFieldGen);

        // Generate the parameters...
        curveParams = curveGenerator.generate();
        initialize(curveParams);
    }

    public AFGHGlobalParameters(InputStream is){
        curveParams = new DefaultCurveParameters();
        ((DefaultCurveParameters) curveParams).load(is);
        initialize(curveParams);
    }

    public AFGHGlobalParameters(File f) throws FileNotFoundException{
        this(new FileInputStream(f));
    }

    public AFGHGlobalParameters(byte[] b){
        this(new String(b));
    }

    public AFGHGlobalParameters(String cp){
        try {
            curveParams = new DefaultCurveParameters();
            
            ByteArrayInputStream is = new ByteArrayInputStream(cp.getBytes());
            ((DefaultCurveParameters) curveParams).load(is);
            initialize(curveParams);
        } catch (Exception ex) {
            Logger.getLogger(AFGHGlobalParameters.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private void initialize(CurveParameters cp){
        random = new Random(0);
        //e = PairingFactory.getPairing(cp);

        e = new TypeAPairing(random, cp);

        // Groups G1 and G2 of prime order q
        G1 = e.getG1();
        G2 = e.getGT();

        

        // Field Zq
        Zq = e.getZr();
        


        // Global system parameters: g \in G1, Z = e(g,g) \in G2
        g = ((CurveField) G1).getGen().getImmutable();
//        if(g.isZero()){
//            System.out.println("g es 0!! :(");
//            System.exit(-1);
//        }
//        g = G1.newRandomElement().getImmutable();
        //System.out.println("g = " + ProxyMain.elementToString(g));


        Z = e.pairing(g, g).getImmutable();

        Z_ppp = Z.pow();
        g_ppp = g.pow();

        

        /*
        System.out.println(G1.getClass());
        System.out.println(G2.getClass());
        System.out.println(Zq.getClass());
        System.out.println(e.getClass());
        System.out.println(g.getClass());
        System.out.println(g.toBytes()[0]);
        System.out.println(Z.getClass());*/
        
    }

    public Field getG1() {
        return G1;
    }

    public Field getG2() {
        return G2;
    }

    public Element getZ() {
        return Z;
    }

    public Field getZq() {
        return Zq;
    }

    public Pairing getE() {
        return e;
    }

    public Element getG() {
        return g;
    }

    public ElementPowPreProcessing getZ_ppp() {
        return Z_ppp;
    }

    public ElementPowPreProcessing getG_ppp() {
        return g_ppp;
    }

    @Override
    public String toString() {
        return curveParams.toString();

        /*try {
            ByteArrayOutputStream os = new ByteArrayOutputStream();

            ObjectOutput oo = new ObjectOutputStream(os);
            curveParams.writeExternal(oo);

            os.close();
            return os.toString();
        } catch (IOException ex) {
            Logger.getLogger(GlobalParameters.class.getName()).log(Level.SEVERE, null, ex);
            return "";
        }*/
    }

    public byte[] toBytes() {
        return toString().getBytes();

        /*try {
            ByteArrayOutputStream os = new ByteArrayOutputStream();

            ObjectOutput oo = new ObjectOutputStream(os);
            curveParams.writeExternal(oo);

            os.close();
            return os.toString();
        } catch (IOException ex) {
            Logger.getLogger(GlobalParameters.class.getName()).log(Level.SEVERE, null, ex);
            return "";
        }*/
    }


    
}
