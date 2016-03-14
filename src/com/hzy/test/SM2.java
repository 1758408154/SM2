package com.hzy.test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECFieldElement.Fp;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Base64;

/**
 * @author hongqian_li
 * @Blog www.sitcoder.com
 */
public class SM2 {

	public static SM2 Instance() {

		return new SM2(false);

	}

	public static SM2 InstanceTest() {
		return new SM2(true);

	}

	public boolean sm2Test = false;

	public String[] ecc_param = sm2_test_param;

	public static BigInteger ecc_p;
	public BigInteger ecc_a;
	public BigInteger ecc_b;
	public BigInteger ecc_n;
	public BigInteger ecc_gx;
	public BigInteger ecc_gy;

	public static ECCurve ecc_curve;
	public ECPoint ecc_point_g;

	public ECDomainParameters ecc_bc_spec;

	public ECKeyPairGenerator ecc_key_pair_generator;
	public ECFieldElement ecc_gx_fieldelement;
	public ECFieldElement ecc_gy_fieldelement;

	public SM2(boolean sm2Test) {
		this.sm2Test = sm2Test;

		if (sm2Test)
			ecc_param = sm2_test_param;
		else
			ecc_param = sm2_param;

		ecc_p = new BigInteger(ecc_param[0], 16);
		ecc_a = new BigInteger(ecc_param[1], 16);
		ecc_b = new BigInteger(ecc_param[2], 16);
		ecc_n = new BigInteger(ecc_param[3], 16);
		ecc_gx = new BigInteger(ecc_param[4], 16);
		ecc_gy = new BigInteger(ecc_param[5], 16);

		ecc_gx_fieldelement = new Fp(ecc_p, ecc_gx);
		ecc_gy_fieldelement = new Fp(ecc_p, ecc_gy);

		ecc_curve = new org.bouncycastle.math.ec.ECCurve.Fp(ecc_p, ecc_a, ecc_b);
		ecc_point_g = new org.bouncycastle.math.ec.ECPoint.Fp(ecc_curve, ecc_gx_fieldelement, ecc_gy_fieldelement);

		ecc_bc_spec = new ECDomainParameters(ecc_curve, ecc_point_g, ecc_n);

		ECKeyGenerationParameters ecc_ecgenparam;
		ecc_ecgenparam = new ECKeyGenerationParameters(ecc_bc_spec, new SecureRandom());

		ecc_key_pair_generator = new ECKeyPairGenerator();
		ecc_key_pair_generator.init(ecc_ecgenparam);
	}

	public byte[] Sm2GetZ(byte[] userId, ECPoint userKey) {
		SM3Digest sm3 = new SM3Digest();
		byte[] p;
		// userId length
		int len = userId.length * 8;
		sm3.update((byte) (len >> 8 & 0x00ff));
		sm3.update((byte) (len & 0x00ff));

		// userId
		sm3.update(userId, 0, userId.length);

		// a,b
		p = ecc_a.toByteArray();
		sm3.update(p, 0, p.length);
		p = ecc_b.toByteArray();
		sm3.update(p, 0, p.length);
		// gx,gy
		p = ecc_gx.toByteArray();
		sm3.update(p, 0, p.length);
		p = ecc_gy.toByteArray();
		sm3.update(p, 0, p.length);

		// x,y
		p = userKey.getX().getEncoded();
		sm3.update(p, 0, p.length);
		p = userKey.getY().getEncoded();
		sm3.update(p, 0, p.length);

		// Z
		byte[] md = new byte[sm3.getDigestSize()];
		sm3.doFinal(md, 0);

		return md;
	}

	public void Sm2Sign(byte[] md, BigInteger userD, ECPoint userKey, SM2Result sm2Ret) {
		// e
		BigInteger e = new BigInteger(1, md);
		// k
		BigInteger k = null;
		ECPoint kp = null;
		BigInteger r = null;
		BigInteger s = null;

		do {
			do {
				if (!sm2Test) {
					AsymmetricCipherKeyPair keypair = ecc_key_pair_generator.generateKeyPair();
					ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) keypair.getPrivate();
					ECPublicKeyParameters ecpub = (ECPublicKeyParameters) keypair.getPublic();
					k = ecpriv.getD();
					kp = ecpub.getQ();
				} else {
					String kS = "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F";
					k = new BigInteger(kS, 16);
					kp = ecc_point_g.multiply(k);
				}

				// r
				r = e.add(kp.getX().toBigInteger());
				r = r.mod(ecc_n);
			} while (r.equals(BigInteger.ZERO) || r.add(k).equals(ecc_n));

			// (1 + dA)~-1
			BigInteger da_1 = userD.add(BigInteger.ONE);
			da_1 = da_1.modInverse(ecc_n);
			// s
			s = r.multiply(userD);
			s = k.subtract(s).mod(ecc_n);
			s = da_1.multiply(s).mod(ecc_n);
		} while (s.equals(BigInteger.ZERO));
		sm2Ret.r = r;
		sm2Ret.s = s;
	}

	public class SM2Result {

		public SM2Result() {
		}

		// 签名、验签
		public BigInteger r;
		public BigInteger s;
		public BigInteger R;

		// 密钥交换
		public byte[] sa;
		public byte[] sb;
		public byte[] s1;
		public byte[] s2;

		public ECPoint keyra;
		public ECPoint keyrb;
	}

	public static String[] sm2_test_param = { "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",// p,0
			"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",// a,1
			"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",// b,2
			"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",// n,3
			"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",// gx,4
			"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0" // gy,5
	};

	public static String[] sm2_param = { "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",// p,0
			"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",// a,1
			"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",// b,2
			"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",// n,3
			"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",// gx,4
			"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0" // gy,5
	};

	public class KeyExchange {
		private SM2 sm2;

		private BigInteger userD;
		private ECPoint userKey;

		private BigInteger rD;
		private ECPoint rKey;

		BigInteger _2w;
		BigInteger _2w_1;

		private int ct = 1;
		private SM3Digest sm3keybase = null;
		private int keyOff = 0;
		private byte[] key = null;

		public KeyExchange() {
		}

		public void Init(SM2 sm2, BigInteger userD, ECPoint userKey) {
			this.sm2 = sm2;
			this.userD = userD;
			this.userKey = userKey;

			AsymmetricCipherKeyPair keypair = null;
			keypair = sm2.ecc_key_pair_generator.generateKeyPair();
			ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) keypair.getPrivate();
			ECPublicKeyParameters ecpub = (ECPublicKeyParameters) keypair.getPublic();
			rD = ecpriv.getD();
			rKey = ecpub.getQ();

			int w = sm2.ecc_n.bitLength();
			w = w / 2 - 1;
			_2w = BigInteger.ONE.shiftLeft(w);
			_2w_1 = _2w.subtract(BigInteger.ONE);
		}

		public void Init_test_a(SM2 sm2, BigInteger userD, ECPoint userKey) {
			Init(sm2, userD, userKey);
			rD = new BigInteger("83A2C9C8B96E5AF70BD480B472409A9A327257F1EBB73F5B073354B248668563", 16);
			rKey = sm2.ecc_point_g.multiply(rD);
			// System.out.println("A用户 R (D,x,y)= \n" + rD.ToString(16));
			// System.out.println(rKey.X.ToBigInteger().ToString(16));
			// System.out.println(rKey.Y.ToBigInteger().ToString(16));
		}

		public void Init_test_b(SM2 sm2, BigInteger userD, ECPoint userKey) {
			Init(sm2, userD, userKey);
			rD = new BigInteger("33FE21940342161C55619C4A0C060293D543C80AF19748CE176D83477DE71C80", 16);
			rKey = sm2.ecc_point_g.multiply(rD);
			// System.out.println("B用户 R (D,x,y)= \n" + rD.ToString(16));
			// System.out.println(rKey.X.ToBigInteger().ToString(16));
			// System.out.println(rKey.Y.ToBigInteger().ToString(16));
		}

		public void DoA_1_3(SM2Result sm2Ret) {
			sm2Ret.keyra = rKey;
		}

		public void DoB_1_10(byte[] ida, byte[] idb, ECPoint keyusera, ECPoint keyra, SM2Result sm2Ret) {
			sm2Ret.keyrb = rKey;
			sm2Ret.sb = null;
			sm2Ret.s2 = null;

			byte[] za = null, zb = null;
			if (ida != null)
				za = sm2.Sm2GetZ(ida, keyusera);
			if (idb != null)
				zb = sm2.Sm2GetZ(idb, this.userKey);

			BigInteger x2_ = _2w.add(this.rKey.getX().toBigInteger().add(_2w_1));
			// System.out.println("x2_ = \n" + x2_.ToString(16));

			BigInteger tb = this.userD.add(this.rD.multiply(x2_)).mod(sm2.ecc_n);
			// System.out.println("tb = \n" + tb.ToString(16));

			BigInteger x1_ = _2w.add(keyra.getX().toBigInteger().add(_2w_1));
			// System.out.println("x1_ = \n" + x1_.ToString(16));

			ECPoint pa0 = keyra.multiply(x1_);
			// System.out.println("pa0 (x,y) = ");
			// System.out.println(pa0.X.ToBigInteger().ToString(16));
			// System.out.println(pa0.Y.ToBigInteger().ToString(16));

			ECPoint pa1 = keyusera.add(pa0);
			// System.out.println("pa1 (x,y) = ");
			// System.out.println(pa1.X.ToBigInteger().ToString(16));
			// System.out.println(pa1.Y.ToBigInteger().ToString(16));

			ECPoint pv = pa1.multiply(tb.multiply(sm2.ecc_bc_spec.getH()));
			// System.out.println("pv (x,y) = ");
			// System.out.println(pv.X.ToBigInteger().ToString(16));
			// System.out.println(pv.Y.ToBigInteger().ToString(16));
			if (pv.isInfinity())
				return;

			// key base
			byte[] p;
			sm3keybase = new SM3Digest();
			p = pv.getX().toBigInteger().toByteArray();
			sm3keybase.update(p, 0, p.length);
			p = pv.getY().toBigInteger().toByteArray();
			sm3keybase.update(p, 0, p.length);
			p = za;
			sm3keybase.update(p, 0, p.length);
			p = zb;
			sm3keybase.update(p, 0, p.length);

			ct = 1;
			key = new byte[32];
			keyOff = 0;
			NextKey();

			// hash & hash
			byte[] mdb = new byte[32];
			byte[] mdsb = new byte[32];
			byte[] mds2 = new byte[32];
			SM3Digest hashb = new SM3Digest();
			p = pv.getX().toBigInteger().toByteArray();
			hashb.update(p, 0, p.length);

			if (za != null)
				hashb.update(za, 0, za.length);
			if (zb != null)
				hashb.update(zb, 0, zb.length);

			p = keyra.getX().toBigInteger().toByteArray();
			hashb.update(p, 0, p.length);
			p = keyra.getY().toBigInteger().toByteArray();
			hashb.update(p, 0, p.length);
			p = this.rKey.getX().toBigInteger().toByteArray();
			hashb.update(p, 0, p.length);
			p = this.rKey.getY().toBigInteger().toByteArray();
			hashb.update(p, 0, p.length);
			hashb.doFinal(mdb, 0);
			// String smd = new String(Hex.encode(mdb));
			// System.out.println("hash1 = \n" + smd);

			hashb.reset();
			hashb.update((byte) 0x02);
			p = pv.getY().toBigInteger().toByteArray();
			hashb.update(p, 0, p.length);
			p = mdb;
			hashb.update(p, 0, p.length);
			hashb.doFinal(mdsb, 0);

			// String smdsb = new String(Hex.encode(mdsb));
			// System.out.println("sb = \n" + smdsb);

			hashb.reset();
			hashb.update((byte) 0x03);
			p = pv.getY().toBigInteger().toByteArray();
			hashb.update(p, 0, p.length);
			p = mdb;
			hashb.update(p, 0, p.length);
			hashb.doFinal(mds2, 0);

			// String smds2 = new String(Hex.encode(mds2));
			// System.out.println("s2 = \n" + smds2);

			sm2Ret.s2 = mds2;
			sm2Ret.sb = mdsb;
		}

		public void DoA_4_10(byte[] ida, byte[] idb, ECPoint keyuserb, ECPoint keyrb, SM2Result sm2Ret) {
			sm2Ret.keyra = rKey;
			sm2Ret.sa = null;
			sm2Ret.s1 = null;

			byte[] za = null, zb = null;
			if (ida != null)
				za = sm2.Sm2GetZ(ida, this.userKey);
			if (idb != null)
				zb = sm2.Sm2GetZ(idb, keyuserb);

			BigInteger x1_a = _2w.add(rKey.getX().toBigInteger().add(_2w_1));
			// System.out.println("x1_a = \n" + x1_a.ToString(16));

			BigInteger x2_a = _2w.add(keyrb.getX().toBigInteger().and(_2w_1));
			// System.out.println("x2_a = \n" + x2_a.ToString(16));

			BigInteger ta = userD.add(rD.multiply(x1_a)).mod(sm2.ecc_n);
			// System.out.println("ta = \n" + ta.ToString(16));

			ECPoint pb0 = keyrb.multiply(x2_a);
			// System.out.println("pb0 (x,y) = " );
			// System.out.println(pb0.X.ToBigInteger().ToString(16));
			// System.out.println(pb0.Y.ToBigInteger().ToString(16));

			ECPoint pb1 = keyuserb.add(pb0);
			// System.out.println("pb1 (x,y) = " );
			// System.out.println(pb1.X.ToBigInteger().ToString(16));
			// System.out.println(pb1.Y.ToBigInteger().ToString(16));

			ECPoint pu = pb1.multiply(ta.multiply(sm2.ecc_bc_spec.getH()));
			// System.out.println("pu (x,y) = " );
			// System.out.println(pu.X.ToBigInteger().ToString(16));
			// System.out.println(pu.Y.ToBigInteger().ToString(16));
			if (pu.isInfinity())
				return;

			byte[] p1;
			SM3Digest sm3keybase1 = new SM3Digest();
			p1 = pu.getX().toBigInteger().toByteArray();
			sm3keybase1.update(p1, 0, p1.length);
			p1 = pu.getY().toBigInteger().toByteArray();
			sm3keybase1.update(p1, 0, p1.length);
			p1 = za;
			sm3keybase1.update(p1, 0, p1.length);
			p1 = zb;
			sm3keybase1.update(p1, 0, p1.length);

			byte[] p;
			// key base
			sm3keybase = new SM3Digest();
			p = pu.getX().toBigInteger().toByteArray();
			sm3keybase.update(p, 0, p.length);
			p = pu.getY().toBigInteger().toByteArray();
			sm3keybase.update(p, 0, p.length);
			p = za;
			sm3keybase.update(p, 0, p.length);
			p = zb;
			sm3keybase.update(p, 0, p.length);

			ct = 1;
			key = new byte[32];
			keyOff = 0;
			NextKey();

			// hash & sa & s1
			byte[] mda = new byte[32];
			byte[] mdsa = new byte[32];
			byte[] mds1 = new byte[32];
			SM3Digest hasha = new SM3Digest();
			p = pu.getX().toBigInteger().toByteArray();
			hasha.update(p, 0, p.length);

			if (za != null)
				hasha.update(za, 0, za.length);
			if (zb != null)
				hasha.update(zb, 0, zb.length);

			p = rKey.getX().toBigInteger().toByteArray();
			hasha.update(p, 0, p.length);
			p = rKey.getY().toBigInteger().toByteArray();
			hasha.update(p, 0, p.length);
			p = keyrb.getY().toBigInteger().toByteArray();
			hasha.update(p, 0, p.length);
			p = keyrb.getY().toBigInteger().toByteArray();
			hasha.update(p, 0, p.length);
			hasha.doFinal(mda, 0);

			// String smd1 = new String(Hex.encode(mda));
			// System.out.println("hash1 = \n" + smd1);

			// sa
			hasha.reset();
			hasha.update((byte) 0x03);
			p = pu.getY().toBigInteger().toByteArray();
			hasha.update(p, 0, p.length);
			p = mda;
			hasha.update(p, 0, p.length);
			hasha.doFinal(mdsa, 0);

			// String smdsa = new String(Hex.encode(mdsa));
			// System.out.println("sa = \n" + smdsa);

			hasha.reset();
			hasha.update((byte) 0x02);
			p = pu.getY().toBigInteger().toByteArray();
			hasha.update(p, 0, p.length);
			p = mda;
			hasha.update(p, 0, p.length);
			hasha.doFinal(mds1, 0);

			// String smds1 = new String(Hex.encode(mds1));
			// System.out.println("s1 = \n" + smds1);

			sm2Ret.s1 = mds1;
			sm2Ret.sa = mdsa;
		}

		public void GetKey(byte[] keybuf) {
			for (int i = 0; i < keybuf.length; i++) {
				if (keyOff == key.length)
					NextKey();

				keybuf[i] = key[keyOff++];
			}
		}

		private void NextKey() {
			SM3Digest sm3keycur = new SM3Digest();
			sm3keycur.update((byte) (ct >> 24 & 0x00ff));
			sm3keycur.update((byte) (ct >> 16 & 0x00ff));
			sm3keycur.update((byte) (ct >> 8 & 0x00ff));
			sm3keycur.update((byte) (ct & 0x00ff));
			sm3keycur.doFinal(key, 0);
			keyOff = 0;
			ct++;
		}
	}

	public static SM2 sm2;
	public static BigInteger userD = null;
	public static ECPoint userKey = null;

	// [STAThread]
	public static void main(String[] args) {
		// p,a,b,n,gx,gy
		sm2 = SM2.InstanceTest();
		boolean sm2Test = sm2.sm2Test;
		Date d = new Date();
		new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(d.getTime());// 设置日期格式
		d.getTime();

		String keys = "MIIEDgIBAzCCA8kGCSqGSIb3DQEHAaCCA7oEggO2MIIDsjCB4QYJKoZIhvcNAQcBoIHTBIHQMIHNMIHKBgsqhkiG9w0BDAoBAqB1MHMwJwYKKoZIhvcNAQwBAzAZBBQ4VM7BxgerT/trDTsnU2AG2gO4gAIBFARIVccc9ytsup9K18hNZFQKMYCfhmm+G7SUVojg5y+oDpxzs5AEaIYNSV7J11Wi1LGMXBcjibiNlZy0/twZPxIhoE5msWmQXJGKMUQwHQYJKoZIhvcNAQkUMRAeDgB0AGUAcwB0ADIAMAA2MCMGCSqGSIb3DQEJFTEWBBReej+913azq8nU+Wgp8BV6YjP/pDCCAsoGCSqGSIb3DQEHBqCCArswggK3AgEAMIICsAYJKoZIhvcNAQcBMCcGCiqGSIb3DQEMAQYwGQQUekHWqtVhdUvLatpe/XO3Ez27urMCARSAggJ4osMwInKHBDsoGfgrv8W7WKSDhIbTa9k4AvRcFLwApus5zlAjOz/mudYfziWQuwrGVLlQ+FIcPBY/EVbSLVrysOAIneOcpXN2pKkAZLcV/ltc+O7Eb0APmu43k4V5mEfxdcPO/7WEjCZIMeB2veSkMneWkQvPNtOrJiyqOk5I706vuvLDQFHV00aRU/c0lbptIY00BpDg2Sni+6etcSbuvQFWXpSb3NjF6lM4swM7elZi2R5hiNFYswIuqWg4lLJpw15+fpytXsEjNDE+HMI9U48JJZ3p0yJzTI3OXXTTvKmkll3tM2ki20yeK+2XIirdgupTen3jTsyv8lUYDCYw35Y3ccFYVjHe4KJGF33xVgOzAzHYFwSU7Hwrd3qDvlw/+ahiXqI5jQeML/qEBrabKgSE2dGqmsEY0NnLS2Yce8WBoNkwjEwStef6+BMgyoUPCEsONTxxEO70wVHfQon4lFq/1ljCrCv1YRhAs8zgocmbl+HZw85hHthoUWbhfDzbNz8mrA2RGKxyfcKTX9l4sFwdqVkA6Df7LugOvYidCf0todk66zUqsny3wiy1jnjwhw9nn9QoqTweusXx3a8AiGAQ02Bdcfs+IpywXxCVIeTdqdS/bAHfWvLn5UECkBdtSXiQSmh/o4fuJRWyrFfhmjjSxUEyz1KxWiKBFR9KjqbM1o44Ae2EEQA0RDHIjMiRg0lemsHQw0qyQITZCNy8TTrHMjHyvsqIMckjwNZTf8pSCf7sC+5pGsCs5HpmDlCS5XfzQUe0aTjgdJvQ17M6tLAwemWIJrlFZV5bCnLDBpPH/uUniquX/fWbgMhPEs8oecq2O4tdS/4wPDAhMAkGBSsOAwIaBQAEFIrezY1BFMuHYdUKTeyWkiaQJ1VwBBSi6BWjmOxPSpwHupgWlEzCQzahIQIBFA==";
		byte[] decode = Base64.decode(keys.getBytes());
		String printHexString = printHexString(decode);

		// if (sm2Test) {
		// System.out.println("p = " + sm2.ecc_p.toString(16));
		// System.out.println("a = " + sm2.ecc_a.toString(16));
		// System.out.println("b = " + sm2.ecc_b.toString(16));
		// System.out.println("n = " + sm2.ecc_n.toString(16));
		// System.out.println("gx= " + sm2.ecc_gx.toString(16));
		// System.out.println("gy= " + sm2.ecc_gy.toString(16));
		// System.out.println("h = " + sm2.ecc_bc_spec.getH().toString(16));
		// }
		d.getTime();
		if (sm2Test) {
			System.out.println("密钥对产生 开始时间 = " + System.currentTimeMillis());
			AsymmetricCipherKeyPair keypair = null;
			for (int i = 0; i < 1; i++)
				keypair = sm2.ecc_key_pair_generator.generateKeyPair();
			System.out.println("密钥对产生 结束时间 = " + System.currentTimeMillis());
			ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) keypair.getPrivate();
			ECPublicKeyParameters ecpub = (ECPublicKeyParameters) keypair.getPublic();
			System.out.println("密钥对(D,x,y)= \n");
			printHexString(ecpriv.getD().toByteArray());
			ecpriv.getD().toByteArray();
			ECFieldElement x = ecpub.getQ().getX();
			byte[] encoded = x.getEncoded();
			// System.out.println(x.toBigInteger().toString(16));
			System.out.println("\n");
			printHexString(encoded);
			ECFieldElement y = ecpub.getQ().getY();
			byte[] encoded2 = y.getEncoded();
			System.out.println("\n");
			printHexString(encoded2);
			// System.out.println(y.toBigInteger().toString(16));
			byte[] pk = byteMerger(encoded, encoded2);

			byte[] privateKey = new byte[] { (byte) 0x07, (byte) 0xC7, (byte) 0xBA, (byte) 0x31, (byte) 0xB4, (byte) 0x0D, (byte) 0x0A, (byte) 0x90, (byte) 0x2D, (byte) 0x1A, (byte) 0xD8,
					(byte) 0xDC, (byte) 0x27, (byte) 0x5B, (byte) 0x58, (byte) 0x6A, (byte) 0xD3, (byte) 0xF1, (byte) 0x81, (byte) 0x41, (byte) 0x48, (byte) 0x4C, (byte) 0x07, (byte) 0xDE,
					(byte) 0xFE, (byte) 0x49, (byte) 0x49, (byte) 0xBF, (byte) 0x42, (byte) 0x13, (byte) 0x64, (byte) 0x1F };

			byte[] publickey = new byte[] { (byte) 0xC5, (byte) 0x21, (byte) 0x55, (byte) 0x04, (byte) 0x15, (byte) 0x58, (byte) 0x68, (byte) 0x61, (byte) 0xD4, (byte) 0x80, (byte) 0xEC, (byte) 0x35,
					(byte) 0xBA, (byte) 0x56, (byte) 0x63, (byte) 0x36, (byte) 0x6F, (byte) 0xE0, (byte) 0x53, (byte) 0x0A, (byte) 0x37, (byte) 0x7B, (byte) 0x9C, (byte) 0x68, (byte) 0x46,
					(byte) 0x0B, (byte) 0x06, (byte) 0x49, (byte) 0xB6, (byte) 0xED, (byte) 0x36, (byte) 0x24, (byte) 0x26, (byte) 0x16, (byte) 0x31, (byte) 0x3D, (byte) 0xE2, (byte) 0x59,
					(byte) 0x06, (byte) 0x81, (byte) 0xA3, (byte) 0x05, (byte) 0x75, (byte) 0x7F, (byte) 0x4E, (byte) 0xA6, (byte) 0x11, (byte) 0xAA, (byte) 0x3D, (byte) 0xC7, (byte) 0xE8,
					(byte) 0xDD, (byte) 0x3D, (byte) 0xF1, (byte) 0x55, (byte) 0x3A, (byte) 0x97, (byte) 0x8F, (byte) 0xB8, (byte) 0xA2, (byte) 0xE8, (byte) 0xA3, (byte) 0x84, (byte) 0x93 };
			byte[] encode = Base64.encode(publickey);
			System.out.println("\n");
			System.out.println(new String(encode));
			System.out.println(new String(Base64.encode(privateKey)));
			// BigInteger[] sm2Sign = sm2.Sm2Sign("message digest1".getBytes(),
			// publickey, privateKey);
			System.out.println("签名值\n");
			// // System.out.print(sm2Sign[0].toString(16));
			// System.out.print(sm2Sign[1].toString(16));
			System.out.println("\n");
			// printHexString(sm2Sign[0].toByteArray());
			System.out.println("\n");
			// printHexString(sm2Sign[1].toByteArray());
			System.out.print("\n");
			userD = ecpriv.getD();
			userKey = ecpub.getQ();
		} else {
			userD = new BigInteger("128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897265", 16);
			System.out.println("测试密钥对(D,x,y) = \n" + userD.toString(16));
			userKey = sm2.ecc_point_g.multiply(userD);
			byte[] byteArray = userKey.getX().toBigInteger().toByteArray();
			byte[] byteArray1 = userKey.getY().toBigInteger().toByteArray();

			System.out.println(userKey.getX().toBigInteger().toString(16));
			System.out.println(userKey.getY().toBigInteger().toString(16));
		}
		String publickey = "xSFVBBVYaGHUgOw1ulZjNm/gUwo3e5xoRgsGSbbtNiQmFjE94lkGgaMFdX9OphGqPcfo3T3xVTqXj7ii6KOEkw==";
		String privatekey = "B8e6MbQNCpAtGtjcJ1tYatPxgUFITAfe/klJv0ITZB8=";

		String plaintext = "hello world!qwqeqweqwewq";

		// 签名
		String signStr = sm2.Sm2Sign(plaintext.getBytes(), Base64.decode(publickey.getBytes()), Base64.decode(privatekey.getBytes()));
		// 验签
		boolean verify = sm2.Verify(plaintext.getBytes(), Base64.decode(signStr.getBytes()), Base64.decode(publickey.getBytes()));
		System.out.println(verify + "");
	}

	public boolean Verify(byte[] msg, byte[] signData, byte[] certPK) {
		System.out.println("\n");
		// printHexString(signData);
		System.out.println("\n");
		// printHexString(msg);
		System.out.println("\n");
		byte[] pkX = SubByte(certPK, 0, 32);
		System.out.println("\n");
		// printHexString(pkX);
		byte[] pkY = SubByte(certPK, 32, 32);
		System.out.println("\n");
		// printHexString(pkY);
		BigInteger biX = new BigInteger(1, pkX);
		BigInteger biY = new BigInteger(1, pkY);
		ECFieldElement x = new Fp(ecc_p, biX);
		ECFieldElement y = new Fp(ecc_p, biY);
		ECPoint userKey = new org.bouncycastle.math.ec.ECPoint.Fp(ecc_curve, x, y);
		//
		SM3Digest sm3 = new SM3Digest();
		byte[] sm2Za = sm3.getSM2Za(pkX, pkY, "1234567812345678".getBytes());
		System.out.println("\n");
		// printHexString(sm2Za);
		sm3.update(sm2Za, 0, sm2Za.length);
		System.out.println("\n");
		// printHexString(sm2Za);
		System.out.println("\n");
		byte[] p = msg;
		sm3.update(p, 0, p.length);
		printHexString(p);
		System.out.println("\n");
		byte[] md = new byte[32];
		sm3.doFinal(md, 0);
		printHexString(md);
		byte[] btRS = signData;
		byte[] btR = SubByte(btRS, 0, btRS.length / 2);
		byte[] btS = SubByte(btRS, btR.length, btRS.length - btR.length);

		BigInteger r = new BigInteger(1, btR);
		BigInteger s = new BigInteger(1, btS);

		// e_
		BigInteger e = new BigInteger(1, md);

		// t
		BigInteger t = r.add(s).mod(ecc_n);

		if (t.equals(BigInteger.ZERO))
			return false;

		// x1y1
		ECPoint x1y1 = ecc_point_g.multiply(s);
		x1y1 = x1y1.add(userKey.multiply(t));

		// R
		BigInteger R = e.add(x1y1.getX().toBigInteger()).mod(ecc_n);

		return r.equals(R);

	}

	public static byte[] SubByte(byte[] input, int startIndex, int length) {
		byte[] bt = new byte[length];
		for (int i = 0; i < length; i++) {
			bt[i] = input[i + startIndex];
		}
		return bt;
	}

	public String Sm2Sign(byte[] md, byte[] pk, byte[] privatekey) {
		SM3Digest sm3 = new SM3Digest();

		byte[] pkX = SubByte(pk, 0, 32);
		byte[] pkY = SubByte(pk, 32, 32);

		byte[] z = sm3.getSM2Za(pkX, pkY, "1234567812345678".getBytes());

		sm3.update(z, 0, z.length);

		byte[] p = md;
		sm3.update(p, 0, p.length);

		byte[] hashData = new byte[32];
		sm3.doFinal(hashData, 0);

		// e  
		BigInteger e = new BigInteger(1, hashData);
		// k
		BigInteger k = null;
		BigInteger r = null;
		BigInteger s = null;
		BigInteger userD = null;
		BigInteger x = new BigInteger(1, pkX);
		BigInteger pr = new BigInteger(1, privatekey);
		do {
			do {

				// ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters)
				// keypair
				// .getPrivate();
				k = pr;
				// ecpriv.getD().toString(16);//私钥
				// kp = ecpub.getQ();//pk

				userD = pr;

				// r
				r = e.add(x);
				r = r.mod(ecc_n);
			} while (r.equals(BigInteger.ZERO) || r.add(k).equals(ecc_n));

			// (1 + dA)~-1
			BigInteger da_1 = userD.add(BigInteger.ONE);
			da_1 = da_1.modInverse(ecc_n);
			// s
			s = r.multiply(userD);
			s = k.subtract(s).mod(ecc_n);
			s = da_1.multiply(s).mod(ecc_n);
		} while (s.equals(BigInteger.ZERO));

		byte[] btRS = new byte[64];
		byte[] btR = r.toByteArray();
		byte[] btS = s.toByteArray();
		System.arraycopy(btR, btR.length - 32, btRS, 0, 32);
		System.arraycopy(btS, btS.length - 32, btRS, 32, 32);
		r.toByteArray();
		s.toByteArray();
		byte[] encode = Base64.encode(btRS);
		System.out.println("sssssss-------r" + r.toString(16));
		System.out.println("sssssss-------s" + s.toString(16));
		return new String(encode);
	}


	public static byte[] byteMerger(byte[] byte_1, byte[] byte_2) {
		byte[] byte_3 = new byte[byte_1.length + byte_2.length];
		System.arraycopy(byte_1, 0, byte_3, 0, byte_1.length);
		System.arraycopy(byte_2, 0, byte_3, byte_1.length, byte_2.length);
		return byte_3;
	}

	public static String printHexString(byte[] b) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < b.length; i++) {
			String hex = Integer.toHexString(b[i] & 0xFF);
			if (hex.length() == 1) {
				hex = '0' + hex;
			}
			sb.append(hex.toUpperCase());
		}
		return sb.toString();
	}

	public static int byteToInt2(byte[] b) {

		int mask = 0xff;
		int temp = 0;
		int n = 0;
		for (int i = 0; i < 2; i++) {
			n <<= 8;
			temp = b[i] & mask;
			n |= temp;
		}
		return n;
	}

}