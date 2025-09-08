import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.upokecenter.cbor.CBORObject;
import de.grooby34.masterthesis.FIDO2Applet;
import javacard.framework.AID;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class Fido2AppletTest {
    private static final byte[] AID = {(byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x06}; // your FIDO2 AID
    private CardSimulator simulator;
    private AID appletAID;

    @BeforeEach
    public void setup() throws CardException {
        simulator = new CardSimulator();
        appletAID = AIDUtil.create(AID);
        simulator.installApplet(appletAID, FIDO2Applet.class);
        simulator.selectApplet(appletAID);
    }

    private ResponseAPDU transmit(CommandAPDU cmd) throws CardException {
        ResponseAPDU resp = simulator.transmitCommand(cmd);
        System.out.printf("APDU SW1=%02X SW2=%02X data=%s%n",
                resp.getSW1(), resp.getSW2(),
                Arrays.toString(resp.getData()));
        return resp;
    }

   /* @Test
    public void testGetInfo() throws Exception {
        // CTAP2 INS = 0x04
        ResponseAPDU resp = transmit((byte)0x00, (byte)0x04, (byte)0x00, (byte)0x00, null);
        assertEquals(0x9000, resp.getSW());
        // further parse resp.getData() for versions, options, aaguid...
    }*/

    @Test
    public void testMakeCredential() throws Exception {
        // 1) Prepare a random clientDataHash
        SecureRandom rnd = new SecureRandom();
        byte[] clientDataHash = new byte[32];
        rnd.nextBytes(clientDataHash);

        // Relying Party
        CBORObject rp = CBORObject.NewMap();
        rp.Add("id", "working-tarpon-lately.ngrok-free.app");
        rp.Add("name", "working-tarpon-lately.ngrok-free.ap");

        // User
        byte[] userID = new byte[32];
        rnd.nextBytes(userID);
        CBORObject user = CBORObject.NewMap();
        user.Add("id", "d2ViYXV0aG5pby1ndXJl");
        user.Add("displayName", "gure");

        // pubKeyCredParams [ { type: "public-key", alg: -7 } ]
        CBORObject pubKeyCredParamsItem = CBORObject.NewMap();
        pubKeyCredParamsItem.Add("type", "public-key");
        pubKeyCredParamsItem.Add("alg", -7); // COSE_ES256
        CBORObject pubKeyCredParams = CBORObject.NewArray();
        pubKeyCredParams.Add(pubKeyCredParamsItem);

        // 2) Build the CBOR map
        // Options { rk: true, uv: false }
        CBORObject options = CBORObject.NewMap();
        options.Add("rk", CBORObject.True);
        options.Add("uv", CBORObject.False);

        // Assemble main request (CBOR map, integer keys per CTAP2)
        CBORObject makeCredentialRequest = CBORObject.NewMap();
        makeCredentialRequest.Add(1, CBORObject.FromObject(clientDataHash));
        makeCredentialRequest.Add(2, rp);
        makeCredentialRequest.Add(3, user);
        makeCredentialRequest.Add(4, pubKeyCredParams);
//        makeCredentialRequest.Add(6, options);

        // 3) Encode to bytes
        byte[] payload = makeCredentialRequest.EncodeToBytes();
                //Hex.decodeHex("
        // a4015820d3e3ec9bd761d7f40ddf0d81e7041dce18860751b0e721a2e8d7da60b4cb2d92 02a26269647824776f726b696e672d746172706f6e2d6c6174656c792e6e67726f6b2d667265652e617070646e616d65782 4776f726b696e672d746172706f6e2d6c6174656c792e6e67726f6b2d667265652e61707003a2626964746432566959585630614735706279316e64584a6c6b646973706c61794e616d6564677572650481a263616c672664747970656a7075626c69632d6b6579");//;
        // a4015820fa6a4e6ec24c65bc6858d6b6b2d77b6d26712fd35b500456fe940bf8b178f8ea 02a26269647824776f726b696e672d746172706f6e2d6c6174656c792e6e67726f6b2d667265652e617070646e616d65782 3776f726b696e672d746172706f6e2d6c6174656c792e6e67726f6b2d667265652e617003a2626964746432566959585630614735706279316e64584a6c6b646973706c61794e616d6564677572650481a263616c672664747970656a7075626c69632d6b6579
        System.out.println(Hex.encodeHexString(payload));


        // 4) Send CTAP2 makeCredential (CLA=0x00, INS=0x01)
        CommandAPDU cmd = new CommandAPDU(
                0x80, // CLA
                0x01, // INS = authenticatorMakeCredential
                0x00, // P1
                0x00, // P2
                payload
        );

        System.out.println(Hex.encodeHexString(cmd.getBytes()));
        // 8001000097a4015820e529a57643c8f5a12c92ca410c85a39d2eb45cfed324a52bfdaf83767390ef3c02a26269646b6578616d706c652e636f6d646e616d65674578616d706c6503a26269645820770cdf240559fad7b7d639bc3ec9e9a62635425b08e0f25781dafb16d5fc7c0b6b646973706c61794e616d65695465737420557365720481a263616c672664747970656a7075626c69632d6b6579
        // 80010000
        ResponseAPDU resp = transmit(cmd);

        System.out.println(Hex.encodeHexString(resp.getData()));

        // 5) Verify status word OK
        assertEquals(0x9000, resp.getSW());

        // 6) Verify CTAP2 Status Code
        assertEquals(0x00, resp.getData()[0]);

        // 7) Parse attestation object from resp.getData()
        byte[] attStmtCbor = resp.getData();
        // Remove the first byte
        byte[] trimmedBytes = new byte[attStmtCbor.length - 1];
        System.arraycopy(attStmtCbor, 1, trimmedBytes, 0, attStmtCbor.length - 1);

        CBORObject attObj = CBORObject.DecodeFromBytes(trimmedBytes);
        assertTrue(attObj.get("fmt").AsString().length() > 0);

        System.out.println(Hex.encodeHexString(attObj.get("authData").EncodeToBytes()));
    /*
        58 a4
        a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947
        41
        00000001
        123456789abcdef01122334455667788
        0020
        000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
        a5010203262001215820982ab6e97a33c43f490ed2b7e3d0462ba2700cc64018d29c03e100f70277980622582068e32ad01bf0edf2093259fc71b77187b9bf34dc85ec9cdd043e6cdb9423fb44
    */
        assertNotNull(attObj.get("authData"));
    }


    @Test
    public void testGetAssertion() throws Exception {
        setup();
        testMakeCredential();

        SecureRandom rnd = new SecureRandom();
        byte[] clientDataHash = new byte[32];
        rnd.nextBytes(clientDataHash);

        // allowList
        CBORObject allowListItem = CBORObject.NewMap();
        allowListItem.Add("type", "public-key");
        allowListItem.Add("id", new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}); // COSE_ES256
        CBORObject allowList = CBORObject.NewArray();
        allowList.Add(allowListItem);

        // Assemble main request (CBOR map, integer keys per CTAP2)
        CBORObject getAssertionRequest = CBORObject.NewMap();
        getAssertionRequest.Add(1, CBORObject.FromObject("example.com"));
        getAssertionRequest.Add(2, CBORObject.FromObject(clientDataHash));
        getAssertionRequest.Add(3, allowList);

        byte[] payload = getAssertionRequest.EncodeToBytes();

        CommandAPDU cmd = new CommandAPDU(
                0x80, // CLA
                0x02, // INS = authenticatorGetAssertion
                0x00, // P1
                0x00, // P2
                payload
        );

        System.out.println(Hex.encodeHexString(cmd.getBytes()));

        //80010000aaa30158201bb5c515a64f3d9612223b02a88da84457580eb11e166afffb540ca5a88dd76502a26269647824776f726b696e672d746172706f6e2d6c6174656c792e6e67726f6b2d667265652e617070646e616d657824776f726b696e672d746172706f6e2d6c6174656c792e6e67726f6b2d667265652e61707003a262696477643256695958563061473570627931305a6e526d6447596b646973706c61794e616d6566746674667466

        ResponseAPDU resp = transmit(cmd);
        System.out.println(Hex.encodeHexString(resp.getData()));

        // Verify status word OK
        assertEquals(0x9000, resp.getSW());

        // Verify CTAP2 Status Code
        assertEquals(0x00, resp.getData()[0]);
    }

    /*@Test
    public void testClientPIN() throws Exception {
        // CTAP2 INS = 0x06, P1 = getRetries=0x01
        ResponseAPDU resp = transmit((byte)0x00, (byte)0x06, (byte)0x01, (byte)0x00, null);
        assertEquals(0x9000, resp.getSW());
        // data[0] is remaining attempts
    }

    @Test
    public void testReset() throws Exception {
        // CTAP2 INS = 0x07
        ResponseAPDU resp = transmit((byte)0x00, (byte)0x07, (byte)0x00, (byte)0x00, null);
        assertEquals(0x9000, resp.getSW());
    }

    @Test
    public void testGetNextAssertion() throws Exception {
        // call GET_ASSERTION INS=0x02 with allowList that yields multiple creds,
        // then INS=0x08 for next
        byte[] payload = CBOR.encodeMap(
                CBOR.ofString("rpId"), "example.com".getBytes(),
                CBOR.ofString("clientDataHash"), new byte[32],
                CBOR.ofString("allowList"), CBOR.ofArray(
                        CBOR.ofMap(CBOR.ofString("id"), yourCredId)
                )
        );
        transmit((byte)0x00, (byte)0x02, (byte)0x00, (byte)0x00, payload);
        // now request next
        ResponseAPDU resp = transmit((byte)0x00, (byte)0x08, (byte)0x00, (byte)0x00, null);
        assertEquals(0x9000, resp.getSW());
    }*/
}
