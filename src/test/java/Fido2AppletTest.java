import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import com.upokecenter.cbor.CBORObject;
import de.grooby34.masterthesis.FIDO2Applet;
import java.security.SecureRandom;
import java.util.Arrays;
import javacard.framework.AID;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.util.encoders.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class Fido2AppletTest {
  private static final byte[] AID = {(byte) 0xA0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x0C, 0x06};
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
    System.out.printf(
        "APDU SW1=%02X SW2=%02X data=%s%n",
        resp.getSW1(), resp.getSW2(), Arrays.toString(resp.getData()));
    return resp;
  }

  @Test
  public void testMakeCredential() throws Exception {
    // 1) Prepare a random clientDataHash
    SecureRandom rnd = new SecureRandom();
    byte[] clientDataHash = new byte[32];
    rnd.nextBytes(clientDataHash);

    // Relying Party
    CBORObject rp = CBORObject.NewMap();
    rp.Add("id", "working-tarpon-lately.ngrok-free.app");
    rp.Add("name", "working-tarpon-lately.ngrok-free.app");

    // User
    byte[] userID = new byte[32];
    rnd.nextBytes(userID);
    CBORObject user = CBORObject.NewMap();
    user.Add("id", Base64.decode("d2ViYXV0aG5pby10ZnZu"));
    user.Add("displayName", "tfvn");

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

    // 4) Send CTAP2 makeCredential (CLA=0x00, INS=0x01)
    CommandAPDU cmd =
        new CommandAPDU(
            0x80, // CLA
            0x01, // INS = authenticatorMakeCredential
            0x00, // P1
            0x00, // P2
            payload);

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

    assertNotNull(attObj.get("authData"));
  }

  @Test
  public void testReset() throws Exception {
    // setup();
    testMakeCredential();

    CommandAPDU cmd =
        new CommandAPDU(
            0x80, // CLA
            0x07, // INS = authenticatorReset
            0x00, // P1
            0x00, // P2
            null // no payload needed
            );

    ResponseAPDU resp = transmit(cmd);
    assertEquals(0x9000, resp.getSW());
  }

    // This test only works if a fixed credentialID is created/used in makeCredential
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
        allowListItem.Add(
                "id",
                new byte[] {
                        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                        0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
                        0x1E, 0x1F
                }); // COSE_ES256
        CBORObject allowList = CBORObject.NewArray();
        allowList.Add(allowListItem);

        // Assemble main request (CBOR map, integer keys per CTAP2)
        CBORObject getAssertionRequest = CBORObject.NewMap();
        getAssertionRequest.Add(1, CBORObject.FromObject("working-tarpon-lately.ngrok-free.app"));
        getAssertionRequest.Add(2, CBORObject.FromObject(clientDataHash));
        getAssertionRequest.Add(3, allowList);

        byte[] payload = getAssertionRequest.EncodeToBytes();

        CommandAPDU cmd =
                new CommandAPDU(
                        0x80, // CLA
                        0x02, // INS = authenticatorGetAssertion
                        0x00, // P1
                        0x00, // P2
                        payload);

        ResponseAPDU resp = transmit(cmd);

        // Verify status word OK
        assertEquals(0x9000, resp.getSW());

        // Verify CTAP2 Status Code
        assertEquals(0x00, resp.getData()[0]);
    }
}
