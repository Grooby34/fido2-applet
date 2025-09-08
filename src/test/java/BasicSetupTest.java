import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import static org.assertj.core.api.Assertions.*;

@DisplayName("Basic Setup Verification Tests")
public class BasicSetupTest {

    @Test
    @DisplayName("Should verify JUnit 5 is working")
    void testJUnit5Setup() {
        assertThat(true).isTrue();
        System.out.println("✓ JUnit 5 is working correctly");
    }

    @Test
    @DisplayName("Should verify AssertJ is working")
    void testAssertJSetup() {
        String message = "Hello FIDO2 Testing";
        assertThat(message).contains("FIDO2");
        System.out.println("✓ AssertJ is working correctly");
    }

    @Test
    @DisplayName("Should verify jCardSim dependency")
    void testJCardSimAvailable() {
        try {
            Class.forName("com.licel.jcardsim.base.Simulator");
            System.out.println("✓ jCardSim is available");
        } catch (ClassNotFoundException e) {
            fail("jCardSim library not found on classpath");
        }
    }

    @Test
    @DisplayName("Should verify CBOR library")
    void testCBORLibrary() {
        try {
            Class.forName("com.fasterxml.jackson.dataformat.cbor.CBORFactory");
            System.out.println("✓ CBOR library is available");
        } catch (ClassNotFoundException e) {
            fail("CBOR library not found on classpath");
        }
    }
}