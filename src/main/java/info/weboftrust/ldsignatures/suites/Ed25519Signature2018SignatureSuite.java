package info.weboftrust.ldsignatures.suites;

import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class Ed25519Signature2018SignatureSuite extends SignatureSuite {

	Ed25519Signature2018SignatureSuite() {

		super(
				"Ed25519Signature2018",
				URI.create("https://w3id.org/security#Ed25519Signature2018"),
				URI.create("https://w3id.org/security#URDNA2015"),
				URI.create("http://w3id.org/digests#sha256"),
				URI.create("http://w3id.org/security#ed25519"),
				List.of(KeyTypeName.Ed25519),
				Map.of(KeyTypeName.Ed25519, List.of(JWSAlgorithm.EdDSA)),
				Arrays.asList(URI.create("https://www.w3.org/2018/credentials/v1"), LDSecurityContexts.JSONLD_CONTEXT_W3ID_SUITES_ED25519_2018_V1,LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V3));
	}
}
