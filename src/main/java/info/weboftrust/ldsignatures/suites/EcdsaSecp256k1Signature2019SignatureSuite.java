package info.weboftrust.ldsignatures.suites;

import com.danubetech.keyformats.jose.JWSAlgorithm;
import com.danubetech.keyformats.jose.KeyTypeName;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class EcdsaSecp256k1Signature2019SignatureSuite extends SignatureSuite {

	EcdsaSecp256k1Signature2019SignatureSuite() {

		super(
				"EcdsaSecp256k1Signature2019",
				URI.create("https://w3id.org/security#EcdsaSecp256k1Signature2019"),
				URI.create("https://w3id.org/security#URDNA2015"),
				URI.create("http://w3id.org/digests#sha256"),
				URI.create("http://w3id.org/security#secp256k1"),
				List.of(KeyTypeName.secp256k1),
				Map.of(KeyTypeName.secp256k1, List.of(JWSAlgorithm.ES256K)),
				Arrays.asList(URI.create("https://www.w3.org/2018/credentials/v1"), LDSecurityContexts.JSONLD_CONTEXT_W3ID_SUITES_SECP256K1_2019_V1,LDSecurityContexts.JSONLD_CONTEXT_W3ID_SECURITY_V3));
	}
}
